#!/usr/bin/env python3
"""
database/retention_manager.py - Database Retention Policy Manager
Handles automatic cleanup of old scans, size-based cleanup, and retention policies
"""

import asyncio
import logging
import time
import os
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class RetentionConfig:
    """Configuration for retention policies"""
    # Time-based retention
    max_retention_days: int = 60  # Keep scans for 60 days
    min_scans_to_keep: int = 10   # Always keep at least 10 most recent scans
    
    # Size-based retention  
    max_database_size_mb: int = 5120  # 5GB in MB
    target_size_after_cleanup_mb: int = 4096  # 4GB target after cleanup
    
    # Cleanup scheduling
    cleanup_interval_hours: int = 24  # Run cleanup every 24 hours
    startup_cleanup_enabled: bool = True  # Run cleanup on startup
    
    # Safety limits
    max_scans_per_cleanup: int = 100  # Don't delete more than 100 scans at once
    require_confirmation_above_scans: int = 50  # Require confirmation for large cleanups

@dataclass  
class CleanupStats:
    """Statistics from a cleanup operation"""
    scans_removed: int = 0
    vulnerabilities_removed: int = 0
    code_contexts_removed: int = 0
    repositories_removed: int = 0
    size_freed_mb: float = 0.0
    cleanup_reason: str = ""
    cleanup_timestamp: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class RetentionPolicyManager:
    """Manages database retention policies and cleanup operations"""
    
    def __init__(self, db_manager, config: RetentionConfig = None):
        self.db_manager = db_manager
        self.config = config or RetentionConfig()
        self.is_running = False
        self.cleanup_task: Optional[asyncio.Task] = None
        self.last_cleanup_time = 0.0
        
    async def start_background_cleanup(self):
        """Start the background cleanup scheduler"""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Run startup cleanup if enabled
        if self.config.startup_cleanup_enabled:
            try:
                await self.run_startup_cleanup()
            except Exception as e:
                logger.error(f"Startup cleanup failed: {e}")
        
        # Start background task
        self.cleanup_task = asyncio.create_task(self._cleanup_scheduler())
        logger.info(f"Retention manager started - cleanup every {self.config.cleanup_interval_hours}h")
    
    async def stop_background_cleanup(self):
        """Stop the background cleanup scheduler"""
        self.is_running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Retention manager stopped")
    
    async def run_startup_cleanup(self):
        """Run cleanup operations on startup"""
        logger.info("Running startup database cleanup...")
        
        try:
            # Check database size first
            db_size_mb = await self._get_database_size_mb()
            
            if db_size_mb > self.config.max_database_size_mb:
                logger.warning(f"Database size ({db_size_mb:.1f}MB) exceeds limit ({self.config.max_database_size_mb}MB)")
                stats = await self.cleanup_by_size()
                logger.info(f"Size-based cleanup completed: {stats.scans_removed} scans removed")
            
            # Then run time-based cleanup
            stats = await self.cleanup_by_age()
            
            if stats.scans_removed > 0:
                logger.info(f"Time-based cleanup completed: {stats.scans_removed} scans removed")
            else:
                logger.info("No old scans found for cleanup")
                
        except Exception as e:
            logger.error(f"Startup cleanup failed: {e}")
    
    async def _cleanup_scheduler(self):
        """Background task that runs cleanup periodically"""
        while self.is_running:
            try:
                # Wait for the cleanup interval
                await asyncio.sleep(self.config.cleanup_interval_hours * 3600)
                
                if not self.is_running:
                    break
                
                # Run automated cleanup
                await self._run_automated_cleanup()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup scheduler: {e}")
                # Wait 5 minutes before retrying
                await asyncio.sleep(300)
    
    async def _run_automated_cleanup(self):
        """Run the automated cleanup process"""
        logger.info("Running scheduled database cleanup...")
        
        try:
            cleanup_needed = False
            total_stats = CleanupStats(cleanup_timestamp=time.time())
            
            # Check if size-based cleanup is needed
            db_size_mb = await self._get_database_size_mb()
            if db_size_mb > self.config.max_database_size_mb:
                logger.info(f"Size threshold exceeded ({db_size_mb:.1f}MB > {self.config.max_database_size_mb}MB)")
                size_stats = await self.cleanup_by_size()
                total_stats = self._merge_stats(total_stats, size_stats)
                cleanup_needed = True
            
            # Run time-based cleanup
            age_stats = await self.cleanup_by_age()
            total_stats = self._merge_stats(total_stats, age_stats)
            
            if age_stats.scans_removed > 0:
                cleanup_needed = True
            
            # Log results
            if cleanup_needed:
                logger.info(f"Scheduled cleanup completed: {total_stats.scans_removed} scans, "
                          f"{total_stats.vulnerabilities_removed} vulnerabilities removed, "
                          f"{total_stats.size_freed_mb:.1f}MB freed")
            else:
                logger.debug("No cleanup needed during scheduled run")
                
            self.last_cleanup_time = time.time()
            
        except Exception as e:
            logger.error(f"Automated cleanup failed: {e}")
    
    async def cleanup_by_age(self) -> CleanupStats:
        """Clean up scans older than the retention period"""
        if not self.db_manager.initialized:
            await self.db_manager.initialize()
        
        cutoff_time = int(time.time()) - (self.config.max_retention_days * 24 * 60 * 60)
        stats = CleanupStats(
            cleanup_reason=f"Age-based cleanup (>{self.config.max_retention_days} days)",
            cleanup_timestamp=time.time()
        )
        
        try:
            # Get scans to delete (excluding minimum recent scans)
            old_scans = await self._get_old_scans(cutoff_time)
            
            if not old_scans:
                return stats
            
            # Apply safety limits
            if len(old_scans) > self.config.max_scans_per_cleanup:
                old_scans = old_scans[:self.config.max_scans_per_cleanup]
                logger.warning(f"Limited cleanup to {self.config.max_scans_per_cleanup} scans for safety")
            
            # Calculate size before cleanup
            size_before_mb = await self._get_database_size_mb()
            
            # Perform deletion
            deletion_stats = await self._delete_scans(old_scans)
            stats.scans_removed = deletion_stats['scans_removed']
            stats.vulnerabilities_removed = deletion_stats['vulnerabilities_removed']
            stats.code_contexts_removed = deletion_stats['code_contexts_removed']
            
            # Calculate size freed
            size_after_mb = await self._get_database_size_mb()
            stats.size_freed_mb = size_before_mb - size_after_mb
            
            logger.info(f"Age-based cleanup: removed {stats.scans_removed} scans older than {self.config.max_retention_days} days")
            
        except Exception as e:
            logger.error(f"Age-based cleanup failed: {e}")
            raise
        
        return stats
    
    async def cleanup_by_size(self) -> CleanupStats:
        """Clean up oldest scans to reduce database size"""
        if not self.db_manager.initialized:
            await self.db_manager.initialize()
        
        current_size_mb = await self._get_database_size_mb()
        stats = CleanupStats(
            cleanup_reason=f"Size-based cleanup ({current_size_mb:.1f}MB > {self.config.max_database_size_mb}MB)",
            cleanup_timestamp=time.time()
        )
        
        if current_size_mb <= self.config.max_database_size_mb:
            return stats  # No cleanup needed
        
        try:
            # Get oldest scans to remove
            scans_to_remove = await self._get_scans_for_size_cleanup(current_size_mb)
            
            if not scans_to_remove:
                logger.warning("No scans available for size-based cleanup")
                return stats
            
            # Calculate size before cleanup
            size_before_mb = await self._get_database_size_mb()
            
            # Perform deletion
            deletion_stats = await self._delete_scans(scans_to_remove)
            stats.scans_removed = deletion_stats['scans_removed']
            stats.vulnerabilities_removed = deletion_stats['vulnerabilities_removed']
            stats.code_contexts_removed = deletion_stats['code_contexts_removed']
            
            # Calculate actual size freed
            size_after_mb = await self._get_database_size_mb()
            stats.size_freed_mb = size_before_mb - size_after_mb
            
            logger.info(f"Size-based cleanup: removed {stats.scans_removed} scans, "
                       f"freed {stats.size_freed_mb:.1f}MB ({size_before_mb:.1f}MB -> {size_after_mb:.1f}MB)")
            
        except Exception as e:
            logger.error(f"Size-based cleanup failed: {e}")
            raise
        
        return stats
    
    async def cleanup_orphaned_data(self) -> CleanupStats:
        """Clean up orphaned repositories and other inconsistent data"""
        if not self.db_manager.initialized:
            await self.db_manager.initialize()
        
        stats = CleanupStats(
            cleanup_reason="Orphaned data cleanup",
            cleanup_timestamp=time.time()
        )
        
        try:
            import aiosqlite
            
            async with aiosqlite.connect(self.db_manager.db_path) as db:
                # Find orphaned repositories (no scans)
                cursor = await db.execute('''
                    SELECT repository_id FROM repositories 
                    WHERE repository_id NOT IN (SELECT DISTINCT repository_id FROM scans)
                ''')
                orphaned_repos = [row[0] for row in await cursor.fetchall()]
                
                # Delete orphaned repositories
                for repo_id in orphaned_repos:
                    await db.execute('DELETE FROM repositories WHERE repository_id = ?', (repo_id,))
                    stats.repositories_removed += 1
                
                # Find and delete orphaned code contexts (vulnerabilities that don't exist)
                cursor = await db.execute('''
                    DELETE FROM code_context 
                    WHERE vulnerability_id NOT IN (SELECT vulnerability_id FROM vulnerabilities)
                ''')
                stats.code_contexts_removed = cursor.rowcount
                
                await db.commit()
                
                if stats.repositories_removed > 0 or stats.code_contexts_removed > 0:
                    logger.info(f"Orphaned data cleanup: removed {stats.repositories_removed} repos, "
                               f"{stats.code_contexts_removed} orphaned contexts")
                
        except Exception as e:
            logger.error(f"Orphaned data cleanup failed: {e}")
            raise
        
        return stats
    
    async def get_cleanup_preview(self) -> Dict[str, Any]:
        """Get a preview of what would be cleaned up without actually doing it"""
        if not self.db_manager.initialized:
            await self.db_manager.initialize()
        
        cutoff_time = int(time.time()) - (self.config.max_retention_days * 24 * 60 * 60)
        current_size_mb = await self._get_database_size_mb()
        
        preview = {
            "current_database_size_mb": current_size_mb,
            "retention_policy_days": self.config.max_retention_days,
            "size_limit_mb": self.config.max_database_size_mb,
            "cleanup_needed": False,
            "age_based_cleanup": {"scans_to_remove": 0, "oldest_scan_date": None},
            "size_based_cleanup": {"scans_to_remove": 0, "estimated_size_freed_mb": 0},
            "orphaned_data": {"orphaned_repositories": 0, "orphaned_contexts": 0}
        }
        
        try:
            import aiosqlite
            
            async with aiosqlite.connect(self.db_manager.db_path) as db:
                # Age-based preview
                old_scans = await self._get_old_scans(cutoff_time)
                if old_scans:
                    preview["age_based_cleanup"]["scans_to_remove"] = len(old_scans)
                    # Get oldest scan date
                    cursor = await db.execute('''
                        SELECT MIN(created_at) FROM scans WHERE created_at < ?
                    ''', (cutoff_time,))
                    oldest_time = (await cursor.fetchone())[0]
                    if oldest_time:
                        preview["age_based_cleanup"]["oldest_scan_date"] = datetime.fromtimestamp(oldest_time).isoformat()
                    preview["cleanup_needed"] = True
                
                # Size-based preview
                if current_size_mb > self.config.max_database_size_mb:
                    scans_for_size = await self._get_scans_for_size_cleanup(current_size_mb)
                    preview["size_based_cleanup"]["scans_to_remove"] = len(scans_for_size)
                    preview["size_based_cleanup"]["estimated_size_freed_mb"] = max(0, 
                        current_size_mb - self.config.target_size_after_cleanup_mb)
                    preview["cleanup_needed"] = True
                
                # Orphaned data preview
                cursor = await db.execute('''
                    SELECT COUNT(*) FROM repositories 
                    WHERE repository_id NOT IN (SELECT DISTINCT repository_id FROM scans)
                ''')
                preview["orphaned_data"]["orphaned_repositories"] = (await cursor.fetchone())[0]
                
                cursor = await db.execute('''
                    SELECT COUNT(*) FROM code_context 
                    WHERE vulnerability_id NOT IN (SELECT vulnerability_id FROM vulnerabilities)
                ''')
                preview["orphaned_data"]["orphaned_contexts"] = (await cursor.fetchone())[0]
                
        except Exception as e:
            logger.error(f"Failed to generate cleanup preview: {e}")
            preview["error"] = str(e)
        
        return preview
    
    async def _get_old_scans(self, cutoff_time: int) -> List[str]:
        """Get scan IDs older than cutoff time, respecting minimum scans to keep"""
        import aiosqlite
        
        async with aiosqlite.connect(self.db_manager.db_path) as db:
            # Get total scan count
            cursor = await db.execute('SELECT COUNT(*) FROM scans')
            total_scans = (await cursor.fetchone())[0]
            
            # If we have fewer than minimum scans, don't delete any
            if total_scans <= self.config.min_scans_to_keep:
                return []
            
            # Get old scans, but ensure we keep at least min_scans_to_keep recent ones
            max_to_delete = total_scans - self.config.min_scans_to_keep
            
            cursor = await db.execute('''
                SELECT scan_id FROM scans 
                WHERE created_at < ? 
                ORDER BY created_at ASC
                LIMIT ?
            ''', (cutoff_time, max_to_delete))
            
            return [row[0] for row in await cursor.fetchall()]
    
    async def _get_scans_for_size_cleanup(self, current_size_mb: float) -> List[str]:
        """Get oldest scans to delete for size-based cleanup"""
        import aiosqlite
        
        # Calculate how many scans we might need to remove
        # This is a rough estimate - we'll delete oldest scans until size target is reached
        target_reduction_mb = current_size_mb - self.config.target_size_after_cleanup_mb
        
        if target_reduction_mb <= 0:
            return []
        
        async with aiosqlite.connect(self.db_manager.db_path) as db:
            # Get total scan count
            cursor = await db.execute('SELECT COUNT(*) FROM scans')
            total_scans = (await cursor.fetchone())[0]
            
            # Ensure we keep minimum scans
            max_to_delete = max(0, total_scans - self.config.min_scans_to_keep)
            
            if max_to_delete == 0:
                return []
            
            # Estimate scans to delete (rough calculation)
            # Assume each scan takes similar space
            estimated_scans_to_delete = min(max_to_delete, int(target_reduction_mb / (current_size_mb / total_scans)) + 1)
            estimated_scans_to_delete = min(estimated_scans_to_delete, self.config.max_scans_per_cleanup)
            
            cursor = await db.execute('''
                SELECT scan_id FROM scans 
                ORDER BY created_at ASC
                LIMIT ?
            ''', (estimated_scans_to_delete,))
            
            return [row[0] for row in await cursor.fetchall()]
    
    async def _delete_scans(self, scan_ids: List[str]) -> Dict[str, int]:
        """Delete the specified scans and related data"""
        if not scan_ids:
            return {'scans_removed': 0, 'vulnerabilities_removed': 0, 'code_contexts_removed': 0}
        
        import aiosqlite
        stats = {'scans_removed': 0, 'vulnerabilities_removed': 0, 'code_contexts_removed': 0}
        
        async with aiosqlite.connect(self.db_manager.db_path) as db:
            for scan_id in scan_ids:
                # Delete code contexts first (foreign key dependency)
                cursor = await db.execute('''
                    DELETE FROM code_context 
                    WHERE vulnerability_id IN (
                        SELECT vulnerability_id FROM vulnerabilities WHERE scan_id = ?
                    )
                ''', (scan_id,))
                stats['code_contexts_removed'] += cursor.rowcount
                
                # Delete vulnerabilities
                cursor = await db.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
                stats['vulnerabilities_removed'] += cursor.rowcount
                
                # Delete scan
                cursor = await db.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
                stats['scans_removed'] += cursor.rowcount
            
            await db.commit()
        
        return stats
    
    async def _get_database_size_mb(self) -> float:
        """Get database file size in MB"""
        try:
            size_bytes = os.path.getsize(self.db_manager.db_path) if os.path.exists(self.db_manager.db_path) else 0
            return size_bytes / (1024 * 1024)  # Convert to MB
        except Exception as e:
            logger.error(f"Failed to get database size: {e}")
            return 0.0
    
    def _merge_stats(self, stats1: CleanupStats, stats2: CleanupStats) -> CleanupStats:
        """Merge two cleanup stats objects"""
        return CleanupStats(
            scans_removed=stats1.scans_removed + stats2.scans_removed,
            vulnerabilities_removed=stats1.vulnerabilities_removed + stats2.vulnerabilities_removed,
            code_contexts_removed=stats1.code_contexts_removed + stats2.code_contexts_removed,
            repositories_removed=stats1.repositories_removed + stats2.repositories_removed,
            size_freed_mb=stats1.size_freed_mb + stats2.size_freed_mb,
            cleanup_reason=f"{stats1.cleanup_reason}; {stats2.cleanup_reason}".strip("; "),
            cleanup_timestamp=max(stats1.cleanup_timestamp, stats2.cleanup_timestamp)
        )
    
    def get_config(self) -> Dict[str, Any]:
        """Get current retention configuration"""
        return asdict(self.config)
    
    async def update_config(self, **kwargs) -> None:
        """Update retention configuration"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.info(f"Updated retention config: {key} = {value}")
            else:
                logger.warning(f"Unknown config parameter: {key}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the retention manager"""
        return {
            "is_running": self.is_running,
            "last_cleanup_time": self.last_cleanup_time,
            "last_cleanup_ago_hours": (time.time() - self.last_cleanup_time) / 3600 if self.last_cleanup_time > 0 else None,
            "next_cleanup_in_hours": self.config.cleanup_interval_hours - ((time.time() - self.last_cleanup_time) / 3600) if self.last_cleanup_time > 0 else None,
            "config": self.get_config()
        }