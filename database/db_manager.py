#!/usr/bin/env python3
"""
database/db_manager.py - SQLite Database Manager for Vulnerability Scanner
Handles repositories, scans, vulnerabilities, and code context with async support
"""

import asyncio
import aiosqlite
import logging
import os
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import asdict
import uuid

# Import vulnerability classes
from scanner.core.base_classes import Vulnerability, ScanResult

logger = logging.getLogger(__name__)

class AsyncDatabaseManager:
    """Async SQLite database manager for vulnerability scanner"""
    
    def __init__(self, db_path: str = "vulnerability_scanner.db"):
        self.db_path = db_path
        self.initialized = False
        self._lock = asyncio.Lock()
    
    async def initialize(self):
        """Initialize database with schema creation"""
        if self.initialized:
            return
        
        async with self._lock:
            if self.initialized:
                return
            
            try:
                # Create database directory if it doesn't exist
                os.makedirs(os.path.dirname(self.db_path) if os.path.dirname(self.db_path) else '.', exist_ok=True)
                
                # Create database and tables
                async with aiosqlite.connect(self.db_path) as db:
                    await self._create_tables(db)
                    await self._create_indexes(db)
                    await db.commit()
                
                self.initialized = True
                logger.info(f"Database initialized: {self.db_path}")
                
            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                raise
    
    async def _create_tables(self, db: aiosqlite.Connection):
        """Create all database tables"""
        
        # 1. Repositories table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS repositories (
                repository_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT,
                type TEXT NOT NULL DEFAULT 'local',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
        ''')
        
        # 2. Scans table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                repository_id TEXT NOT NULL,
                scan_path TEXT NOT NULL,
                language TEXT,
                status TEXT NOT NULL DEFAULT 'in_progress',
                total_files INTEGER DEFAULT 0,
                total_vulnerabilities INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL,
                completed_at INTEGER,
                scan_duration REAL DEFAULT 0.0,
                error_message TEXT,
                FOREIGN KEY (repository_id) REFERENCES repositories (repository_id)
            )
        ''')
        
        # 3. Vulnerabilities table  
        await db.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vulnerability_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                column_start INTEGER DEFAULT 0,
                column_end INTEGER DEFAULT 0,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                vulnerable_code TEXT,
                solution TEXT,
                cwe TEXT,
                category TEXT,
                language TEXT NOT NULL,
                confidence TEXT DEFAULT 'HIGH',
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                timestamp INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
            )
        ''')
        
        # 4. Code context table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS code_context (
                context_id INTEGER PRIMARY KEY AUTOINCREMENT,
                vulnerability_id TEXT NOT NULL,
                line_number INTEGER NOT NULL,
                content TEXT NOT NULL,
                is_vulnerable INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (vulnerability_id)
            )
        ''')
        
        logger.info("Database tables created successfully")
    
    async def store_vulnerabilities_batch(self, scan_id: str, vulnerabilities: List[Vulnerability]) -> int:
        """Store multiple vulnerabilities in a single transaction with proper type handling"""
        if not self.initialized:
            await self.initialize()
        
        if not vulnerabilities:
            return 0
        
        vulnerability_count = 0
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Prepare batch data with proper type conversion
                vulnerability_data = []
                context_data = []
                
                for vulnerability in vulnerabilities:
                    vuln_id = f"vuln_{uuid.uuid4().hex[:8]}"
                    timestamp = int(time.time())
                    
                    # Convert data to SQLite-compatible types
                    def safe_str(value, max_length=5000):
                        """Convert to string and limit length"""
                        if value is None:
                            return None
                        str_value = str(value)
                        return str_value[:max_length] if len(str_value) > max_length else str_value
                    
                    def safe_int(value, default=0):
                        """Convert to int safely"""
                        try:
                            return int(value) if value is not None else default
                        except (ValueError, TypeError):
                            return default
                    
                    # Vulnerability data with type safety
                    vulnerability_data.append((
                        vuln_id,
                        safe_str(scan_id),
                        safe_str(vulnerability.rule_id),
                        safe_str(vulnerability.file_path),
                        safe_int(vulnerability.line_number),
                        safe_int(vulnerability.column_start),
                        safe_int(vulnerability.column_end),
                        safe_str(vulnerability.severity),
                        safe_str(vulnerability.message, 2000),  # Limit message length
                        safe_str(vulnerability.vulnerable_code, 1000),  # Limit code length
                        safe_str(vulnerability.solution, 3000),  # Limit solution length
                        safe_str(vulnerability.cwe),
                        safe_str(vulnerability.category),
                        safe_str(vulnerability.language),
                        safe_str(vulnerability.confidence),
                        timestamp
                    ))
                    
                    # Context data with type safety
                    if vulnerability.code_context:
                        for context_line in vulnerability.code_context:
                            if isinstance(context_line, dict):
                                context_data.append((
                                    vuln_id,
                                    safe_int(context_line.get('line_number'), 0),
                                    safe_str(context_line.get('content', ''), 500),  # Limit context length
                                    1 if context_line.get('is_vulnerable', False) else 0
                                ))
                    
                    vulnerability_count += 1
                
                # Batch insert vulnerabilities
                await db.executemany('''
                    INSERT OR IGNORE INTO vulnerabilities 
                    (vulnerability_id, scan_id, rule_id, file_path, line_number, 
                    column_start, column_end, severity, message, vulnerable_code,
                    solution, cwe, category, language, confidence, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', vulnerability_data)
                
                # Batch insert code contexts
                if context_data:
                    await db.executemany('''
                        INSERT INTO code_context 
                        (vulnerability_id, line_number, content, is_vulnerable)
                        VALUES (?, ?, ?, ?)
                    ''', context_data)
                
                await db.commit()
                logger.info(f"Batch stored {vulnerability_count} vulnerabilities for scan {scan_id}")
                return vulnerability_count
                
        except Exception as e:
            logger.error(f"Failed to batch store vulnerabilities: {e}")
            # Log the first few vulnerability data for debugging
            if vulnerability_data:
                logger.error(f"Sample vulnerability data: {vulnerability_data[0]}")
            raise
    
    async def _create_indexes(self, db: aiosqlite.Connection):
        """Create database indexes for performance"""
        
        indexes = [
            # Foreign key indexes
            "CREATE INDEX IF NOT EXISTS idx_scans_repository ON scans(repository_id)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id)",
            "CREATE INDEX IF NOT EXISTS idx_context_vuln ON code_context(vulnerability_id)",
            
            # Query optimization indexes
            "CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status)",
            "CREATE INDEX IF NOT EXISTS idx_vulns_file ON vulnerabilities(file_path)",
            "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at)",
            
            # Unique constraint for preventing duplicates
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_vulns_unique ON vulnerabilities(scan_id, rule_id, file_path, line_number)"
        ]
        
        for index_sql in indexes:
            try:
                await db.execute(index_sql)
            except Exception as e:
                logger.warning(f"Failed to create index: {e}")
        
        logger.info("Database indexes created successfully")
    
    async def create_repository(self, name: str, path: str, repo_type: str = "local") -> str:
        """Create or get existing repository"""
        if not self.initialized:
            await self.initialize()
        
        # Generate repository ID based on path for consistency
        repo_id = f"repo_{hash(path) & 0x7fffffff}"
        current_time = int(time.time())
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Try to insert, ignore if exists
                await db.execute('''
                    INSERT OR IGNORE INTO repositories 
                    (repository_id, name, url, type, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (repo_id, name, path, repo_type, current_time, current_time))
                
                # Update the updated_at timestamp
                await db.execute('''
                    UPDATE repositories SET updated_at = ? WHERE repository_id = ?
                ''', (current_time, repo_id))
                
                await db.commit()
                logger.info(f"Repository created/updated: {repo_id} ({name})")
                return repo_id
                
        except Exception as e:
            logger.error(f"Failed to create repository: {e}")
            raise
    
    async def create_scan_session(self, scan_id: str, repository_id: str, scan_path: str, language: str = "java") -> None:
        """Create a new scan session"""
        if not self.initialized:
            await self.initialize()
        
        current_time = int(time.time())
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute('''
                    INSERT OR REPLACE INTO scans 
                    (scan_id, repository_id, scan_path, language, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (scan_id, repository_id, scan_path, language, 'in_progress', current_time))
                
                await db.commit()
                logger.info(f"Scan session created: {scan_id}")
                
        except Exception as e:
            logger.error(f"Failed to create scan session: {e}")
            raise
    
    async def update_scan_status(self, scan_id: str, status: str, total_files: int = None, 
                                total_vulnerabilities: int = None, error_message: str = None) -> None:
        """Update scan status and statistics"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Build dynamic update query
                update_fields = ["status = ?"]
                params = [status]
                
                if status == 'completed':
                    update_fields.append("completed_at = ?")
                    params.append(int(time.time()))
                
                if total_files is not None:
                    update_fields.append("total_files = ?")
                    params.append(total_files)
                
                if total_vulnerabilities is not None:
                    update_fields.append("total_vulnerabilities = ?")
                    params.append(total_vulnerabilities)
                
                if error_message:
                    update_fields.append("error_message = ?")
                    params.append(error_message)
                
                params.append(scan_id)
                
                query = f"UPDATE scans SET {', '.join(update_fields)} WHERE scan_id = ?"
                await db.execute(query, params)
                await db.commit()
                
                logger.debug(f"Scan status updated: {scan_id} -> {status}")
                
        except Exception as e:
            logger.error(f"Failed to update scan status: {e}")
            raise
    
    async def store_vulnerability(self, scan_id: str, vulnerability: Vulnerability) -> str:
        """Store a vulnerability with its code context"""
        if not self.initialized:
            await self.initialize()
        
        vuln_id = f"vuln_{uuid.uuid4().hex[:8]}"
        timestamp = int(time.time())
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Insert vulnerability
                await db.execute('''
                    INSERT OR IGNORE INTO vulnerabilities 
                    (vulnerability_id, scan_id, rule_id, file_path, line_number, 
                     column_start, column_end, severity, message, vulnerable_code,
                     solution, cwe, category, language, confidence, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    vuln_id, scan_id, vulnerability.rule_id, vulnerability.file_path,
                    vulnerability.line_number, vulnerability.column_start, vulnerability.column_end,
                    vulnerability.severity, vulnerability.message, vulnerability.vulnerable_code,
                    vulnerability.solution, vulnerability.cwe, vulnerability.category,
                    vulnerability.language, vulnerability.confidence, timestamp
                ))
                
                # Insert code context
                if vulnerability.code_context:
                    for context_line in vulnerability.code_context:
                        if isinstance(context_line, dict):
                            await db.execute('''
                                INSERT INTO code_context 
                                (vulnerability_id, line_number, content, is_vulnerable)
                                VALUES (?, ?, ?, ?)
                            ''', (
                                vuln_id, 
                                context_line.get('line_number', 0),
                                context_line.get('content', ''),
                                1 if context_line.get('is_vulnerable', False) else 0
                            ))
                
                await db.commit()
                logger.debug(f"Vulnerability stored: {vuln_id}")
                return vuln_id
                
        except Exception as e:
            logger.error(f"Failed to store vulnerability: {e}")
            raise
    
    async def get_scan_with_vulnerabilities(self, scan_id: str) -> Optional[Dict]:
        """Get scan details with all vulnerabilities"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get scan details
                cursor = await db.execute('''
                    SELECT s.*, r.name as repository_name, r.url as repository_url
                    FROM scans s
                    LEFT JOIN repositories r ON s.repository_id = r.repository_id
                    WHERE s.scan_id = ?
                ''', (scan_id,))
                
                scan_row = await cursor.fetchone()
                if not scan_row:
                    return None
                
                # Convert to dict
                columns = [desc[0] for desc in cursor.description]
                scan_data = dict(zip(columns, scan_row))
                
                # Get vulnerabilities
                cursor = await db.execute('''
                    SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY severity DESC, file_path, line_number
                ''', (scan_id,))
                
                vuln_rows = await cursor.fetchall()
                vuln_columns = [desc[0] for desc in cursor.description]
                
                vulnerabilities = []
                for row in vuln_rows:
                    vuln_dict = dict(zip(vuln_columns, row))
                    
                    # Get code context
                    context_cursor = await db.execute('''
                        SELECT line_number, content, is_vulnerable 
                        FROM code_context 
                        WHERE vulnerability_id = ? 
                        ORDER BY line_number
                    ''', (vuln_dict['vulnerability_id'],))
                    
                    context_rows = await context_cursor.fetchall()
                    vuln_dict['code_context'] = [
                        {
                            'line_number': row[0],
                            'content': row[1],
                            'is_vulnerable': bool(row[2])
                        }
                        for row in context_rows
                    ]
                    
                    vulnerabilities.append(vuln_dict)
                
                scan_data['vulnerabilities'] = vulnerabilities
                return scan_data
                
        except Exception as e:
            logger.error(f"Failed to get scan with vulnerabilities: {e}")
            raise
    
    async def get_all_repositories(self) -> List[Dict]:
        """Get all repositories with scan counts"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('''
                    SELECT r.*, 
                           COUNT(s.scan_id) as total_scans,
                           MAX(s.created_at) as last_scan_time
                    FROM repositories r
                    LEFT JOIN scans s ON r.repository_id = s.repository_id
                    GROUP BY r.repository_id
                    ORDER BY r.updated_at DESC
                ''')
                
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                return [dict(zip(columns, row)) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to get repositories: {e}")
            raise
    
    async def get_scans_for_repository(self, repository_id: str) -> List[Dict]:
        """Get all scans for a repository"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('''
                    SELECT * FROM scans 
                    WHERE repository_id = ? 
                    ORDER BY created_at DESC
                ''', (repository_id,))
                
                rows = await cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                
                return [dict(zip(columns, row)) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to get scans for repository: {e}")
            raise
    
    async def cleanup_old_records(self, retention_days: int = 60) -> Dict[str, int]:
        """Clean up old scan records based on retention policy"""
        if not self.initialized:
            await self.initialize()
        
        cutoff_time = int(time.time()) - (retention_days * 24 * 60 * 60)
        cleanup_stats = {"scans_removed": 0, "vulnerabilities_removed": 0, "contexts_removed": 0}
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                # Get old scan IDs
                cursor = await db.execute('''
                    SELECT scan_id FROM scans WHERE created_at < ?
                ''', (cutoff_time,))
                
                old_scan_ids = [row[0] for row in await cursor.fetchall()]
                
                if old_scan_ids:
                    # Delete code contexts first (foreign key dependency)
                    for scan_id in old_scan_ids:
                        cursor = await db.execute('''
                            DELETE FROM code_context 
                            WHERE vulnerability_id IN (
                                SELECT vulnerability_id FROM vulnerabilities WHERE scan_id = ?
                            )
                        ''', (scan_id,))
                        cleanup_stats["contexts_removed"] += cursor.rowcount
                    
                    # Delete vulnerabilities
                    for scan_id in old_scan_ids:
                        cursor = await db.execute('''
                            DELETE FROM vulnerabilities WHERE scan_id = ?
                        ''', (scan_id,))
                        cleanup_stats["vulnerabilities_removed"] += cursor.rowcount
                    
                    # Delete scans
                    cursor = await db.execute('''
                        DELETE FROM scans WHERE created_at < ?
                    ''', (cutoff_time,))
                    cleanup_stats["scans_removed"] = cursor.rowcount
                    
                    await db.commit()
                    logger.info(f"Cleanup completed: {cleanup_stats}")
                
                return cleanup_stats
                
        except Exception as e:
            logger.error(f"Failed to cleanup old records: {e}")
            raise
    
    async def delete_all_scans(self) -> Dict[str, int]:
        """Delete ALL data from the database including repositories"""
        if not self.initialized:
            await self.initialize()
        
        try:
            import aiosqlite
            
            async with aiosqlite.connect(self.db_path) as db:
                # Get counts before deletion for reporting (with null safety)
                cursor = await db.execute('SELECT COUNT(*) FROM repositories')
                result = await cursor.fetchone()
                repositories_count = result[0] if result else 0
                
                cursor = await db.execute('SELECT COUNT(*) FROM scans')
                result = await cursor.fetchone()
                scans_count = result[0] if result else 0
                
                cursor = await db.execute('SELECT COUNT(*) FROM vulnerabilities')
                result = await cursor.fetchone()
                vulnerabilities_count = result[0] if result else 0
                
                cursor = await db.execute('SELECT COUNT(*) FROM code_context')
                result = await cursor.fetchone()
                contexts_count = result[0] if result else 0
                
                logger.info(f"Before deletion: {repositories_count} repos, {scans_count} scans, {vulnerabilities_count} vulns, {contexts_count} contexts")
                
                # Disable foreign key constraints temporarily
                await db.execute('PRAGMA foreign_keys = OFF')
                
                # Delete everything in any order (foreign keys disabled)
                await db.execute('DELETE FROM code_context')
                logger.info("Deleted code_context records")
                
                await db.execute('DELETE FROM vulnerabilities')
                logger.info("Deleted vulnerabilities records")
                
                await db.execute('DELETE FROM scans')
                logger.info("Deleted scans records")
                
                await db.execute('DELETE FROM repositories')
                logger.info("Deleted repositories records")
                
                # Re-enable foreign key constraints
                await db.execute('PRAGMA foreign_keys = ON')
                
                # Commit the deletions
                await db.commit()
                logger.info("All deletions committed")
                
                # Verify deletion worked (with null safety)
                cursor = await db.execute('SELECT COUNT(*) FROM repositories')
                result = await cursor.fetchone()
                remaining_repos = result[0] if result else 0
                
                cursor = await db.execute('SELECT COUNT(*) FROM scans')
                result = await cursor.fetchone()
                remaining_scans = result[0] if result else 0
                
                logger.info(f"After deletion verification: {remaining_repos} repos, {remaining_scans} scans remaining")
                
                # VACUUM to reclaim disk space
                logger.info("Running VACUUM to reclaim space...")
                await db.execute('VACUUM')
                logger.info("VACUUM completed")
                
                logger.info(f"Successfully deleted ALL database data: {repositories_count} repositories, {scans_count} scans, {vulnerabilities_count} vulnerabilities, {contexts_count} contexts")
                
                return {
                    "repositories": repositories_count,
                    "scans": scans_count,
                    "vulnerabilities": vulnerabilities_count,
                    "code_contexts": contexts_count
                }
                
        except Exception as e:
            logger.error(f"Failed to delete all data: {e}")
            # Re-enable foreign keys if there was an error
            try:
                async with aiosqlite.connect(self.db_path) as db:
                    await db.execute('PRAGMA foreign_keys = ON')
                    await db.commit()
            except:
                pass
            raise
    
    async def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.initialized:
            await self.initialize()
        
        try:
            async with aiosqlite.connect(self.db_path) as db:
                stats = {}
                
                # Table counts
                tables = ['repositories', 'scans', 'vulnerabilities', 'code_context']
                for table in tables:
                    cursor = await db.execute(f'SELECT COUNT(*) FROM {table}')
                    count = (await cursor.fetchone())[0]
                    stats[f'{table}_count'] = count
                
                # Database size
                stats['database_size_bytes'] = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                stats['database_size_mb'] = round(stats['database_size_bytes'] / 1024 / 1024, 2)
                
                # Recent activity
                cursor = await db.execute('SELECT COUNT(*) FROM scans WHERE created_at > ?', (int(time.time()) - 86400,))
                stats['scans_last_24h'] = (await cursor.fetchone())[0]
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            raise

# Global database manager instance
db_manager = AsyncDatabaseManager("data/vulnerability_scanner.db")