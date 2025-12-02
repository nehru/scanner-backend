#!/usr/bin/env python3
"""
main.py - Complete WebSocket Vulnerability Scanner with Database & Retention Management
Production-ready version with automated cleanup and retention policies
"""

import asyncio
import logging
import uuid
import os
import sys
from typing import Dict, List, Optional
from datetime import datetime
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import time
import os
import hashlib

scanner_engine = None
java_engine = None
config_manager = None
retention_manager = None  # NEW: Retention manager

# Simple cache for scan results
simple_scan_cache = {}
CACHE_EXPIRY_HOURS = 24  # Cache expires after 24 hours (change to 168 for weekly)
MAX_CACHE_ENTRIES = 50

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import WebSocket manager
try:
    from api.websocket_manager import (
        websocket_manager, ProgressEvent, 
        create_progress_event, create_status_event, 
        create_language_start_event, create_language_complete_event,
        create_error_event
    )
    print("Successfully imported websocket_manager")
except ImportError as e:
    print(f"✗ Failed to import websocket_manager: {e}")
    sys.exit(1)

# Import database manager
try:
    from database.db_manager import db_manager
    print("Successfully imported database manager")
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"✗ Failed to import database manager: {e}")
    DATABASE_AVAILABLE = False

# NEW: Import retention manager
try:
    from database.retention_manager import RetentionPolicyManager, RetentionConfig
    print("Successfully imported retention manager")
    RETENTION_AVAILABLE = True
except ImportError as e:
    print(f"✗ Failed to import retention manager: {e}")
    RETENTION_AVAILABLE = False

# Import scanner components
try:
    from scanner.core.base_classes import AsyncScannerEngine, ProgressCallback
    from scanner.core.language_config import create_config_manager
    from scanner.core.rule_loader import get_async_rule_loader, create_default_rule_config
    from scanner.engines.java_engine import create_java_engine
    print("Successfully imported all scanner components")
    JAVA_ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"✗ Failed to import scanner components: {e}")
    JAVA_ENGINE_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global components
scanner_engine = None
java_engine = None
config_manager = None
retention_manager = None

async def initialize_scanner_components():
    """Initialize all scanner components"""
    global scanner_engine, java_engine, config_manager
    
    if not JAVA_ENGINE_AVAILABLE:
        logger.warning("Scanner components not available")
        return False
    
    try:
        # Create language config manager
        config_manager = await create_config_manager("config/languages.yml")
        logger.info("✓ Language config manager initialized")
        
        # Configure rule loader
        rule_loader = get_async_rule_loader()
        base_config = await create_default_rule_config()
        
        # Language-specific configurations
        language_configs = {
            'java': {
                'semgrep_rule_paths': ['java/security'],
                'custom_rules_filename': 'java-rules.yml',
                'solutions_filename': 'java-solutions.yml',
                'enabled': True
            }
        }
        
        await rule_loader.configure(base_config, language_configs)
        logger.info("✓ Rule loader configured")
        
        # Create Java engine
        java_engine = await create_java_engine(config_manager)
        logger.info("✓ Java vulnerability engine initialized")
        
        # Create and configure scanner engine
        scanner_engine = AsyncScannerEngine()
        scanner_engine.register_engine(java_engine)
        scanner_engine.set_websocket_manager(websocket_manager)
        logger.info("✓ Scanner engine configured")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize scanner components: {e}")
        return False

async def initialize_retention_manager():
    """Initialize retention policy manager"""
    global retention_manager
    
    if not DATABASE_AVAILABLE or not RETENTION_AVAILABLE:
        logger.warning("Retention manager not available")
        return False
    
    try:
        # Configure retention policies
        retention_config = RetentionConfig(
            max_retention_days=60,        # Keep scans for 60 days
            min_scans_to_keep=10,         # Always keep at least 10 recent scans
            max_database_size_mb=5120,    # 5GB limit
            target_size_after_cleanup_mb=4096,  # 4GB target after cleanup
            cleanup_interval_hours=24,    # Daily cleanup
            startup_cleanup_enabled=True  # Clean on startup
        )
        
        # Create retention manager
        retention_manager = RetentionPolicyManager(db_manager, retention_config)
        
        # Start background cleanup
        await retention_manager.start_background_cleanup()
        
        logger.info("✓ Retention manager initialized with automated cleanup")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize retention manager: {e}")
        return False

def generate_directory_fingerprint(directory: str) -> str:
    """Generate fingerprint based on Java file modification times"""
    try:
        file_info = []
        
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                # Skip common build directories
                dirs[:] = [d for d in dirs if d not in ['.git', 'target', 'build', 'node_modules']]
                
                for file in files:
                    if file.endswith(('.java', '.jsp', '.jspx')):
                        file_path = os.path.join(root, file)
                        try:
                            mtime = os.path.getmtime(file_path)
                            file_size = os.path.getsize(file_path)
                            file_info.append(f"{file_path}:{mtime}:{file_size}")
                        except (OSError, IOError):
                            continue
        
        # Sort for consistent hashing
        file_info.sort()
        
        # Generate fingerprint
        content = f"{directory}:{'|'.join(file_info)}"
        fingerprint = hashlib.md5(content.encode()).hexdigest()[:16]  # Short hash
        
        return fingerprint
        
    except Exception as e:
        logger.warning(f"Failed to generate fingerprint for {directory}: {e}")
        return ""

def enforce_cache_size_limit():
    """Remove oldest entries when cache exceeds MAX_CACHE_ENTRIES"""
    global simple_scan_cache
    
    if len(simple_scan_cache) <= MAX_CACHE_ENTRIES:
        return  # No need to clean up
    
    # Get entries sorted by cached_at time (oldest first)
    entries_with_time = []
    for key, entry in simple_scan_cache.items():
        if isinstance(entry, dict) and 'cached_at' in entry:
            entries_with_time.append((key, entry['cached_at']))
    
    # Sort by cached_at time (oldest first)
    entries_with_time.sort(key=lambda x: x[1])
    
    # Calculate how many to remove
    entries_to_remove = len(simple_scan_cache) - MAX_CACHE_ENTRIES
    
    # Remove oldest entries
    for i in range(entries_to_remove):
        if i < len(entries_with_time):
            key_to_remove = entries_with_time[i][0]
            removed_entry = simple_scan_cache.pop(key_to_remove, None)
            if removed_entry:
                logger.info(f"Removed old cache entry for size limit: {key_to_remove}")
    
    logger.info(f"Cache size limit enforced: removed {entries_to_remove} entries, {len(simple_scan_cache)} remaining")

def is_cache_entry_valid(cache_entry):
    """Check if cache entry is valid (not expired and files unchanged)"""
    try:
        # Handle old format entries
        if not isinstance(cache_entry, dict) or 'cached_at' not in cache_entry:
            return False
        
        # Check expiry time
        cached_time = cache_entry.get('cached_at')
        if not cached_time:
            return False
        
        expiry_time = cached_time + timedelta(hours=CACHE_EXPIRY_HOURS)
        current_time = datetime.now()
        
        if current_time >= expiry_time:
            logger.debug(f"Cache entry expired: cached at {cached_time}")
            return False
        
        # Check file modification fingerprint
        directory = cache_entry.get('directory')
        cached_fingerprint = cache_entry.get('fingerprint')
        
        if directory and cached_fingerprint:
            current_fingerprint = generate_directory_fingerprint(directory)
            if current_fingerprint != cached_fingerprint:
                logger.info(f"Cache invalidated: files modified in {directory}")
                return False
        
        return True
        
    except Exception as e:
        logger.warning(f"Error checking cache validity: {e}")
        return False

def cleanup_expired_cache_entries():
    """Remove expired entries from cache"""
    global simple_scan_cache
    
    expired_keys = []
    for cache_key, cache_entry in simple_scan_cache.items():
        if not is_cache_entry_valid(cache_entry):
            expired_keys.append(cache_key)
    
    # Remove expired entries
    for key in expired_keys:
        del simple_scan_cache[key]
        logger.info(f"Removed expired cache entry: {key}")
    
    if expired_keys:
        logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    # Enforce size limit after cleanup
    enforce_cache_size_limit()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown"""
    # Startup
    logger.info("Starting WebSocket Vulnerability Scanner with Database & Retention...")
    
    try:
        # Initialize database first
        if DATABASE_AVAILABLE:
            await db_manager.initialize()
            logger.info("✓ Database initialized")
        else:
            logger.warning("⚠ Database not available - using memory storage")
        
        # NEW: Initialize retention manager
        if DATABASE_AVAILABLE and RETENTION_AVAILABLE:
            success = await initialize_retention_manager()
            if success:
                logger.info("✓ Automated retention policies enabled")
            else:
                logger.warning("⚠ Retention manager initialization failed")
        
        # Start WebSocket manager
        await websocket_manager.start()
        logger.info("✓ WebSocket manager started")
        
        # Initialize scanner components
        if JAVA_ENGINE_AVAILABLE:
            success = await initialize_scanner_components()
            if success:
                logger.info("✓ Real vulnerability detection enabled")
            else:
                logger.warning("⚠ Failed to initialize - using fallback mode")
        else:
            logger.warning("⚠ Dependencies missing - using fallback simulator")
        
        logger.info("✓ WebSocket Vulnerability Scanner with Database & Retention ready")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"✗ Failed to start scanner: {e}")
        raise
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("Shutting down WebSocket Vulnerability Scanner...")
    
    # NEW: Stop retention manager
    if retention_manager:
        await retention_manager.stop_background_cleanup()
    
    await websocket_manager.stop()

# FastAPI app with lifespan
app = FastAPI(
    title="WebSocket Vulnerability Scanner with Database & Retention", 
    version="2.2.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class ScanRequest(BaseModel):
    scan_type: str  # "files" or "directory"
    paths: List[str]  # File paths or directory path
    scan_id: Optional[str] = None
    languages: Optional[List[str]] = None  # Specific languages to scan
    recursive: Optional[bool] = True
    max_files: Optional[int] = 1000
    repository_name: Optional[str] = None  # NEW: Optional repository name

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    languages_available: List[str]
    real_vulnerability_detection: bool
    repository_id: Optional[str] = None  # NEW: Return repository ID

# NEW: Retention configuration request model
class RetentionConfigRequest(BaseModel):
    max_retention_days: Optional[int] = None
    min_scans_to_keep: Optional[int] = None
    max_database_size_mb: Optional[int] = None
    cleanup_interval_hours: Optional[int] = None

class WebSocketProgressCallback(ProgressCallback):
    """Enhanced progress callback for WebSocket updates"""
    
    def __init__(self, scan_id: str):
        super().__init__(websocket_manager, scan_id)
        self.scan_id = scan_id
    
    async def update(self, stage: str, **kwargs):
        """Send detailed progress updates via WebSocket"""
        try:
            # Extract message from kwargs to avoid duplicate keyword argument
            message = kwargs.pop("message", None)
            
            # Create appropriate event based on stage
            if stage == "started":
                event = create_status_event(
                    scan_id=self.scan_id,
                    status="started",
                    message=message or "Starting scan",
                    **kwargs
                )
            elif stage == "completed":
                event = create_status_event(
                    scan_id=self.scan_id,
                    status="completed", 
                    message=message or "Scan completed",
                    **kwargs
                )
            elif stage == "failed":
                event = create_error_event(
                    scan_id=self.scan_id,
                    error_message=message or "Scan failed"
                )
            elif stage == "scanning":
                # Calculate progress percentage
                files_processed = kwargs.get("files_processed", 0)
                total_files = kwargs.get("total_files", 1)
                progress = (files_processed / total_files) * 70 + 10  # 10-80% for scanning
                
                event = create_progress_event(
                    scan_id=self.scan_id,
                    progress=progress,
                    stage="scanning",
                    current_file=kwargs.get("current_file"),
                    files_processed=files_processed,
                    total_files=total_files
                )
            elif stage == "analyzing":
                event = create_progress_event(
                    scan_id=self.scan_id,
                    progress=85.0,
                    stage="analyzing",
                    message=kwargs.get("message", "Analyzing results"),
                    current_file=kwargs.get("current_file")
                )
            else:
                # Generic progress event
                event = create_progress_event(
                    scan_id=self.scan_id,
                    progress=kwargs.get("progress", 0),
                    stage=stage,
                    **kwargs
                )
            
            await websocket_manager.broadcast_progress_event(event)
            
        except Exception as e:
            logger.error(f"Error sending progress update: {e}")

# Add this at the top of main.py after imports
DB_WRITE_SEMAPHORE = asyncio.Semaphore(2)  # Limit concurrent database writes

async def scan_with_real_engine(directory: str, scan_id: str, languages: List[str] = None, repository_name: str = None):
    """Scan directory using real vulnerability detection engines with optimized database storage"""
    SCAN_TIMEOUT = 300  # 5 minute timeout per scan
    
    try:
        # Set up progress callback
        progress_callback = WebSocketProgressCallback(scan_id)
        
        # Send start event
        await progress_callback.update("started", message=f"Starting vulnerability scan: {directory}")
        
        # CLEANUP EXPIRED ENTRIES FIRST (keep existing cache logic)
        cleanup_expired_cache_entries()
        
        # CHECK CACHE WITH EXPIRY FIRST - before any database operations
        cache_key = f"{directory}_java"
        if cache_key in simple_scan_cache:
            cache_entry = simple_scan_cache[cache_key]
            
            if is_cache_entry_valid(cache_entry):
                cached_result = cache_entry['scan_result']
                cached_time = cache_entry['cached_at']
                
                logger.info(f"Cache hit for scan {scan_id}, cached at {cached_time}")
                
                # Send quick progress updates to maintain user experience
                await progress_callback.update("scanning", message="Retrieving cached results...")
                
                # Send language start event
                language_start_event = create_language_start_event(scan_id=scan_id, language="java")
                await websocket_manager.broadcast_progress_event(language_start_event)
                
                # Brief delay to simulate processing
                await asyncio.sleep(0.2)
                
                # For cached results, skip database operations entirely for better performance
                # Just create a minimal repo_id for return value consistency
                repo_id = f"cached_repo_{hash(directory) & 0x7fffffff}"
                
                # Send language complete event with cached data
                language_complete_event = create_language_complete_event(
                    scan_id=scan_id,
                    language="java",
                    vulnerabilities_count=cached_result.total_vulnerabilities
                )
                await websocket_manager.broadcast_progress_event(language_complete_event)
                
                # Store results in WebSocket manager (keep existing functionality)
                await websocket_manager.store_scan_result(scan_id, cached_result.to_dict())
                
                # Send completion event
                await progress_callback.update(
                    "completed",
                    message=f"Cached scan completed: {cached_result.total_files} files, {cached_result.total_vulnerabilities} vulnerabilities (cached {cached_time.strftime('%Y-%m-%d %H:%M')})",
                    files_processed=cached_result.total_files,
                    vulnerabilities_found=cached_result.total_vulnerabilities
                )
                
                logger.info(f"Returned cached scan result: {cached_result.total_vulnerabilities} vulnerabilities found")
                
                completion_event = ProgressEvent(
                    event_type="scan-completed", 
                    scan_id=scan_id,
                    timestamp=datetime.utcnow().isoformat(),
                    status="completed",
                    details={
                        "scanId": scan_id,
                        "totalFiles": cached_result.total_files,
                        "totalVulnerabilities": cached_result.total_vulnerabilities,
                        "results": []
                    }
                )

                await websocket_manager.broadcast_progress_event(completion_event)
                logger.info(f"Broadcasted cached scan completion event for {scan_id}")
                
                return cached_result, repo_id
            else:
                # Remove expired entry
                del simple_scan_cache[cache_key]
                logger.info(f"Removed expired cache entry for {directory}")
        
        # NO CACHE HIT - Create repository record with write limit
        repo_id = None
        if DATABASE_AVAILABLE:
            try:
                async with DB_WRITE_SEMAPHORE:  # Limit concurrent database operations
                    repo_name = repository_name or f"Auto-discovered: {os.path.basename(directory)}"
                    repo_id = await db_manager.create_repository(repo_name, directory, "local")
                    
                    # Create scan session
                    await db_manager.create_scan_session(scan_id, repo_id, directory, "java")
                    logger.info(f"Database: Created repository {repo_id} and scan session {scan_id}")
            except Exception as e:
                logger.error(f"Database error during setup: {e}")
                # Continue with scan even if database fails
                repo_id = f"fallback_repo_{hash(directory) & 0x7fffffff}"
        
        # NO VALID CACHE HIT - Continue with normal scan
        if not java_engine:
            raise ValueError("Java engine not initialized")
        
        # Set progress callback for the engine
        java_engine.set_progress_callback(progress_callback)
        
        # Send language start event
        language_start_event = create_language_start_event(scan_id=scan_id, language="java")
        await websocket_manager.broadcast_progress_event(language_start_event)
        
        # Perform actual vulnerability scan
        await progress_callback.update("scanning", message="Discovering Java files...")
        
        # Add timeout wrapper
        try:
            scan_result = await asyncio.wait_for(
                java_engine.scan_directory(directory),
                timeout=SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.error(f"Scan {scan_id} timed out after {SCAN_TIMEOUT} seconds")
            if DATABASE_AVAILABLE and repo_id and not repo_id.startswith("fallback_"):
                try:
                    async with DB_WRITE_SEMAPHORE:
                        await db_manager.update_scan_status(scan_id, "failed", error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
                except Exception as e:
                    logger.error(f"Failed to update scan status: {e}")
            await progress_callback.update("failed", message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
            raise asyncio.TimeoutError(f"Scan timed out after {SCAN_TIMEOUT} seconds")
        
        # Store results in database with write limiting
        if DATABASE_AVAILABLE and repo_id and not repo_id.startswith("fallback_") and scan_result:
            try:
                async with DB_WRITE_SEMAPHORE:  # Serialize database writes
                    await progress_callback.update("analyzing", message="Storing results in database...")
                    
                    # Use batch method for vulnerabilities
                    await db_manager.store_vulnerabilities_batch(scan_id, scan_result.vulnerabilities)
                    
                    # Update scan completion
                    await db_manager.update_scan_status(
                        scan_id=scan_id,
                        status="completed",
                        total_files=scan_result.total_files,
                        total_vulnerabilities=scan_result.total_vulnerabilities
                    )
                    logger.info(f"Database: Stored {scan_result.total_vulnerabilities} vulnerabilities for scan {scan_id}")
                
            except Exception as e:
                logger.error(f"Database error storing scan results: {e}")
                # Continue even if database storage fails
        
        # CACHE THE RESULT WITH TIMESTAMP (only if scan was successful)
        if scan_result and hasattr(scan_result, 'total_vulnerabilities'):
            directory_fingerprint = generate_directory_fingerprint(directory)
            
            cache_entry = {
                'scan_result': scan_result,
                'cached_at': datetime.now(),
                'directory': directory,
                'fingerprint': directory_fingerprint
            }
            simple_scan_cache[cache_key] = cache_entry
            logger.info(f"Cached scan result for directory: {directory} at {cache_entry['cached_at']}")
            enforce_cache_size_limit()
    
        # Send language complete event
        language_complete_event = create_language_complete_event(
            scan_id=scan_id,
            language="java",
            vulnerabilities_count=scan_result.total_vulnerabilities
        )
        await websocket_manager.broadcast_progress_event(language_complete_event)
        
        # Store results in WebSocket manager (keep existing functionality)
        await websocket_manager.store_scan_result(scan_id, scan_result.to_dict())
        
        # Send completion event
        await progress_callback.update(
            "completed",
            message=f"Vulnerability scan completed: {scan_result.total_files} files, {scan_result.total_vulnerabilities} vulnerabilities",
            files_processed=scan_result.total_files,
            vulnerabilities_found=scan_result.total_vulnerabilities
        )
        
        logger.info(f"Real vulnerability scan completed: {scan_result.total_vulnerabilities} vulnerabilities found")
        
        # NEW: Send scan completion event that React app expects  
        completion_event_data = {
            "scanId": scan_id,
            "totalFiles": scan_result.total_files,
            "totalVulnerabilities": scan_result.total_vulnerabilities,
            "results": []
        }

        # Create the exact event your React app expects
        completion_event = ProgressEvent(
            event_type="scan-completed", 
            scan_id=scan_id,
            timestamp=datetime.utcnow().isoformat(),
            status="completed",
            details=completion_event_data
        )

        # Broadcast using the progress event system
        await websocket_manager.broadcast_progress_event(completion_event)
        logger.info(f"Broadcasted scan completion event for {scan_id}")
        
        return scan_result, repo_id
        
    except asyncio.TimeoutError:
        # Handle timeout specifically
        if DATABASE_AVAILABLE and repo_id and not repo_id.startswith("fallback_"):
            try:
                async with DB_WRITE_SEMAPHORE:
                    await db_manager.update_scan_status(scan_id, "failed", error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
            except Exception as e:
                logger.error(f"Failed to update timeout status: {e}")
        error_event = create_error_event(scan_id=scan_id, error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
        await websocket_manager.broadcast_progress_event(error_event)
        raise
        
    except Exception as e:
        logger.error(f"Real scan failed: {e}")
        if DATABASE_AVAILABLE and repo_id and not repo_id.startswith("fallback_"):
            try:
                async with DB_WRITE_SEMAPHORE:
                    await db_manager.update_scan_status(scan_id, "failed", error_message=str(e))
            except Exception as db_error:
                logger.error(f"Failed to update error status: {db_error}")
        error_event = create_error_event(scan_id=scan_id, error_message=f"Scan failed: {str(e)}")
        await websocket_manager.broadcast_progress_event(error_event)
        raise

async def scan_with_fallback_simulator(directory: str, scan_id: str):
    """Fallback simulator when real engines are not available"""
    try:
        progress_callback = WebSocketProgressCallback(scan_id)
        
        await progress_callback.update("started", message=f"Starting simulated scan: {directory}")
        
        # Simulate file discovery
        java_files = []
        if os.path.exists(directory):
            for root, dirs, files in os.walk(directory):
                dirs[:] = [d for d in dirs if d not in ['.git', 'target', 'build', 'node_modules']]
                for file in files:
                    if file.endswith(('.java', '.jsp', '.jspx')):
                        java_files.append(os.path.join(root, file))
        
        # Simulate scanning progress
        for i, file_path in enumerate(java_files):
            progress = 25 + (i / len(java_files)) * 50
            await progress_callback.update(
                "scanning",
                progress=progress,
                current_file=os.path.basename(file_path),
                files_processed=i + 1,
                total_files=len(java_files)
            )
            await asyncio.sleep(0.1)
        
        # Complete
        await progress_callback.update(
            "completed",
            message=f"Simulated scan completed: {len(java_files)} files (no real vulnerability detection)",
            files_processed=len(java_files),
            vulnerabilities_found=0
        )
        
        return {
            "scan_id": scan_id,
            "files_scanned": len(java_files),
            "vulnerabilities_found": 0,
            "status": "completed",
            "note": "Simulated scan - no real vulnerability detection"
        }, None
        
    except Exception as e:
        logger.error(f"Simulated scan failed: {e}")
        error_event = create_error_event(scan_id=scan_id, error_message=f"Simulated scan failed: {str(e)}")
        await websocket_manager.broadcast_progress_event(error_event)
        raise

# Add this endpoint after your existing API endpoints
@app.get("/api/cache/stats")
async def get_cache_stats_with_expiry():
    """Get cache statistics with expiry information"""
    # Clean up first to get accurate stats
    cleanup_expired_cache_entries()
    
    total_entries = len(simple_scan_cache)
    valid_entries = 0
    expired_entries = 0
    
    for cache_entry in simple_scan_cache.values():
        if is_cache_entry_valid(cache_entry):
            valid_entries += 1
        else:
            expired_entries += 1
    
    return {
        "total_cached_directories": total_entries,
        "valid_entries": valid_entries,
        "expired_entries": expired_entries,
        "cache_expiry_hours": CACHE_EXPIRY_HOURS,
        "cache_keys": list(simple_scan_cache.keys()),
        "cache_entries_detail": [
            {
                "key": key,
                "cached_at": entry.get('cached_at').isoformat() if entry.get('cached_at') else "unknown",
                "directory": entry.get('directory', 'unknown'),
                "valid": is_cache_entry_valid(entry)
            }
            for key, entry in simple_scan_cache.items()
            if isinstance(entry, dict)  # Only process dict entries
        ]
    }

@app.post("/api/cache/clear")
async def clear_simple_cache():
    """Clear the simple scan cache"""
    global simple_scan_cache
    cleared_count = len(simple_scan_cache)
    simple_scan_cache.clear()
    return {
        "message": f"Cleared {cleared_count} cached scan results",
        "remaining_entries": len(simple_scan_cache),
        "cache_expiry_hours": CACHE_EXPIRY_HOURS
    }

@app.post("/api/cache/cleanup")
async def manual_cache_cleanup():
    """Manually trigger cleanup of expired cache entries"""
    initial_count = len(simple_scan_cache)
    cleanup_expired_cache_entries()
    final_count = len(simple_scan_cache)
    removed_count = initial_count - final_count
    
    return {
        "message": f"Cache cleanup completed",
        "entries_removed": removed_count,
        "entries_remaining": final_count,
        "cache_expiry_hours": CACHE_EXPIRY_HOURS
    }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time progress updates"""
    connection_id = None
    try:
        connection_id = await websocket_manager.connect(websocket)
        logger.info(f"WebSocket connected: {connection_id}")
        
        while True:
            try:
                message = await websocket.receive_text()
                await websocket_manager.handle_websocket_message(connection_id, message)
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket error: {e}")
                break
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {connection_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if connection_id:
            await websocket_manager.disconnect(connection_id)

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a new vulnerability scan with database integration"""
    try:
        scan_id = request.scan_id or str(uuid.uuid4())
        
        # Validate request
        if request.scan_type not in ["files", "directory"]:
            raise HTTPException(status_code=400, detail="scan_type must be 'files' or 'directory'")
        
        if not request.paths:
            raise HTTPException(status_code=400, detail="paths cannot be empty")
        
        # Get available languages
        available_languages = ["java"] if java_engine else []
        
        # Start scan in background
        if request.scan_type == "directory":
            if len(request.paths) != 1:
                raise HTTPException(status_code=400, detail="Directory scan requires exactly one path")
            
            directory = request.paths[0]
            if not os.path.exists(directory):
                raise HTTPException(status_code=400, detail=f"Directory not found: {directory}")
            
            # Choose scan method based on engine availability
            if java_engine and JAVA_ENGINE_AVAILABLE:
                # NEW: Pass repository name to scan function
                task = scan_with_real_engine(directory, scan_id, request.languages, request.repository_name)
                asyncio.create_task(task)
                message = f"Real vulnerability scan {scan_id} started with database storage"
                real_detection = True
            else:
                asyncio.create_task(scan_with_fallback_simulator(directory, scan_id))
                message = f"Simulated scan {scan_id} started (real engines not available)"
                real_detection = False
                
        else:
            raise HTTPException(status_code=501, detail="File scan not implemented yet")
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=message,
            languages_available=available_languages,
            real_vulnerability_detection=real_detection
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{scan_id}/result")
async def get_scan_result(scan_id: str):
    """Get completed scan result from database or memory"""
    # NEW: Try database first
    if DATABASE_AVAILABLE:
        try:
            db_result = await db_manager.get_scan_with_vulnerabilities(scan_id)
            if db_result:
                logger.info(f"Retrieved scan {scan_id} from database")
                return db_result
        except Exception as e:
            logger.error(f"Database error retrieving scan: {e}")
    
    # Fallback to WebSocket manager memory storage
    result = await websocket_manager.get_scan_result(scan_id)
    if result:
        logger.info(f"Retrieved scan {scan_id} from memory")
        return result
    else:
        raise HTTPException(status_code=404, detail="Scan result not found")

# NEW: Database-specific endpoints
@app.get("/api/repositories")
async def get_all_repositories():
    """Get all repositories with scan counts"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        repositories = await db_manager.get_all_repositories()
        return {
            "repositories": repositories,
            "total_repositories": len(repositories)
        }
    except Exception as e:
        logger.error(f"Failed to get repositories: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/repository/{repository_id}/scans")
async def get_repository_scans(repository_id: str):
    """Get all scans for a specific repository"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        scans = await db_manager.get_scans_for_repository(repository_id)
        return {
            "repository_id": repository_id,
            "scans": scans,
            "total_scans": len(scans)
        }
    except Exception as e:
        logger.error(f"Failed to get repository scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Add this new endpoint to your main.py file, after your existing API endpoints

@app.get("/api/scans/all")
async def get_all_scans():
    """Get all scans across all repositories with summary information"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # First get all repositories
        repositories = await db_manager.get_all_repositories()
        
        all_scans = []
        
        # Get scans for each repository
        for repo in repositories:
            repo_scans = await db_manager.get_scans_for_repository(repo['repository_id'])
            
            # Add repository info to each scan
            for scan in repo_scans:
                scan_summary = {
                    "scan_id": scan['scan_id'],
                    "repository_id": scan['repository_id'],
                    "repository_name": repo['name'],
                    "repository_url": repo['url'],
                    "scan_path": scan['scan_path'],
                    "language": scan['language'],
                    "status": scan['status'],
                    "total_files": scan['total_files'] or 0,
                    "total_vulnerabilities": scan['total_vulnerabilities'] or 0,
                    "created_at": scan['created_at'],
                    "completed_at": scan['completed_at'],
                    "scan_duration": scan['scan_duration'] or 0.0,
                    "error_message": scan['error_message']
                }
                all_scans.append(scan_summary)
        
        # Sort by creation time (newest first)
        all_scans.sort(key=lambda x: x['created_at'], reverse=True)
        
        return {
            "scans": all_scans,
            "total_scans": len(all_scans),
            "total_repositories": len(repositories)
        }
        
    except Exception as e:
        logger.error(f"Failed to get all scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans/recent")
async def get_recent_scans(limit: int = 50):
    """Get recent scans with limit"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # Get all scans (reuse the logic from get_all_scans)
        all_scans_response = await get_all_scans()
        all_scans = all_scans_response["scans"]
        
        # Limit the results
        recent_scans = all_scans[:limit]
        
        return {
            "scans": recent_scans,
            "total_shown": len(recent_scans),
            "total_available": len(all_scans)
        }
        
    except Exception as e:
        logger.error(f"Failed to get recent scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/scans/all")
async def delete_all_scans():
    """Delete all scans and associated vulnerabilities"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        # Call the database manager method
        deleted_stats = await db_manager.delete_all_scans()
        
        logger.info(f"Deleted all scans: {deleted_stats}")
        
        return {
            "message": "All scan records deleted successfully",
            "deleted_items": deleted_stats
        }
        
    except Exception as e:
        logger.error(f"Failed to delete all scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and all associated vulnerabilities"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        import aiosqlite
        
        async with aiosqlite.connect(db_manager.db_path) as db:
            # Check if scan exists
            cursor = await db.execute('SELECT scan_id FROM scans WHERE scan_id = ?', (scan_id,))
            scan_exists = await cursor.fetchone()
            
            if not scan_exists:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            # Delete code contexts first (foreign key dependency)
            cursor = await db.execute('''
                DELETE FROM code_context 
                WHERE vulnerability_id IN (
                    SELECT vulnerability_id FROM vulnerabilities WHERE scan_id = ?
                )
            ''', (scan_id,))
            contexts_deleted = cursor.rowcount
            
            # Delete vulnerabilities
            cursor = await db.execute('DELETE FROM vulnerabilities WHERE scan_id = ?', (scan_id,))
            vulnerabilities_deleted = cursor.rowcount
            
            # Delete scan
            cursor = await db.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            scans_deleted = cursor.rowcount
            
            await db.commit()
            
            logger.info(f"Deleted scan {scan_id}: {scans_deleted} scan, {vulnerabilities_deleted} vulnerabilities, {contexts_deleted} contexts")
            
            return {
                "message": f"Scan {scan_id} deleted successfully",
                "deleted_items": {
                    "scans": scans_deleted,
                    "vulnerabilities": vulnerabilities_deleted,
                    "code_contexts": contexts_deleted
                }
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/database/stats")
async def get_database_stats():
    """Get database statistics"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        stats = await db_manager.get_database_stats()
        return stats
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/database/cleanup")
async def cleanup_database():
    """Manually trigger database cleanup"""
    if not DATABASE_AVAILABLE:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        cleanup_stats = await db_manager.cleanup_old_records(retention_days=60)
        return {
            "message": "Database cleanup completed",
            **cleanup_stats
        }
    except Exception as e:
        logger.error(f"Failed to cleanup database: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# NEW: Retention Management Endpoints
@app.get("/api/retention/status")
async def get_retention_status():
    """Get retention manager status"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        status = retention_manager.get_status()
        return status
    except Exception as e:
        logger.error(f"Failed to get retention status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/retention/preview")
async def get_cleanup_preview():
    """Get preview of what would be cleaned up"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        preview = await retention_manager.get_cleanup_preview()
        return preview
    except Exception as e:
        logger.error(f"Failed to generate cleanup preview: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/retention/cleanup/age")
async def manual_age_cleanup():
    """Manually trigger age-based cleanup"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        stats = await retention_manager.cleanup_by_age()
        return {
            "message": "Age-based cleanup completed",
            "stats": stats.to_dict()
        }
    except Exception as e:
        logger.error(f"Age-based cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/retention/cleanup/size")
async def manual_size_cleanup():
    """Manually trigger size-based cleanup"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        stats = await retention_manager.cleanup_by_size()
        return {
            "message": "Size-based cleanup completed",
            "stats": stats.to_dict()
        }
    except Exception as e:
        logger.error(f"Size-based cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/retention/cleanup/orphaned")
async def manual_orphaned_cleanup():
    """Manually trigger orphaned data cleanup"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        stats = await retention_manager.cleanup_orphaned_data()
        return {
            "message": "Orphaned data cleanup completed",
            "stats": stats.to_dict()
        }
    except Exception as e:
        logger.error(f"Orphaned data cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/retention/cleanup/full")
async def manual_full_cleanup():
    """Manually trigger full cleanup (age + size + orphaned)"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        # Run all cleanup types
        age_stats = await retention_manager.cleanup_by_age()
        size_stats = await retention_manager.cleanup_by_size()
        orphaned_stats = await retention_manager.cleanup_orphaned_data()
        
        # Combine stats
        total_scans = age_stats.scans_removed + size_stats.scans_removed
        total_vulns = age_stats.vulnerabilities_removed + size_stats.vulnerabilities_removed
        total_contexts = age_stats.code_contexts_removed + size_stats.code_contexts_removed
        total_repos = orphaned_stats.repositories_removed
        total_size_freed = age_stats.size_freed_mb + size_stats.size_freed_mb
        
        return {
            "message": "Full cleanup completed",
            "total_stats": {
                "scans_removed": total_scans,
                "vulnerabilities_removed": total_vulns,
                "code_contexts_removed": total_contexts,
                "repositories_removed": total_repos,
                "size_freed_mb": total_size_freed
            },
            "detailed_stats": {
                "age_based": age_stats.to_dict(),
                "size_based": size_stats.to_dict(),
                "orphaned_data": orphaned_stats.to_dict()
            }
        }
    except Exception as e:
        logger.error(f"Full cleanup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/retention/config")
async def get_retention_config():
    """Get current retention configuration"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        config = retention_manager.get_config()
        return config
    except Exception as e:
        logger.error(f"Failed to get retention config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/retention/config")
async def update_retention_config(config: RetentionConfigRequest):
    """Update retention configuration"""
    if not retention_manager:
        raise HTTPException(status_code=503, detail="Retention manager not available")
    
    try:
        # Only update non-None values
        updates = {k: v for k, v in config.dict().items() if v is not None}
        
        if not updates:
            raise HTTPException(status_code=400, detail="No configuration values provided")
        
        await retention_manager.update_config(**updates)
        
        return {
            "message": "Retention configuration updated",
            "updated_values": updates,
            "current_config": retention_manager.get_config()
        }
    except Exception as e:
        logger.error(f"Failed to update retention config: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scans")
async def get_all_scan_results():
    """Get all completed scan results from database and memory"""
    results = {}
    
    # Get from database if available
    if DATABASE_AVAILABLE:
        try:
            # This would need a new method in db_manager to get all scans
            # For now, we'll just return memory results
            pass
        except Exception as e:
            logger.error(f"Database error getting all scans: {e}")
    
    # Get from memory
    memory_results = await websocket_manager.get_all_scan_results()
    results.update(memory_results)
    
    return results

@app.get("/api/health")
async def health_check():
    """Health check endpoint with database status"""
    engine_status = "unknown"
    if java_engine:
        try:
            rule_info = await java_engine.get_rule_info()
            engine_status = f"loaded ({rule_info.get('total_rules', 0)} rules)"
        except Exception as e:
            engine_status = f"error: {e}"
    
    # Check database health
    database_status = "not available"
    if DATABASE_AVAILABLE:
        try:
            await db_manager.initialize()
            stats = await db_manager.get_database_stats()
            database_status = f"healthy ({stats.get('scans_count', 0)} scans stored)"
        except Exception as e:
            database_status = f"error: {e}"
    
    # Check retention health
    retention_status = "not available"
    if retention_manager:
        try:
            status = retention_manager.get_status()
            retention_status = f"running (last cleanup: {status.get('last_cleanup_ago_hours', 'never')} hours ago)"
        except Exception as e:
            retention_status = f"error: {e}"
    
    return {
        "status": "healthy",
        "scanner": "WebSocket Vulnerability Scanner with Database & Retention",
        "timestamp": datetime.utcnow().isoformat(),
        "websocket_manager_running": websocket_manager.running,
        "java_engine_available": java_engine is not None,
        "java_engine_status": engine_status,
        "database_available": DATABASE_AVAILABLE,
        "database_status": database_status,
        "retention_available": retention_manager is not None,
        "retention_status": retention_status,
        "real_vulnerability_detection": JAVA_ENGINE_AVAILABLE and java_engine is not None,
        "dependencies_available": JAVA_ENGINE_AVAILABLE
    }
    
@app.get("/api/queue/stats")
async def get_queue_stats():
    """Get current queue statistics"""
    stats = await websocket_manager.get_queue_stats()
    return {
        "max_workers": websocket_manager.job_queue.max_workers,
        "pending_jobs": stats.pending_jobs,
        "running_jobs": stats.running_jobs,
        "queue_health": stats.queue_health
    }

@app.get("/api/stats")
async def get_websocket_stats():
    """Get WebSocket connection statistics"""
    stats = await websocket_manager.get_connection_stats()
    return stats

@app.get("/api/engines")
async def get_available_engines():
    """Get information about available scanning engines"""
    engines = {}
    
    if java_engine:
        try:
            engines["java"] = await java_engine.get_rule_info()
        except Exception as e:
            engines["java"] = {"error": str(e), "available": False}
    else:
        engines["java"] = {"available": False, "reason": "Engine not initialized"}
    
    return {
        "engines": engines,
        "java_engine_available": java_engine is not None,
        "real_scanning": JAVA_ENGINE_AVAILABLE and java_engine is not None
    }

@app.get("/api/validate")
async def validate_scanner():
    """Validate scanner configuration and rules"""
    validation = {
        "scanner_valid": True,
        "errors": [],
        "warnings": [],
        "java_engine": {},
        "config_manager": {},
        "rule_loader": {},
        "database": {},
        "retention": {}
    }
    
    # Validate Java engine
    if java_engine:
        try:
            java_validation = await java_engine.validate_rules()
            validation["java_engine"] = java_validation
            if not java_validation.get("valid", False):
                validation["scanner_valid"] = False
                validation["errors"].extend(java_validation.get("errors", []))
        except Exception as e:
            validation["java_engine"] = {"error": str(e)}
            validation["errors"].append(f"Java engine validation failed: {e}")
            validation["scanner_valid"] = False
    else:
        validation["warnings"].append("Java engine not available")
    
    # Validate config manager
    if config_manager:
        try:
            config_validation = await config_manager.validate_configuration()
            validation["config_manager"] = config_validation
            if config_validation.get("errors"):
                validation["warnings"].extend(config_validation["errors"])
        except Exception as e:
            validation["config_manager"] = {"error": str(e)}
            validation["warnings"].append(f"Config validation failed: {e}")
    
    # Validate rule loader
    try:
        rule_loader = get_async_rule_loader()
        rule_validation = await rule_loader.validate_configuration()
        validation["rule_loader"] = rule_validation
        if not rule_validation.get("valid", False):
            validation["warnings"].extend(rule_validation.get("errors", []))
    except Exception as e:
        validation["rule_loader"] = {"error": str(e)}
        validation["warnings"].append(f"Rule loader validation failed: {e}")
    
    # NEW: Validate database
    if DATABASE_AVAILABLE:
        try:
            await db_manager.initialize()
            stats = await db_manager.get_database_stats()
            validation["database"] = {
                "available": True,
                "initialized": True,
                "stats": stats
            }
        except Exception as e:
            validation["database"] = {"error": str(e)}
            validation["warnings"].append(f"Database validation failed: {e}")
    else:
        validation["database"] = {"available": False}
        validation["warnings"].append("Database not available")
    
    # NEW: Validate retention manager
    if retention_manager:
        try:
            status = retention_manager.get_status()
            validation["retention"] = {
                "available": True,
                "running": status["is_running"],
                "config": status["config"]
            }
        except Exception as e:
            validation["retention"] = {"error": str(e)}
            validation["warnings"].append(f"Retention validation failed: {e}")
    else:
        validation["retention"] = {"available": False}
        validation["warnings"].append("Retention manager not available")
    
    return validation

@app.get("/")
async def root():
    """Root endpoint with basic info including job queue, database, and retention features"""
    queue_info = {}
    # Fixed: Access job_queue through websocket_manager
    if hasattr(websocket_manager, 'job_queue') and websocket_manager.job_queue:
        try:
            stats = await websocket_manager.get_queue_stats()
            queue_info = {
                "queue_enabled": True,
                "max_concurrent_scans": websocket_manager.job_queue.max_workers,
                "current_queue_length": stats.pending_jobs,
                "running_scans": stats.running_jobs
            }
        except Exception:
            queue_info = {"queue_enabled": False, "error": "Queue stats unavailable"}
    else:
        queue_info = {"queue_enabled": False}
    
    # Database info
    database_info = {
        "database_enabled": DATABASE_AVAILABLE,
        "persistent_storage": DATABASE_AVAILABLE
    }
    
    if DATABASE_AVAILABLE:
        try:
            stats = await db_manager.get_database_stats()
            database_info.update({
                "total_repositories": stats.get('repositories_count', 0),
                "total_scans": stats.get('scans_count', 0),
                "total_vulnerabilities": stats.get('vulnerabilities_count', 0)
            })
        except Exception:
            database_info["error"] = "Database stats unavailable"
    
    # NEW: Retention info
    retention_info = {
        "retention_enabled": retention_manager is not None,
        "automated_cleanup": retention_manager is not None
    }
    
    if retention_manager:
        try:
            status = retention_manager.get_status()
            retention_info.update({
                "cleanup_interval_hours": status["config"]["cleanup_interval_hours"],
                "max_retention_days": status["config"]["max_retention_days"],
                "max_database_size_mb": status["config"]["max_database_size_mb"],
                "last_cleanup_ago_hours": status.get("last_cleanup_ago_hours"),
                "next_cleanup_in_hours": status.get("next_cleanup_in_hours")
            })
        except Exception:
            retention_info["error"] = "Retention status unavailable"
    
    return {
        "message": "WebSocket Vulnerability Scanner with Database & Automated Retention",
        "version": "2.2.0",
        "websocket_url": "/ws",
        "api_docs": "/docs",
        "real_vulnerability_detection": JAVA_ENGINE_AVAILABLE and java_engine is not None,
        "engines_available": ["java"] if java_engine else [],
        "queue_info": queue_info,
        "database_info": database_info,
        "retention_info": retention_info,
        "endpoints": {
            "start_scan": "POST /api/scan",
            "get_result": "GET /api/scan/{scan_id}/result",
            "repositories": "GET /api/repositories",
            "repository_scans": "GET /api/repository/{repository_id}/scans",
            "database_stats": "GET /api/database/stats",
            "database_cleanup": "POST /api/database/cleanup",
            "retention_status": "GET /api/retention/status",
            "cleanup_preview": "GET /api/retention/preview", 
            "manual_cleanup": "POST /api/retention/cleanup/full",
            "retention_config": "GET /api/retention/config",
            "job_status": "GET /api/job/{job_id}/status",
            "job_result": "GET /api/job/{job_id}/result",
            "queue_stats": "GET /api/queue/stats",
            "queue_jobs": "GET /api/queue/jobs",
            "health": "GET /api/health",
            "validate": "GET /api/validate",
            "engines": "GET /api/engines"
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    print("WebSocket Vulnerability Scanner with Database & Automated Retention")
    print("=" * 80)
    print(f"Real vulnerability detection: {JAVA_ENGINE_AVAILABLE}")
    print(f"Database storage: {DATABASE_AVAILABLE}")
    print(f"Automated retention: {RETENTION_AVAILABLE}")
    print("WebSocket URL: ws://localhost:8000/ws")
    print("API docs: http://localhost:8000/docs")
    print("Health check: http://localhost:8000/api/health")
    print("Database stats: http://localhost:8000/api/database/stats")
    print("Retention status: http://localhost:8000/api/retention/status")
    print("Cleanup preview: http://localhost:8000/api/retention/preview")
    print("=" * 80)
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="127.0.0.1",  # Changed from 0.0.0.0 to match frontend
        port=8000,
        reload=False,
        log_level="info",
        # Improved connection settings
        limit_concurrency=200,        # Increased from 100
        limit_max_requests=10000,     # Increased from 1000
        backlog=200,                  # Increased from 100
        timeout_keep_alive=120,       # Increased from 30 to 120 seconds
    )