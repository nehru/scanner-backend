#!/usr/bin/env python3
"""
main.py - Complete WebSocket Vulnerability Scanner with Database Integration
Production-ready version using AsyncJavaEngine with SQLite database storage
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
    print("✓ Successfully imported websocket_manager")
except ImportError as e:
    print(f"✗ Failed to import websocket_manager: {e}")
    sys.exit(1)

# Import database manager
try:
    from database.db_manager import db_manager
    print("✓ Successfully imported database manager")
    DATABASE_AVAILABLE = True
except ImportError as e:
    print(f"✗ Failed to import database manager: {e}")
    DATABASE_AVAILABLE = False

# Import scanner components
try:
    from scanner.core.base_classes import AsyncScannerEngine, ProgressCallback
    from scanner.core.language_config import create_config_manager
    from scanner.core.rule_loader import get_async_rule_loader, create_default_rule_config
    from scanner.engines.java_engine import create_java_engine
    print("✓ Successfully imported all scanner components")
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
    logger.info("Starting WebSocket Vulnerability Scanner with Database...")
    
    try:
        # Initialize database first
        if DATABASE_AVAILABLE:
            await db_manager.initialize()
            logger.info("✓ Database initialized")
        else:
            logger.warning("⚠ Database not available - using memory storage")
        
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
        
        logger.info("✓ WebSocket Vulnerability Scanner with Database ready")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"✗ Failed to start scanner: {e}")
        raise
    
    yield  # Application runs here
    
    # Shutdown
    logger.info("Shutting down WebSocket Vulnerability Scanner...")
    await websocket_manager.stop()

# FastAPI app with lifespan
app = FastAPI(
    title="WebSocket Vulnerability Scanner with Database", 
    version="2.1.0",
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

async def scan_with_real_engine(directory: str, scan_id: str, languages: List[str] = None, repository_name: str = None):
    """Scan directory using real vulnerability detection engines with database storage"""
    SCAN_TIMEOUT = 300  # 5 minute timeout per scan
    
    try:
        # Set up progress callback
        progress_callback = WebSocketProgressCallback(scan_id)
        
        # Send start event
        await progress_callback.update("started", message=f"Starting vulnerability scan: {directory}")
        
        # NEW: Create repository record in database
        repo_id = None
        if DATABASE_AVAILABLE:
            try:
                repo_name = repository_name or f"Auto-discovered: {os.path.basename(directory)}"
                repo_id = await db_manager.create_repository(repo_name, directory, "local")
                
                # Create scan session
                await db_manager.create_scan_session(scan_id, repo_id, directory, "java")
                logger.info(f"Database: Created repository {repo_id} and scan session {scan_id}")
            except Exception as e:
                logger.error(f"Database error during setup: {e}")
                # Continue with scan even if database fails
        
        # CLEANUP EXPIRED ENTRIES FIRST (keep existing cache logic)
        cleanup_expired_cache_entries()
        
        # CHECK CACHE WITH EXPIRY
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
                await asyncio.sleep(0.5)
                
                # NEW: Store cached results in database
                if DATABASE_AVAILABLE and repo_id:
                    try:
                        # Store vulnerabilities in database
                        for vulnerability in cached_result.vulnerabilities:
                            await db_manager.store_vulnerability(scan_id, vulnerability)
                        
                        # Update scan status
                        await db_manager.update_scan_status(
                            scan_id=scan_id,
                            status="completed",
                            total_files=cached_result.total_files,
                            total_vulnerabilities=cached_result.total_vulnerabilities
                        )
                        logger.info(f"Database: Stored cached scan results for {scan_id}")
                    except Exception as e:
                        logger.error(f"Database error storing cached results: {e}")
                
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
                return cached_result, repo_id
            else:
                # Remove expired entry
                del simple_scan_cache[cache_key]
                logger.info(f"Removed expired cache entry for {directory}")
        
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
            if DATABASE_AVAILABLE and repo_id:
                await db_manager.update_scan_status(scan_id, "failed", error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
            await progress_callback.update("failed", message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
            raise asyncio.TimeoutError(f"Scan timed out after {SCAN_TIMEOUT} seconds")
        
        # NEW: Store results in database
        if DATABASE_AVAILABLE and repo_id and scan_result:
            try:
                # Store each vulnerability
                await progress_callback.update("analyzing", message="Storing results in database...")
                
                for vulnerability in scan_result.vulnerabilities:
                    await db_manager.store_vulnerability(scan_id, vulnerability)
                
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
                'fingerprint': directory_fingerprint  # NEW: Add fingerprint
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
        return scan_result, repo_id
        
    except asyncio.TimeoutError:
        # Handle timeout specifically
        if DATABASE_AVAILABLE and repo_id:
            await db_manager.update_scan_status(scan_id, "failed", error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
        error_event = create_error_event(scan_id=scan_id, error_message=f"Scan timed out after {SCAN_TIMEOUT} seconds")
        await websocket_manager.broadcast_progress_event(error_event)
        raise
        
    except Exception as e:
        logger.error(f"Real scan failed: {e}")
        if DATABASE_AVAILABLE and repo_id:
            await db_manager.update_scan_status(scan_id, "failed", error_message=str(e))
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
    
    return {
        "status": "healthy",
        "scanner": "WebSocket Vulnerability Scanner with Database",
        "timestamp": datetime.utcnow().isoformat(),
        "websocket_manager_running": websocket_manager.running,
        "java_engine_available": java_engine is not None,
        "java_engine_status": engine_status,
        "database_available": DATABASE_AVAILABLE,
        "database_status": database_status,
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
        "database": {}
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
    
    return validation

@app.get("/")
async def root():
    """Root endpoint with basic info including job queue and database features"""
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
    
    # NEW: Database info
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
    
    return {
        "message": "WebSocket Vulnerability Scanner with Database & Job Queue",
        "version": "2.1.0",
        "websocket_url": "/ws",
        "api_docs": "/docs",
        "real_vulnerability_detection": JAVA_ENGINE_AVAILABLE and java_engine is not None,
        "engines_available": ["java"] if java_engine else [],
        "queue_info": queue_info,
        "database_info": database_info,
        "endpoints": {
            "start_scan": "POST /api/scan",
            "get_result": "GET /api/scan/{scan_id}/result",
            "repositories": "GET /api/repositories",
            "repository_scans": "GET /api/repository/{repository_id}/scans",
            "database_stats": "GET /api/database/stats",
            "database_cleanup": "POST /api/database/cleanup",
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
    
    print("WebSocket Vulnerability Scanner with Database")
    print("=" * 60)
    print(f"Real vulnerability detection: {JAVA_ENGINE_AVAILABLE}")
    print(f"Database storage: {DATABASE_AVAILABLE}")
    print("WebSocket URL: ws://localhost:8000/ws")
    print("API docs: http://localhost:8000/docs")
    print("Health check: http://localhost:8000/api/health")
    print("Database stats: http://localhost:8000/api/database/stats")
    print("Repositories: http://localhost:8000/api/repositories")
    print("=" * 60)
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
        # Add these connection limits
        limit_concurrency=100,        # Max concurrent connections
        limit_max_requests=1000,      # Max requests per connection
        backlog=100,                  # Connection backlog
        timeout_keep_alive=30         # Keep-alive timeout
    )