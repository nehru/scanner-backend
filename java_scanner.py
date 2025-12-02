#!/usr/bin/env python3
"""
java_scanner_complete.py - Complete Java WebSocket Scanner with Results API
All-in-one file with result storage and retrieval
"""

import asyncio
import json
import logging
import time
import uuid
import os
from typing import Dict, Set, Optional, Any, List
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dataclasses import dataclass, asdict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============================================================================
# WEBSOCKET MANAGER (with result storage)
# ============================================================================

@dataclass
class ProgressEvent:
    """Progress event data structure"""
    event_type: str
    scan_id: str
    timestamp: str
    progress_percentage: Optional[float] = None
    current_stage: Optional[str] = None
    current_file: Optional[str] = None
    message: Optional[str] = None
    status: Optional[str] = None
    files_processed: Optional[int] = None
    total_files: Optional[int] = None
    vulnerabilities_found: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

class WebSocketConnection:
    def __init__(self, websocket: WebSocket, connection_id: str):
        self.websocket = websocket
        self.connection_id = connection_id
        self.connected_at = datetime.utcnow()
        self.subscribed_scans: Set[str] = set()
        self.last_ping = time.time()
        self.is_active = True

    async def send_event(self, event: ProgressEvent):
        try:
            await self.websocket.send_text(json.dumps(event.to_dict()))
            return True
        except Exception as e:
            logger.warning(f"Failed to send event to {self.connection_id}: {e}")
            self.is_active = False
            return False

    async def send_message(self, message: Dict[str, Any]):
        try:
            await self.websocket.send_text(json.dumps(message))
            return True
        except Exception as e:
            logger.warning(f"Failed to send message to {self.connection_id}: {e}")
            self.is_active = False
            return False

class WebSocketManager:
    def __init__(self):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.scan_connections: Dict[str, Set[str]] = {}
        self.connection_counter = 0
        self.event_history: Dict[str, List[ProgressEvent]] = {}
        self.scan_results: Dict[str, Dict] = {}  # Store completed scan results
        self.running = False

    async def start(self):
        if self.running:
            return
        self.running = True
        logger.info("WebSocket manager started")

    async def stop(self):
        self.running = False
        for connection in list(self.connections.values()):
            try:
                await connection.websocket.close()
            except Exception:
                pass
        self.connections.clear()
        self.scan_connections.clear()
        logger.info("WebSocket manager stopped")

    async def connect(self, websocket: WebSocket) -> str:
        await websocket.accept()
        
        self.connection_counter += 1
        connection_id = f"ws_{self.connection_counter}_{int(time.time())}"
        
        connection = WebSocketConnection(websocket, connection_id)
        self.connections[connection_id] = connection
        
        logger.info(f"WebSocket connected: {connection_id}")
        
        welcome_message = {
            "event_type": "connection_established",
            "connection_id": connection_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "WebSocket connection established"
        }
        await connection.send_message(welcome_message)
        
        return connection_id

    async def disconnect(self, connection_id: str):
        if connection_id in self.connections:
            del self.connections[connection_id]
            logger.info(f"WebSocket disconnected: {connection_id}")

    async def store_scan_result(self, scan_id: str, result: Dict):
        """Store completed scan result"""
        self.scan_results[scan_id] = result
        logger.info(f"Stored result for scan {scan_id}")

    async def get_scan_result(self, scan_id: str) -> Optional[Dict]:
        """Get completed scan result"""
        return self.scan_results.get(scan_id)

    async def get_all_scan_results(self) -> Dict[str, Dict]:
        """Get all scan results"""
        return self.scan_results.copy()

    async def broadcast_progress_event(self, event: ProgressEvent):
        scan_id = event.scan_id
        
        # Store in history
        if scan_id not in self.event_history:
            self.event_history[scan_id] = []
        self.event_history[scan_id].append(event)
        
        # Broadcast to all connections (simplified - broadcast to all)
        successful_sends = 0
        failed_connections = []
        
        for connection_id, connection in self.connections.items():
            if connection.is_active:
                success = await connection.send_event(event)
                if success:
                    successful_sends += 1
                else:
                    failed_connections.append(connection_id)
        
        # Clean up failed connections
        for connection_id in failed_connections:
            await self.disconnect(connection_id)
        
        if successful_sends > 0:
            logger.debug(f"Broadcasted {event.event_type} to {successful_sends} connections")

    async def handle_websocket_message(self, connection_id: str, message: str):
        try:
            data = json.loads(message)
            action = data.get("action")
            
            if action == "ping":
                if connection_id in self.connections:
                    self.connections[connection_id].last_ping = time.time()
                    pong_message = {
                        "event_type": "pong",
                        "timestamp": datetime.utcnow().isoformat(),
                        "connection_id": connection_id
                    }
                    await self.connections[connection_id].send_message(pong_message)
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")

    async def get_connection_stats(self) -> Dict[str, Any]:
        active_connections = sum(1 for conn in self.connections.values() if conn.is_active)
        return {
            "total_connections": len(self.connections),
            "active_connections": active_connections,
            "events_in_history": sum(len(events) for events in self.event_history.values()),
            "completed_scans": len(self.scan_results)
        }

# Helper functions
def create_progress_event(scan_id: str, progress: float, stage: str = None, 
                         message: str = None, **kwargs) -> ProgressEvent:
    return ProgressEvent(
        event_type="progress",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        progress_percentage=progress,
        current_stage=stage,
        message=message,
        **kwargs
    )

def create_status_event(scan_id: str, status: str, message: str = None, **kwargs) -> ProgressEvent:
    return ProgressEvent(
        event_type="status_change",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        status=status,
        message=message,
        **kwargs
    )

def create_error_event(scan_id: str, error_message: str, **kwargs) -> ProgressEvent:
    return ProgressEvent(
        event_type="error",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        message=error_message,
        **kwargs
    )

# Global WebSocket manager
websocket_manager = WebSocketManager()

# ============================================================================
# JAVA SCANNER
# ============================================================================

class SimpleJavaScanner:
    """Simple Java scanner for testing WebSocket integration"""
    
    def __init__(self):
        self.supported_extensions = ['.java', '.jsp', '.jspx']
        self.max_file_size = 10 * 1024 * 1024  # 10MB
    
    async def scan_directory(self, directory: str, scan_id: str):
        """Simple directory scan with WebSocket progress"""
        try:
            # Send start event
            start_event = create_status_event(
                scan_id=scan_id,
                status="started",
                message=f"Starting Java scan of: {directory}"
            )
            await websocket_manager.broadcast_progress_event(start_event)
            
            # Find Java files
            java_files = []
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    # Skip common build directories
                    dirs[:] = [d for d in dirs if d not in ['.git', 'target', 'build', 'node_modules']]
                    
                    for file in files:
                        if any(file.endswith(ext) for ext in self.supported_extensions):
                            file_path = os.path.join(root, file)
                            try:
                                if os.path.getsize(file_path) <= self.max_file_size:
                                    java_files.append(file_path)
                            except OSError:
                                continue
            
            # Send discovery progress
            discovery_event = create_progress_event(
                scan_id=scan_id,
                progress=25.0,
                stage="discovery",
                message=f"Found {len(java_files)} Java files",
                total_files=len(java_files)
            )
            await websocket_manager.broadcast_progress_event(discovery_event)
            
            # Simulate processing files
            for i, file_path in enumerate(java_files):
                progress = 25 + (i / max(1, len(java_files))) * 70  # 25% to 95%
                
                progress_event = create_progress_event(
                    scan_id=scan_id,
                    progress=progress,
                    stage="scanning",
                    current_file=os.path.basename(file_path),
                    files_processed=i + 1,
                    total_files=len(java_files)
                )
                await websocket_manager.broadcast_progress_event(progress_event)
                
                # Small delay to simulate processing
                await asyncio.sleep(0.1)
            
            # Create detailed scan result
            scan_result = {
                "scan_id": scan_id,
                "files_scanned": len(java_files),
                "vulnerabilities_found": 0,
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "directory_scanned": directory,
                "java_files": [os.path.basename(f) for f in java_files],
                "scan_summary": {
                    "total_files": len(java_files),
                    "file_types": {
                        ".java": len([f for f in java_files if f.endswith('.java')]),
                        ".jsp": len([f for f in java_files if f.endswith('.jsp')]),
                        ".jspx": len([f for f in java_files if f.endswith('.jspx')])
                    },
                    "largest_file_bytes": max((os.path.getsize(f) for f in java_files), default=0) if java_files else 0,
                    "scan_duration_seconds": 0.1 * len(java_files)  # Simulated duration
                }
            }
            
            # Store the result
            await websocket_manager.store_scan_result(scan_id, scan_result)
            
            # Send completion
            complete_event = create_status_event(
                scan_id=scan_id,
                status="completed",
                message=f"Scan completed: {len(java_files)} Java files processed",
                files_processed=len(java_files),
                vulnerabilities_found=0
            )
            await websocket_manager.broadcast_progress_event(complete_event)
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            error_event = create_error_event(
                scan_id=scan_id,
                error_message=f"Scan failed: {str(e)}"
            )
            await websocket_manager.broadcast_progress_event(error_event)
            raise

# ============================================================================
# FASTAPI APP
# ============================================================================

app = FastAPI(title="Java WebSocket Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    scan_type: str  # "directory"
    paths: List[str]  # Directory path
    scan_id: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

# Global scanner
java_scanner = SimpleJavaScanner()

@app.on_event("startup")
async def startup_event():
    """Initialize the WebSocket scanner"""
    logger.info("Starting Java WebSocket Scanner...")
    await websocket_manager.start()
    logger.info("Java WebSocket Scanner ready!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("Shutting down...")
    await websocket_manager.stop()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time progress updates"""
    connection_id = None
    try:
        connection_id = await websocket_manager.connect(websocket)
        
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
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if connection_id:
            await websocket_manager.disconnect(connection_id)

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest):
    """Start a new Java scan"""
    try:
        # Log the received request for debugging
        logger.info(f"Received scan request: scan_type={request.scan_type}, paths={request.paths}")
        
        scan_id = request.scan_id or str(uuid.uuid4())
        
        # Validate scan_type
        if request.scan_type != "directory":
            raise HTTPException(
                status_code=400, 
                detail=f"Invalid scan_type: '{request.scan_type}'. Only 'directory' is supported."
            )
        
        # Validate paths
        if not request.paths:
            raise HTTPException(
                status_code=400, 
                detail="paths field is required and cannot be empty"
            )
        
        if len(request.paths) != 1:
            raise HTTPException(
                status_code=400, 
                detail=f"Exactly one directory path required, got {len(request.paths)} paths"
            )
        
        directory = request.paths[0]
        
        # Validate directory exists
        if not directory:
            raise HTTPException(status_code=400, detail="Directory path cannot be empty")
            
        if not os.path.exists(directory):
            raise HTTPException(
                status_code=400, 
                detail=f"Directory not found: {directory}"
            )
        
        if not os.path.isdir(directory):
            raise HTTPException(
                status_code=400, 
                detail=f"Path is not a directory: {directory}"
            )
        
        logger.info(f"Starting scan {scan_id} for directory: {directory}")
        
        # Start scan in background
        asyncio.create_task(java_scanner.scan_directory(directory, scan_id))
        
        return ScanResponse(
            scan_id=scan_id,
            status="started",
            message=f"Java scan {scan_id} started for: {directory}"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get result of a specific scan"""
    result = await websocket_manager.get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return result

@app.get("/api/scans")
async def get_all_scans():
    """Get all completed scan results"""
    results = await websocket_manager.get_all_scan_results()
    return {
        "total_scans": len(results),
        "scans": results
    }

@app.get("/api/scan/{scan_id}/events")
async def get_scan_events(scan_id: str):
    """Get all events for a specific scan"""
    if scan_id not in websocket_manager.event_history:
        raise HTTPException(status_code=404, detail=f"No events found for scan {scan_id}")
    
    events = websocket_manager.event_history[scan_id]
    return {
        "scan_id": scan_id,
        "total_events": len(events),
        "events": [event.to_dict() for event in events]
    }

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "scanner": "Java WebSocket Scanner",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/api/stats")
async def get_stats():
    stats = await websocket_manager.get_connection_stats()
    return stats

@app.get("/")
async def root():
    return {
        "message": "Java WebSocket Scanner",
        "websocket_url": "/ws",
        "api_docs": "/docs",
        "endpoints": {
            "start_scan": "POST /api/scan",
            "get_scan_result": "GET /api/scan/{scan_id}",
            "get_all_scans": "GET /api/scans",
            "get_scan_events": "GET /api/scan/{scan_id}/events"
        },
        "example_scan": {
            "method": "POST",
            "url": "/api/scan", 
            "body": {
                "scan_type": "directory",
                "paths": ["C:/path/to/java/code"]
            }
        }
    }

if __name__ == "__main__":
    import uvicorn
    
    print("Starting Java WebSocket Scanner...")
    print("WebSocket URL: ws://localhost:8000/ws")
    print("API docs: http://localhost:8000/docs")
    print("Home page: http://localhost:8000/")
    
    uvicorn.run(
        "__main__:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info"
    )