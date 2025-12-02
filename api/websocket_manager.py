#!/usr/bin/env python3
"""
api/websocket_manager.py - Enhanced with Job Queue Management and Improved Connection Stability
WebSocket Manager for Real-time Progress Updates with Production-Grade Job Queuing
Handles WebSocket connections, progress event broadcasting, and scan job management
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Dict, Set, Optional, Any, List, Callable
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect
from dataclasses import dataclass, asdict
from collections import deque
import threading
import os
import multiprocessing
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# FIXED: Change relative import to absolute import
from scanner.core.base_classes import (
    ScanJob, JobStatus, JobPriority, QueueStats, WorkerInfo, 
    ScanResult, ProgressCallback
)

@dataclass
class ProgressEvent:
    """Progress event data structure"""
    event_type: str  # "progress", "status_change", "language_start", "language_complete", "error", "warning", "queue_update"
    scan_id: str
    timestamp: str
    progress_percentage: Optional[float] = None
    current_stage: Optional[str] = None
    current_language: Optional[str] = None
    current_file: Optional[str] = None
    message: Optional[str] = None
    status: Optional[str] = None
    files_processed: Optional[int] = None
    total_files: Optional[int] = None
    vulnerabilities_found: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    
    # Queue-specific fields
    job_id: Optional[str] = None
    queue_position: Optional[int] = None
    estimated_wait_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {k: v for k, v in asdict(self).items() if v is not None}

class WebSocketConnection:
    """Represents a single WebSocket connection with improved resilience"""
    
    def __init__(self, websocket: WebSocket, connection_id: str):
        self.websocket = websocket
        self.connection_id = connection_id
        self.connected_at = datetime.utcnow()
        self.subscribed_scans: Set[str] = set()
        self.subscribed_jobs: Set[str] = set()  # NEW: Job subscriptions
        self.last_ping = time.time()
        self.last_pong = time.time()  # NEW: Track pong responses
        self.is_active = True
        self.consecutive_failures = 0  # NEW: Track consecutive send failures
        self.max_failures = 3  # NEW: Allow some failures before marking inactive

    async def send_event(self, event: ProgressEvent):
        """Send a progress event to this connection with improved error handling"""
        try:
            await self.websocket.send_text(json.dumps(event.to_dict()))
            # Reset failure count on success
            self.consecutive_failures = 0
            return True
        except Exception as e:
            logger.warning(f"Failed to send event to connection {self.connection_id}: {e}")
            
            # Increment failure count
            self.consecutive_failures += 1
            
            # Only mark inactive after consecutive failures
            if self.consecutive_failures >= self.max_failures:
                logger.warning(f"Connection {self.connection_id} marked inactive after {self.consecutive_failures} consecutive failures")
                self.is_active = False
            
            return False

    async def send_message(self, message: Dict[str, Any]):
        """Send a custom message to this connection with improved error handling"""
        try:
            await self.websocket.send_text(json.dumps(message))
            # Reset failure count on success
            self.consecutive_failures = 0
            return True
        except Exception as e:
            logger.warning(f"Failed to send message to connection {self.connection_id}: {e}")
            
            # Increment failure count
            self.consecutive_failures += 1
            
            # Only mark inactive after consecutive failures
            if self.consecutive_failures >= self.max_failures:
                logger.warning(f"Connection {self.connection_id} marked inactive after {self.consecutive_failures} consecutive failures")
                self.is_active = False
            
            return False

    def subscribe_to_scan(self, scan_id: str):
        """Subscribe this connection to updates for a specific scan"""
        self.subscribed_scans.add(scan_id)
        logger.debug(f"Connection {self.connection_id} subscribed to scan {scan_id}")

    def subscribe_to_job(self, job_id: str):
        """Subscribe this connection to updates for a specific job"""
        self.subscribed_jobs.add(job_id)
        logger.debug(f"Connection {self.connection_id} subscribed to job {job_id}")

    def unsubscribe_from_scan(self, scan_id: str):
        """Unsubscribe this connection from updates for a specific scan"""
        self.subscribed_scans.discard(scan_id)
        logger.debug(f"Connection {self.connection_id} unsubscribed from scan {scan_id}")

    def unsubscribe_from_job(self, job_id: str):
        """Unsubscribe this connection from updates for a specific job"""
        self.subscribed_jobs.discard(job_id)
        logger.debug(f"Connection {self.connection_id} unsubscribed from job {job_id}")

    def is_subscribed_to_scan(self, scan_id: str) -> bool:
        """Check if this connection is subscribed to updates for a specific scan"""
        return scan_id in self.subscribed_scans

    def is_subscribed_to_job(self, job_id: str) -> bool:
        """Check if this connection is subscribed to updates for a specific job"""
        return job_id in self.subscribed_jobs

    def update_ping_time(self):
        """Update last ping time"""
        self.last_ping = time.time()

    def update_pong_time(self):
        """Update last pong time"""
        self.last_pong = time.time()
        # Reset failure count on successful pong
        self.consecutive_failures = 0

    def is_connection_stale(self, stale_timeout: float = 300.0) -> bool:
        """Check if connection is stale (no activity for specified time)"""
        current_time = time.time()
        time_since_ping = current_time - self.last_ping
        time_since_pong = current_time - self.last_pong
        
        # Connection is stale if no ping for stale_timeout seconds
        # OR no pong response for half that time (indicating client isn't responding)
        return (time_since_ping > stale_timeout or 
                time_since_pong > stale_timeout / 2)

class ScanJobQueue:
    """
    Production-grade job queue for managing vulnerability scans
    Prevents resource exhaustion by limiting concurrent scans
    """
    
    def __init__(self, max_workers: int = 3, max_queue_size: int = 15):
        self.max_workers = max_workers
        self.max_queue_size = max_queue_size
        
        # Job storage
        self.pending_jobs = deque()  # Jobs waiting to be processed
        self.running_jobs: Dict[str, ScanJob] = {}  # Currently executing jobs
        self.completed_jobs: Dict[str, ScanJob] = {}  # Completed jobs (last 100)
        self.failed_jobs: Dict[str, ScanJob] = {}  # Failed jobs (last 50)
        
        # Worker management
        self.workers: Dict[str, WorkerInfo] = {}
        self.worker_tasks: Dict[str, asyncio.Task] = {}
        
        # Statistics
        self.total_jobs_processed = 0
        self.total_scan_time = 0.0
        
        # Control
        self.is_running = False
        self.processor_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self.scan_function: Optional[Callable] = None
        self.websocket_manager = None
        
        # Initialize workers
        for i in range(max_workers):
            worker_id = f"worker-{i+1}"
            self.workers[worker_id] = WorkerInfo(
                worker_id=worker_id,
                status="idle"
            )
    
    def set_scan_function(self, scan_func: Callable):
        """Set the function to execute scans"""
        self.scan_function = scan_func
    
    def set_websocket_manager(self, ws_manager):
        """Set WebSocket manager for progress updates"""
        self.websocket_manager = ws_manager
    
    async def start(self):
        """Start the job queue processor"""
        if self.is_running:
            return
        
        self.is_running = True
        self.processor_task = asyncio.create_task(self._process_queue())
        logger.info(f"Job queue started with {self.max_workers} workers")
    
    async def stop(self):
        """Stop the job queue and cancel running jobs"""
        self.is_running = False
        
        if self.processor_task:
            self.processor_task.cancel()
        
        # Cancel all worker tasks
        for task in self.worker_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks.values(), return_exceptions=True)
        
        logger.info("Job queue stopped")
    
    async def submit_job(self, job: ScanJob) -> bool:
        """Submit a job to the queue"""
        if len(self.pending_jobs) >= self.max_queue_size:
            logger.warning(f"Queue is full ({self.max_queue_size} jobs), rejecting job {job.job_id}")
            return False
        
        job.status = JobStatus.QUEUED
        job.queue_position = len(self.pending_jobs) + 1
        job.estimated_wait_time = self._estimate_wait_time()
        
        # Insert based on priority
        if job.priority == JobPriority.URGENT:
            self.pending_jobs.appendleft(job)
        elif job.priority == JobPriority.HIGH:
            # Insert after other urgent jobs
            urgent_count = sum(1 for j in self.pending_jobs if j.priority == JobPriority.URGENT)
            if urgent_count == 0:
                self.pending_jobs.appendleft(job)
            else:
                # Convert to list, insert, convert back
                jobs_list = list(self.pending_jobs)
                jobs_list.insert(urgent_count, job)
                self.pending_jobs = deque(jobs_list)
        else:
            self.pending_jobs.append(job)
        
        logger.info(f"Job {job.job_id} queued with priority {job.priority.value}, position: {job.queue_position}")
        
        # Update queue positions for all jobs
        await self._update_queue_positions()
        
        # Notify WebSocket subscribers
        if self.websocket_manager:
            await self._broadcast_queue_event(job, "queued")
        
        return True
    
    async def get_job_status(self, job_id: str) -> Optional[ScanJob]:
        """Get the current status of a job"""
        # Check running jobs first
        if job_id in self.running_jobs:
            return self.running_jobs[job_id]
        
        # Check completed jobs
        if job_id in self.completed_jobs:
            return self.completed_jobs[job_id]
        
        # Check failed jobs
        if job_id in self.failed_jobs:
            return self.failed_jobs[job_id]
        
        # Check pending jobs
        for job in self.pending_jobs:
            if job.job_id == job_id:
                return job
        
        return None
    
    def get_queue_stats(self) -> QueueStats:
        """Get current queue statistics"""
        pending_count = len(self.pending_jobs)
        running_count = len(self.running_jobs)
        completed_count = len(self.completed_jobs)
        failed_count = len(self.failed_jobs)
        
        active_workers = sum(1 for w in self.workers.values() if w.status == "busy")
        
        # Calculate averages
        avg_wait_time = 0.0
        avg_scan_duration = 0.0
        
        if self.total_jobs_processed > 0:
            avg_scan_duration = self.total_scan_time / self.total_jobs_processed
        
        # Determine queue health
        queue_health = "healthy"
        if pending_count > self.max_queue_size * 0.8:
            queue_health = "congested"
        elif failed_count > completed_count * 0.1:
            queue_health = "degraded"
        
        return QueueStats(
            pending_jobs=pending_count,
            running_jobs=running_count,
            completed_jobs=completed_count,
            failed_jobs=failed_count,
            total_workers=len(self.workers),
            active_workers=active_workers,
            average_wait_time=avg_wait_time,
            average_scan_duration=avg_scan_duration,
            total_jobs_processed=self.total_jobs_processed,
            queue_health=queue_health
        )
    
    async def _process_queue(self):
        """Main queue processing loop"""
        while self.is_running:
            try:
                # Find available worker
                available_worker = None
                for worker_id, worker in self.workers.items():
                    if worker.status == "idle" and worker_id not in self.worker_tasks:
                        available_worker = worker_id
                        break
                
                # Get next job if worker available
                if available_worker and self.pending_jobs:
                    job = self.pending_jobs.popleft()
                    
                    # Update worker status
                    self.workers[available_worker].status = "busy"
                    self.workers[available_worker].current_job_id = job.job_id
                    self.workers[available_worker].last_activity = time.time()
                    
                    # Update job status
                    job.status = JobStatus.RUNNING
                    job.started_at = time.time()
                    job.assigned_worker = available_worker
                    self.running_jobs[job.job_id] = job
                    
                    # Start worker task
                    task = asyncio.create_task(self._execute_job(job, available_worker))
                    self.worker_tasks[available_worker] = task
                    
                    logger.info(f"Started job {job.job_id} on worker {available_worker}")
                    
                    # Update queue positions
                    await self._update_queue_positions()
                    
                    # Notify WebSocket subscribers
                    if self.websocket_manager:
                        await self._broadcast_queue_event(job, "started")
                
                # Sleep briefly before next iteration
                await asyncio.sleep(1.0)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in queue processor: {e}")
                await asyncio.sleep(5.0)
    
    async def _execute_job(self, job: ScanJob, worker_id: str):
        """Execute a scan job"""
        try:
            if not self.scan_function:
                raise ValueError("No scan function configured")
            
            # Create progress callback
            progress_callback = ProgressCallback(
                websocket_manager=self.websocket_manager,
                scan_id=job.job_id,  # Use job_id as scan_id
                job_id=job.job_id
            )
            job.progress_callback = progress_callback
            
            # Execute the scan
            if job.scan_type == "directory":
                result = await self.scan_function(job.paths[0], job.job_id, job.languages)
            else:
                result = await self.scan_function(job.paths, job.job_id, job.languages)
            
            # Job completed successfully
            job.completed_at = time.time()
            job.status = JobStatus.COMPLETED
            job.scan_result = result
            
            # Update statistics
            duration = job.duration
            if duration:
                self.total_scan_time += duration
            self.total_jobs_processed += 1
            
            # Move to completed jobs
            self.completed_jobs[job.job_id] = job
            del self.running_jobs[job.job_id]
            
            # Update worker stats
            worker = self.workers[worker_id]
            worker.jobs_completed += 1
            if duration:
                worker.total_scan_time += duration
            
            logger.info(f"Job {job.job_id} completed successfully in {duration:.2f}s")
            
            # Notify WebSocket subscribers
            if self.websocket_manager:
                await self._broadcast_queue_event(job, "completed")
            
        except Exception as e:
            # Job failed
            job.completed_at = time.time()
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            
            # Move to failed jobs
            self.failed_jobs[job.job_id] = job
            if job.job_id in self.running_jobs:
                del self.running_jobs[job.job_id]
            
            logger.error(f"Job {job.job_id} failed: {e}")
            
            # Notify WebSocket subscribers
            if self.websocket_manager:
                await self._broadcast_queue_event(job, "failed")
        
        finally:
            # Clean up worker
            worker = self.workers[worker_id]
            worker.status = "idle"
            worker.current_job_id = None
            worker.last_activity = time.time()
            
            # Remove task
            if worker_id in self.worker_tasks:
                del self.worker_tasks[worker_id]
    
    def _estimate_wait_time(self) -> float:
        """Estimate wait time for new jobs"""
        if not self.pending_jobs:
            return 0.0
        
        # Simple estimation based on average scan time and queue position
        avg_scan_time = 15.0  # Default 15 seconds
        if self.total_jobs_processed > 0:
            avg_scan_time = self.total_scan_time / self.total_jobs_processed
        
        queue_length = len(self.pending_jobs)
        available_workers = sum(1 for w in self.workers.values() if w.status == "idle")
        
        if available_workers > 0:
            return (queue_length / available_workers) * avg_scan_time
        else:
            return queue_length * avg_scan_time
    
    async def _update_queue_positions(self):
        """Update queue positions for all pending jobs"""
        for i, job in enumerate(self.pending_jobs):
            job.queue_position = i + 1
            job.estimated_wait_time = self._estimate_wait_time()
    
    async def _broadcast_queue_event(self, job: ScanJob, event_type: str):
        """Broadcast queue event to WebSocket subscribers"""
        if not self.websocket_manager:
            return
        
        event = ProgressEvent(
            event_type="queue_update",
            scan_id=job.job_id,
            job_id=job.job_id,
            timestamp=datetime.utcnow().isoformat(),
            message=f"Job {event_type}",
            status=job.status.value,
            queue_position=job.queue_position,
            estimated_wait_time=job.estimated_wait_time
        )
        
        await self.websocket_manager.broadcast_progress_event(event)

class WebSocketManager:
    """
    Enhanced WebSocket Manager with Job Queue Integration and Improved Connection Stability
    Manages WebSocket connections, progress broadcasting, and scan job queuing
    """
    
    def __init__(self, max_workers: int = 3):
        self.connections: Dict[str, WebSocketConnection] = {}
        self.scan_connections: Dict[str, Set[str]] = {}  # scan_id -> set of connection_ids
        self.job_connections: Dict[str, Set[str]] = {}   # job_id -> set of connection_ids
        self.connection_counter = 0
        self.event_history: Dict[str, List[ProgressEvent]] = {}  # scan_id -> events
        self.scan_results: Dict[str, Dict] = {}  # Store completed scan results
        self.max_history_per_scan = 100
        
        # Job Queue Integration
        self.job_queue = ScanJobQueue(max_workers=max_workers)
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.ping_task: Optional[asyncio.Task] = None
        self.running = False

    async def start(self):
        """Start the WebSocket manager and job queue"""
        if self.running:
            return
        
        self.running = True
        
        # Start job queue
        await self.job_queue.start()
        self.job_queue.set_websocket_manager(self)
        
        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.ping_task = asyncio.create_task(self._ping_loop())
        
        logger.info("WebSocket manager with job queue started")

    async def stop(self):
        """Stop the WebSocket manager and job queue"""
        self.running = False
        
        # Stop job queue
        await self.job_queue.stop()
        
        # Cancel background tasks
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.ping_task:
            self.ping_task.cancel()
        
        # Disconnect all clients
        for connection in list(self.connections.values()):
            try:
                await connection.websocket.close()
            except Exception as e:
                logger.debug(f"Error closing connection {connection.connection_id}: {e}")
        
        self.connections.clear()
        self.scan_connections.clear()
        self.job_connections.clear()
        logger.info("WebSocket manager stopped")

    def set_scan_function(self, scan_func: Callable):
        """Set the scan function for the job queue"""
        self.job_queue.set_scan_function(scan_func)

    async def connect(self, websocket: WebSocket) -> str:
        """Accept a new WebSocket connection"""
        await websocket.accept()
        
        self.connection_counter += 1
        connection_id = f"ws_{self.connection_counter}_{int(time.time())}"
        
        connection = WebSocketConnection(websocket, connection_id)
        self.connections[connection_id] = connection
        
        logger.info(f"WebSocket connection established: {connection_id}")
        
        # Send welcome message
        welcome_message = {
            "event_type": "connection_established",
            "connection_id": connection_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": "WebSocket connection established successfully",
            "queue_enabled": True,
            "max_workers": self.job_queue.max_workers
        }
        await connection.send_message(welcome_message)
        
        return connection_id

    async def disconnect(self, connection_id: str):
        """Handle WebSocket disconnection"""
        if connection_id in self.connections:
            connection = self.connections[connection_id]
            
            # Remove from scan subscriptions
            for scan_id in list(connection.subscribed_scans):
                self._unsubscribe_from_scan(connection_id, scan_id)
            
            # Remove from job subscriptions
            for job_id in list(connection.subscribed_jobs):
                self._unsubscribe_from_job(connection_id, job_id)
            
            # Remove connection
            del self.connections[connection_id]
            logger.info(f"WebSocket connection disconnected: {connection_id}")

    async def submit_scan_job(self, job: ScanJob) -> bool:
        """Submit a scan job to the queue"""
        return await self.job_queue.submit_job(job)

    async def get_job_status(self, job_id: str) -> Optional[ScanJob]:
        """Get the status of a scan job"""
        return await self.job_queue.get_job_status(job_id)

    async def get_queue_stats(self) -> QueueStats:
        """Get current queue statistics"""
        return self.job_queue.get_queue_stats()

    async def subscribe_to_scan(self, connection_id: str, scan_id: str):
        """Subscribe a connection to updates for a specific scan"""
        if connection_id not in self.connections:
            return False
        
        connection = self.connections[connection_id]
        connection.subscribe_to_scan(scan_id)
        
        # Add to scan connections mapping
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = set()
        self.scan_connections[scan_id].add(connection_id)
        
        # Send historical events for this scan
        if scan_id in self.event_history:
            for event in self.event_history[scan_id][-10:]:
                await connection.send_event(event)
        
        # Send subscription confirmation
        confirmation = {
            "event_type": "subscription_confirmed",
            "scan_id": scan_id,
            "connection_id": connection_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Subscribed to scan {scan_id}"
        }
        await connection.send_message(confirmation)
        
        return True

    async def subscribe_to_job(self, connection_id: str, job_id: str):
        """Subscribe a connection to updates for a specific job"""
        if connection_id not in self.connections:
            return False
        
        connection = self.connections[connection_id]
        connection.subscribe_to_job(job_id)
        
        # Add to job connections mapping
        if job_id not in self.job_connections:
            self.job_connections[job_id] = set()
        self.job_connections[job_id].add(connection_id)
        
        # Send job status
        job = await self.get_job_status(job_id)
        if job:
            status_message = {
                "event_type": "job_status",
                "job_id": job_id,
                "status": job.status.value,
                "queue_position": job.queue_position,
                "estimated_wait_time": job.estimated_wait_time,
                "timestamp": datetime.utcnow().isoformat()
            }
            await connection.send_message(status_message)
        
        # Send subscription confirmation
        confirmation = {
            "event_type": "job_subscription_confirmed",
            "job_id": job_id,
            "connection_id": connection_id,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Subscribed to job {job_id}"
        }
        await connection.send_message(confirmation)
        
        return True

    def _unsubscribe_from_scan(self, connection_id: str, scan_id: str):
        """Internal method to unsubscribe from scan"""
        if connection_id in self.connections:
            self.connections[connection_id].unsubscribe_from_scan(scan_id)
        
        if scan_id in self.scan_connections:
            self.scan_connections[scan_id].discard(connection_id)
            if not self.scan_connections[scan_id]:
                del self.scan_connections[scan_id]

    def _unsubscribe_from_job(self, connection_id: str, job_id: str):
        """Internal method to unsubscribe from job"""
        if connection_id in self.connections:
            self.connections[connection_id].unsubscribe_from_job(job_id)
        
        if job_id in self.job_connections:
            self.job_connections[job_id].discard(connection_id)
            if not self.job_connections[job_id]:
                del self.job_connections[job_id]

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
        """Broadcast a progress event to all subscribed connections with improved error handling"""
        scan_id = event.scan_id
        
        # Store in history
        if scan_id not in self.event_history:
            self.event_history[scan_id] = []
        self.event_history[scan_id].append(event)
        
        # Limit history size
        if len(self.event_history[scan_id]) > self.max_history_per_scan:
            self.event_history[scan_id] = self.event_history[scan_id][-self.max_history_per_scan:]
        
        # Send to scan subscribers
        scan_connections = self.scan_connections.get(scan_id, set()).copy()
        job_connections = self.job_connections.get(event.job_id, set()).copy() if event.job_id else set()
        
        all_connections = scan_connections | job_connections
        successful_sends = 0
        
        for connection_id in all_connections:
            if connection_id in self.connections:
                connection = self.connections[connection_id]
                if connection.is_active:
                    success = await connection.send_event(event)
                    if success:
                        successful_sends += 1
                    # Don't mark as failed immediately - let connection handle its own failure tracking
        
        # Only log if we had successful sends
        if successful_sends > 0:
            logger.debug(f"Broadcasted {event.event_type} event for scan {scan_id} to {successful_sends} connections")
        elif all_connections:
            logger.warning(f"Failed to broadcast {event.event_type} event for scan {scan_id} - no active connections")

    async def broadcast_queue_event(self, event: Dict[str, Any]):
        """Broadcast a queue-specific event"""
        job_id = event.get("job_id")
        if not job_id:
            return
        
        # Send to job subscribers
        job_connections = self.job_connections.get(job_id, set()).copy()
        successful_sends = 0
        
        for connection_id in job_connections:
            if connection_id in self.connections:
                connection = self.connections[connection_id]
                if connection.is_active:
                    success = await connection.send_message(event)
                    if success:
                        successful_sends += 1
        
        if successful_sends > 0:
            logger.debug(f"Broadcasted queue event to {successful_sends} connections")

    async def broadcast_to_all(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients"""
        successful_sends = 0
        
        for connection_id, connection in self.connections.items():
            if connection.is_active:
                success = await connection.send_message(message)
                if success:
                    successful_sends += 1
        
        logger.debug(f"Broadcasted message to {successful_sends} connections")

    async def get_connection_stats(self) -> Dict[str, Any]:
        """Get statistics about current connections and queue"""
        active_connections = sum(1 for conn in self.connections.values() if conn.is_active)
        queue_stats = self.job_queue.get_queue_stats()
        
        scan_subscription_stats = {}
        for scan_id, connection_ids in self.scan_connections.items():
            scan_subscription_stats[scan_id] = len(connection_ids)
        
        job_subscription_stats = {}
        for job_id, connection_ids in self.job_connections.items():
            job_subscription_stats[job_id] = len(connection_ids)
        
        return {
            "total_connections": len(self.connections),
            "active_connections": active_connections,
            "total_scans_with_subscribers": len(self.scan_connections),
            "total_jobs_with_subscribers": len(self.job_connections),
            "scan_subscriptions": scan_subscription_stats,
            "job_subscriptions": job_subscription_stats,
            "events_in_history": sum(len(events) for events in self.event_history.values()),
            "completed_scans": len(self.scan_results),
            "queue_stats": queue_stats.to_dict()
        }

    async def get_connection_health_stats(self) -> Dict[str, Any]:
        """Get connection health statistics"""
        stats = {
            "total_connections": len(self.connections),
            "healthy_connections": 0,
            "stale_connections": 0,
            "failed_connections": 0,
            "avg_consecutive_failures": 0
        }
        
        total_failures = 0
        for conn in self.connections.values():
            total_failures += conn.consecutive_failures
            if conn.is_connection_stale():
                stats["stale_connections"] += 1
            elif not conn.is_active:
                stats["failed_connections"] += 1
            else:
                stats["healthy_connections"] += 1
        
        if self.connections:
            stats["avg_consecutive_failures"] = total_failures / len(self.connections)
        
        return stats

    async def handle_websocket_message(self, connection_id: str, message: str):
        """Handle incoming WebSocket messages from clients with improved ping/pong"""
        try:
            data = json.loads(message)
            action = data.get("action")
            
            # Update connection activity for any message
            if connection_id in self.connections:
                self.connections[connection_id].update_ping_time()
            
            if action == "subscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    await self.subscribe_to_scan(connection_id, scan_id)
                    
            elif action == "subscribe_job":
                job_id = data.get("job_id")
                if job_id:
                    await self.subscribe_to_job(connection_id, job_id)
                    
            elif action == "unsubscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    await self.unsubscribe_from_scan(connection_id, scan_id)
                    
            elif action == "unsubscribe_job":
                job_id = data.get("job_id")
                if job_id:
                    await self.unsubscribe_from_job(connection_id, job_id)
                    
            elif action == "ping":
                if connection_id in self.connections:
                    connection = self.connections[connection_id]
                    connection.update_ping_time()
                    pong_message = {
                        "event_type": "pong",
                        "timestamp": datetime.utcnow().isoformat(),
                        "connection_id": connection_id,
                        "server_time": time.time()
                    }
                    await connection.send_message(pong_message)
                    logger.debug(f"Sent pong response to {connection_id}")
                    
            elif action == "pong":
                if connection_id in self.connections:
                    self.connections[connection_id].update_pong_time()
                    logger.debug(f"Received pong from {connection_id}")
                    
            elif action == "get_stats":
                if connection_id in self.connections:
                    stats = await self.get_connection_stats()
                    stats_message = {
                        "event_type": "stats",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": stats
                    }
                    await self.connections[connection_id].send_message(stats_message)
            
            elif action == "get_queue_stats":
                if connection_id in self.connections:
                    queue_stats = await self.get_queue_stats()
                    stats_message = {
                        "event_type": "queue_stats",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": queue_stats.to_dict()
                    }
                    await self.connections[connection_id].send_message(stats_message)
            
            else:
                logger.debug(f"Unknown WebSocket action: {action}")
                
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received from connection {connection_id}: {message}")
        except Exception as e:
            logger.error(f"Error handling WebSocket message from {connection_id}: {e}")

    async def _cleanup_loop(self):
        """Background task to clean up inactive connections with improved logic"""
        while self.running:
            try:
                # Run cleanup less frequently
                await asyncio.sleep(60)  # Changed from 30 to 60 seconds
                
                inactive_connections = []
                current_time = time.time()
                
                for connection_id, connection in self.connections.items():
                    # Use the new stale connection check with longer timeout
                    if connection.is_connection_stale(stale_timeout=300.0):  # 5 minutes instead of 2
                        logger.info(f"Connection {connection_id} is stale (no activity for 5+ minutes)")
                        inactive_connections.append(connection_id)
                    # Check if connection is marked as inactive due to send failures
                    elif not connection.is_active:
                        logger.info(f"Connection {connection_id} marked as inactive due to send failures")
                        inactive_connections.append(connection_id)
                
                # Clean up inactive connections
                for connection_id in inactive_connections:
                    await self.disconnect(connection_id)
                
                # Clean up old event history (keep this as is)
                for scan_id in list(self.event_history.keys()):
                    if scan_id not in self.scan_connections:
                        # No active subscriptions, clean up old history
                        del self.event_history[scan_id]
                
                if inactive_connections:
                    logger.info(f"Cleaned up {len(inactive_connections)} inactive connections")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in WebSocket cleanup loop: {e}")

    async def _ping_loop(self):
        """Background task to ping all connections with improved logic"""
        while self.running:
            try:
                # Ping less frequently
                await asyncio.sleep(120)  # Changed from 60 to 120 seconds (2 minutes)
                
                if not self.connections:
                    continue
                
                ping_message = {
                    "event_type": "ping",
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": "Server ping",
                    "server_time": time.time()
                }
                
                successful_pings = 0
                
                for connection_id, connection in self.connections.items():
                    if connection.is_active:
                        success = await connection.send_message(ping_message)
                        if success:
                            successful_pings += 1
                
                logger.debug(f"Sent ping to {successful_pings} connections")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in WebSocket ping loop: {e}")

# Global WebSocket manager instance with queue support
cpu_count = multiprocessing.cpu_count()
max_workers = min(cpu_count, 4)  # 1x CPU cores, max 4 workers

websocket_manager = WebSocketManager(max_workers=max_workers)

# Helper functions for creating progress events (enhanced for queue support)
def create_progress_event(scan_id: str, progress: float, stage: str = None, 
                         language: str = None, message: str = None, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create a progress update event"""
    return ProgressEvent(
        event_type="progress",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        progress_percentage=progress,
        current_stage=stage,
        current_language=language,
        message=message,
        job_id=job_id,
        **kwargs
    )

def create_status_event(scan_id: str, status: str, message: str = None, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create a status change event"""
    return ProgressEvent(
        event_type="status_change",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        status=status,
        message=message,
        job_id=job_id,
        **kwargs
    )

def create_language_start_event(scan_id: str, language: str, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create a language scan start event"""
    return ProgressEvent(
        event_type="language_start",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        current_language=language,
        message=f"Starting {language} scan",
        job_id=job_id,
        **kwargs
    )

def create_language_complete_event(scan_id: str, language: str, vulnerabilities_count: int = None, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create a language scan completion event"""
    return ProgressEvent(
        event_type="language_complete",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        current_language=language,
        vulnerabilities_found=vulnerabilities_count,
        message=f"Completed {language} scan",
        job_id=job_id,
        **kwargs
    )

def create_error_event(scan_id: str, error_message: str, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create an error event"""
    return ProgressEvent(
        event_type="error",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        message=error_message,
        job_id=job_id,
        **kwargs
    )

def create_warning_event(scan_id: str, warning_message: str, job_id: str = None, **kwargs) -> ProgressEvent:
    """Create a warning event"""
    return ProgressEvent(
        event_type="warning",
        scan_id=scan_id,
        timestamp=datetime.utcnow().isoformat(),
        message=warning_message,
        job_id=job_id,
        **kwargs
    )