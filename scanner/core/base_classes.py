#!/usr/bin/env python3
"""
scanner/core/base_classes.py - Enhanced with Job Queue Support
Abstract base classes for async multi-language scanning with WebSocket support
Added job queuing data structures for production load management
"""

import abc
import uuid
import os
import asyncio
import time
from typing import List, Dict, Optional, Tuple, Any, Set, AsyncGenerator
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)

# Existing classes remain the same...
@dataclass
class Vulnerability:
    """Generic vulnerability finding - language agnostic"""
    id: str
    rule_id: str
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    severity: str
    message: str
    vulnerable_code: str
    code_context: List[str]
    solution: Optional[str]
    cwe: Optional[str]
    category: str
    language: str
    confidence: str = "HIGH"
    timestamp: Optional[str] = field(default=None, init=False)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ScanProgress:
    """Real-time scan progress for WebSocket updates"""
    scan_id: str
    stage: str  # 'starting', 'scanning', 'analyzing', 'completed'
    current_file: Optional[str] = None
    files_processed: int = 0
    total_files: int = 0
    vulnerabilities_found: int = 0
    language: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass
class ScanResult:
    """Generic scan results - language agnostic, async-optimized"""
    scan_id: str
    language: str
    languages_detected: List[str] = field(default_factory=list)
    files_scanned: List[str] = field(default_factory=list)
    total_files: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    total_vulnerabilities: int = 0
    scan_duration: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    rules_used: List[str] = field(default_factory=list)
    semgrep_version: str = ""
    scan_status: str = "completed"
    error_message: Optional[str] = None
    
    def __post_init__(self):
        if not self.languages_detected and self.language:
            self.languages_detected = [self.language]
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.total_files = len(self.files_scanned)
    
    def to_dict(self) -> Dict:
        return {
            **asdict(self),
            'vulnerabilities': [vuln.to_dict() for vuln in self.vulnerabilities]
        }
    
    def get_vulnerabilities_by_language(self, language: str) -> List[Vulnerability]:
        return [vuln for vuln in self.vulnerabilities if vuln.language == language]
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[Vulnerability]:
        return [vuln for vuln in self.vulnerabilities if vuln.severity.upper() == severity.upper()]
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        self.vulnerabilities.append(vulnerability)
        self.total_vulnerabilities = len(self.vulnerabilities)
    
    def merge_results(self, other_result: 'ScanResult') -> None:
        self.vulnerabilities.extend(other_result.vulnerabilities)
        self.total_vulnerabilities = len(self.vulnerabilities)
        
        all_files = set(self.files_scanned + other_result.files_scanned)
        self.files_scanned = list(all_files)
        self.total_files = len(self.files_scanned)
        
        all_languages = set(self.languages_detected + other_result.languages_detected)
        self.languages_detected = list(all_languages)
        
        all_rules = set(self.rules_used + other_result.rules_used)
        self.rules_used = list(all_rules)
        
        self.scan_duration += other_result.scan_duration

# NEW: Job Queue Data Structures
class JobStatus(Enum):
    """Status of scan jobs in the queue"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class JobPriority(Enum):
    """Priority levels for scan jobs"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4

@dataclass
class ScanJob:
    """Represents a scan job in the queue"""
    job_id: str
    scan_type: str  # "directory" or "files"
    paths: List[str]
    languages: Optional[List[str]] = None
    recursive: bool = True
    max_files: Optional[int] = None
    
    # Job management fields
    status: JobStatus = JobStatus.PENDING
    priority: JobPriority = JobPriority.NORMAL
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    assigned_worker: Optional[str] = None
    
    # Result tracking
    scan_result: Optional[ScanResult] = None
    error_message: Optional[str] = None
    progress_callback: Optional['ProgressCallback'] = None
    
    # Queue position tracking
    queue_position: int = 0
    estimated_wait_time: float = 0.0
    
    def __post_init__(self):
        if not self.job_id:
            self.job_id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary for API responses"""
        return {
            'job_id': self.job_id,
            'scan_type': self.scan_type,
            'paths': self.paths,
            'languages': self.languages,
            'status': self.status.value,
            'priority': self.priority.value,
            'created_at': self.created_at,
            'started_at': self.started_at,
            'completed_at': self.completed_at,
            'queue_position': self.queue_position,
            'estimated_wait_time': self.estimated_wait_time,
            'assigned_worker': self.assigned_worker,
            'error_message': self.error_message
        }
    
    @property
    def duration(self) -> Optional[float]:
        """Get job execution duration if completed"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None
    
    @property
    def total_time(self) -> Optional[float]:
        """Get total time from creation to completion"""
        if self.completed_at:
            return self.completed_at - self.created_at
        return None

@dataclass
class QueueStats:
    """Statistics about the job queue"""
    pending_jobs: int = 0
    running_jobs: int = 0
    completed_jobs: int = 0
    failed_jobs: int = 0
    total_workers: int = 0
    active_workers: int = 0
    average_wait_time: float = 0.0
    average_scan_duration: float = 0.0
    total_jobs_processed: int = 0
    queue_health: str = "healthy"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class WorkerInfo:
    """Information about a scan worker"""
    worker_id: str
    status: str  # "idle", "busy", "error"
    current_job_id: Optional[str] = None
    jobs_completed: int = 0
    total_scan_time: float = 0.0
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @property
    def average_scan_time(self) -> float:
        """Average time per scan for this worker"""
        if self.jobs_completed > 0:
            return self.total_scan_time / self.jobs_completed
        return 0.0

# Enhanced Progress Callback for Queue Integration
class ProgressCallback:
    """Async progress callback for WebSocket updates with queue support"""
    
    def __init__(self, websocket_manager=None, scan_id: str = None, job_id: str = None):
        self.websocket_manager = websocket_manager
        self.scan_id = scan_id or str(uuid.uuid4())
        self.job_id = job_id
        
    async def update(self, stage: str, **kwargs) -> None:
        """Send progress update via WebSocket"""
        if not self.websocket_manager:
            return
            
        progress = ScanProgress(
            scan_id=self.scan_id,
            stage=stage,
            **kwargs
        )
        
        try:
            await self.websocket_manager.broadcast_progress(progress.to_dict())
        except Exception as e:
            logger.debug(f"Progress update failed: {e}")
    
    async def queue_update(self, position: int, estimated_wait: float, **kwargs) -> None:
        """Send queue position update"""
        if not self.websocket_manager:
            return
        
        try:
            queue_event = {
                'event_type': 'queue_update',
                'scan_id': self.scan_id,
                'job_id': self.job_id,
                'queue_position': position,
                'estimated_wait_time': estimated_wait,
                'timestamp': datetime.now().isoformat(),
                **kwargs
            }
            await self.websocket_manager.broadcast_queue_event(queue_event)
        except Exception as e:
            logger.debug(f"Queue update failed: {e}")

# Existing classes continue unchanged...
class BaseLanguageEngine(abc.ABC):
    """
    Async base class for language engines with queue support
    """
    
    def __init__(self, language_name: str, language_config, base_config: Optional[Dict] = None):
        self.language = language_name
        self.language_config = language_config
        self.base_config = base_config or {}
        
        # Configuration
        self.supported_extensions = getattr(language_config, 'extensions', [])
        self.semgrep_timeout = self.base_config.get('timeout', 300)
        self.max_file_size = self.base_config.get('max_file_size', 10 * 1024 * 1024)
        self.max_files_per_scan = self.base_config.get('max_files_per_scan', 1000)
        
        # Async configuration
        self.max_concurrent_files = self.base_config.get('max_concurrent_files', 10)
        self.progress_callback: Optional[ProgressCallback] = None
        
        logger.info(f"Async BaseLanguageEngine initialized for {language_name}")
    
    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback for WebSocket updates"""
        self.progress_callback = callback
    
    async def _progress_update(self, stage: str, **kwargs) -> None:
        """Send progress update if callback is set"""
        if self.progress_callback:
            await self.progress_callback.update(stage, language=self.language, **kwargs)
    
    async def _get_code_context(self, file_path: str, line_number: int, context_lines: int = 3) -> Tuple[str, List[str]]:
        """Extract vulnerable code and surrounding context - async implementation"""
        try:
            async with asyncio.Lock():
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            
            if 1 <= line_number <= len(lines):
                vulnerable_line = lines[line_number - 1].strip()
            else:
                vulnerable_line = "Unable to read vulnerable line"
            
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            context = []
            for i in range(start, end):
                line_num = i + 1
                line_content = lines[i].rstrip()
                is_vulnerable = line_num == line_number
                context.append({
                    'line_number': line_num,
                    'content': line_content,
                    'is_vulnerable': is_vulnerable
                })
            
            return vulnerable_line, context
            
        except Exception as e:
            logger.warning(f"Could not read code context from {file_path}: {e}")
            return "Unable to read code", []
    
    async def scan_files_batch(self, file_paths: List[str], batch_size: int = None) -> AsyncGenerator[ScanResult, None]:
        """Scan files in batches with async progress updates"""
        batch_size = batch_size or self.max_concurrent_files
        
        for i in range(0, len(file_paths), batch_size):
            batch = file_paths[i:i + batch_size]
            
            await self._progress_update(
                'scanning',
                current_file=batch[0],
                files_processed=i,
                total_files=len(file_paths)
            )
            
            tasks = [self._scan_single_file(file_path) for file_path in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(batch_results):
                if isinstance(result, Exception):
                    logger.error(f"Error scanning {batch[j]}: {result}")
                    continue
                    
                if result and result.vulnerabilities:
                    yield result
    
    async def _scan_single_file(self, file_path: str) -> Optional[ScanResult]:
        """Scan a single file (to be implemented by subclasses)"""
        return None
    
    async def generate_csv_report(self, scan_result: ScanResult, output_file: str) -> None:
        """Generate CSV report - async implementation"""
        import csv
        
        try:
            async with asyncio.Lock():
                with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                    fieldnames = [
                        'File Name', 'Line Number', 'Error Description', 
                        'Solution Code', 'Rule ID', 'Severity', 'Language', 'CWE'
                    ]
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    
                    for vuln in scan_result.vulnerabilities:
                        filename = os.path.basename(vuln.file_path)
                        solution = vuln.solution if vuln.solution else "No solution available"
                        solution_clean = solution.replace('\n', ' | ').replace('\r', '')
                        
                        writer.writerow({
                            'File Name': filename,
                            'Line Number': vuln.line_number,
                            'Error Description': vuln.message,
                            'Solution Code': solution_clean,
                            'Rule ID': vuln.rule_id,
                            'Severity': vuln.severity,
                            'Language': vuln.language,
                            'CWE': vuln.cwe or 'N/A'
                        })
            
            logger.info(f"Async CSV report generated: {output_file}")
            
        except Exception as e:
            logger.error(f"Error generating CSV report: {e}")
            raise
    
    def get_statistics(self, scan_result: ScanResult) -> Dict:
        """Generate statistics for scan results"""
        if not scan_result.vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'by_severity': {},
                'by_rule': {},
                'by_file': {},
                'most_vulnerable_files': []
            }
        
        severity_counts = {}
        for vuln in scan_result.vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        rule_counts = {}
        for vuln in scan_result.vulnerabilities:
            rule_counts[vuln.rule_id] = rule_counts.get(vuln.rule_id, 0) + 1
        
        file_counts = {}
        for vuln in scan_result.vulnerabilities:
            file_counts[vuln.file_path] = file_counts.get(vuln.file_path, 0) + 1
        
        most_vulnerable = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            'total_vulnerabilities': len(scan_result.vulnerabilities),
            'by_severity': severity_counts,
            'by_rule': rule_counts,
            'by_file': file_counts,
            'most_vulnerable_files': most_vulnerable,
            'files_with_issues': len(file_counts),
            'clean_files': scan_result.total_files - len(file_counts)
        }
    
    # Abstract methods that subclasses must implement
    @abc.abstractmethod
    async def _initialize_engine(self):
        """Initialize language-specific components (rules, solutions, etc.)"""
        pass
    
    @abc.abstractmethod
    async def identify_files(self, file_paths: List[str]) -> List[str]:
        """Filter and identify files for this language from a list of file paths"""
        pass
    
    @abc.abstractmethod
    async def discover_files_in_directory(self, directory: str) -> List[str]:
        """Recursively discover files for this language in a directory"""
        pass
    
    @abc.abstractmethod
    async def scan_files(self, file_paths: List[str]) -> ScanResult:
        """Scan specific files for vulnerabilities"""
        pass
    
    @abc.abstractmethod
    async def scan_directory(self, directory: str) -> ScanResult:
        """Scan a directory for vulnerabilities"""
        pass
    
    @abc.abstractmethod
    async def get_rule_info(self) -> Dict:
        """Get information about loaded rules for this language"""
        pass
    
    @abc.abstractmethod
    async def validate_rules(self) -> Dict:
        """Validate that rules are accessible and functional"""
        pass
    
    def get_language_info(self) -> Dict:
        """Get basic information about this language engine"""
        return {
            'language': self.language,
            'extensions': self.supported_extensions,
            'enabled': self.language_config.enabled,
            'description': self.language_config.description,
            'async_engine': True,
            'websocket_capable': True,
            'queue_ready': True
        }

class AsyncScannerEngine:
    """Main async scanner engine with job queue support"""
    
    def __init__(self, base_config: Optional[Dict] = None):
        self.base_config = base_config or {}
        self.language_engines: Dict[str, BaseLanguageEngine] = {}
        self.websocket_manager = None
        self.job_queue = None  # Will be set by WebSocket manager
        
    def register_engine(self, engine: BaseLanguageEngine) -> None:
        """Register a language engine"""
        self.language_engines[engine.language] = engine
        logger.info(f"Registered async engine for {engine.language}")
    
    def set_websocket_manager(self, websocket_manager) -> None:
        """Set WebSocket manager for progress updates"""
        self.websocket_manager = websocket_manager
        
        for engine in self.language_engines.values():
            callback = ProgressCallback(websocket_manager)
            engine.set_progress_callback(callback)
    
    def set_job_queue(self, job_queue) -> None:
        """Set job queue for managing scan workload"""
        self.job_queue = job_queue
    
    async def scan_with_multiple_languages(self, file_paths: List[str], languages: List[str] = None) -> ScanResult:
        """Scan files with multiple language engines concurrently"""
        if not languages:
            languages = list(self.language_engines.keys())
        
        available_engines = {
            lang: engine for lang, engine in self.language_engines.items() 
            if lang in languages
        }
        
        if not available_engines:
            raise ValueError(f"No engines available for languages: {languages}")
        
        scan_tasks = []
        for lang, engine in available_engines.items():
            lang_files = await engine.identify_files(file_paths)
            if lang_files:
                task = engine.scan_files(lang_files)
                scan_tasks.append((lang, task))
        
        combined_result = ScanResult(
            scan_id=str(uuid.uuid4()),
            language='multi-language'
        )
        
        for lang, task in scan_tasks:
            try:
                result = await task
                combined_result.merge_results(result)
            except Exception as e:
                logger.error(f"Error scanning with {lang} engine: {e}")
        
        return combined_result
    
    def get_supported_languages(self) -> List[str]:
        """Get list of supported languages"""
        return list(self.language_engines.keys())
    
    async def get_all_rule_info(self) -> Dict[str, Dict]:
        """Get rule information for all engines"""
        rule_info = {}
        for lang, engine in self.language_engines.items():
            try:
                rule_info[lang] = await engine.get_rule_info()
            except Exception as e:
                rule_info[lang] = {'error': str(e)}
        return rule_info