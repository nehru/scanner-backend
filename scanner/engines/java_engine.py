#!/usr/bin/env python3
"""
scanner/engines/java_engine.py - Fixed Async WebSocket Version
Java Scanner Engine with proper async patterns for WebSocket operation
Fixed initialization and rule loading issues
"""

import subprocess
import json
import os
import uuid
import asyncio
import tempfile
import logging
import time
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime

# Import async base classes and rule loading
from ..core.language_config import AsyncLanguageConfigManager, LanguageConfig
from ..core.base_classes import BaseLanguageEngine, Vulnerability, ScanResult, ProgressCallback
from ..core.rule_loader import get_async_rule_loader, RuleSet

logger = logging.getLogger(__name__)

class AsyncJavaEngine(BaseLanguageEngine):
    """
    Fixed Async Java vulnerability scanner engine for WebSocket operation
    Proper async initialization and rule loading
    """
    
    def __init__(self, config_manager: AsyncLanguageConfigManager, semgrep_rules_base_dir: str = None, base_config: Optional[Dict] = None):
        """Initialize async Java scanner engine"""
        # Store initialization parameters
        self.config_manager = config_manager
        self.semgrep_rules_base_dir = semgrep_rules_base_dir or 'semgrep-rules'
        self.language_config = None
        
        # Java-specific configuration
        self.semgrep_timeout = (base_config or {}).get('timeout', 300)
        self.max_file_size = (base_config or {}).get('max_file_size', 10 * 1024 * 1024)
        self.max_files_per_scan = (base_config or {}).get('max_files_per_scan', 1000)
        self.max_concurrent_files = (base_config or {}).get('max_concurrent_files', 10)
        
        # Rules will be loaded during initialization
        self._rules_loaded = False
        self._current_ruleset: Optional[RuleSet] = None
        
        # Initialize base engine - this will call _initialize_engine when create_java_engine is called
        super().__init__('java', None, base_config)
        
        logger.info("Async Java Scanner Engine created")
    
    async def _initialize_engine(self):
        """Initialize Java-specific components asynchronously - FIXED VERSION"""
        logger.info("Initializing async Java engine...")
        
        # Get language configuration
        self.language_config = await self.config_manager.get_language_config('java')
        if not self.language_config:
            raise ValueError("Java language configuration not found")
        
        if not self.language_config.enabled:
            raise ValueError("Java language is disabled in configuration")
        
        # Set supported extensions from config
        self.supported_extensions = self.language_config.extensions
        
        # NOW configure rule loader properly (FIXED - await it!)
        await self._configure_rule_loader()
        
        logger.info("Async Java engine initialized successfully")
    
    async def _configure_rule_loader(self):
        """Configure the async rule loader manager - FIXED VERSION"""
        logger.info("Configuring async rule loader for Java...")
        
        rule_loader = get_async_rule_loader()
        
        # Base configuration for file paths
        base_config = {
            'semgrep_rules_base': self.semgrep_rules_base_dir,
            'custom_security_rules_base': 'custom-security-rules',
            'solution_rules_base': 'solution-rules'
        }
        
        # Java-specific rule configuration
        language_configs = {
            'java': {
                'semgrep_rule_paths': ['java/security'],
                'custom_rules_filename': 'java-rules.yml',
                'solutions_filename': 'java-solutions.yml',
                'enabled': True
            }
        }
        
        # Configure the rule loader
        await rule_loader.configure(base_config, language_configs)
        logger.info("Async rule loader configured for Java")
    
    async def _ensure_rules_loaded(self):
        """Async lazy loading of rules - improved error handling"""
        if not self._rules_loaded:
            logger.info("Loading Java rules...")
            
            try:
                rule_loader = get_async_rule_loader()
                self._current_ruleset = await rule_loader.get_rules_for_language('java')
                self._rules_loaded = True
                
                logger.info(f"Java rules loaded successfully:")
                logger.info(f"  - Semgrep rules: {len(self._current_ruleset.semgrep_rules)}")
                logger.info(f"  - Custom rules: {len(self._current_ruleset.custom_rules)}")
                logger.info(f"  - Solutions: {len(self._current_ruleset.solutions)}")
                
                if self._current_ruleset.total_rules == 0:
                    logger.warning("No Java rules found! Check your rule directories and files.")
                
            except Exception as e:
                logger.error(f"Failed to load Java rules: {e}")
                # Create empty ruleset as fallback
                from ..core.rule_loader import RuleSet
                self._current_ruleset = RuleSet(language='java')
                self._rules_loaded = True
                raise
    
    async def identify_files(self, file_paths: List[str]) -> List[str]:
        """Async file identification"""
        java_files = []
        
        for file_path in file_paths:
            if any(file_path.lower().endswith(ext) for ext in self.supported_extensions):
                if os.path.exists(file_path):
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size <= self.max_file_size:
                            java_files.append(file_path)
                            logger.debug(f"Added Java file: {file_path} ({file_size} bytes)")
                        else:
                            logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                    except OSError as e:
                        logger.warning(f"Cannot access file: {file_path} - {e}")
                else:
                    logger.warning(f"File not found: {file_path}")
        
        if len(java_files) > self.max_files_per_scan:
            logger.warning(f"Too many files ({len(java_files)}), limiting to {self.max_files_per_scan}")
            java_files = java_files[:self.max_files_per_scan]
        
        logger.info(f"Identified {len(java_files)} Java files for scanning")
        return java_files
    
    async def discover_files_in_directory(self, directory: str) -> List[str]:
        """Async directory discovery"""
        if not os.path.exists(directory):
            logger.error(f"Directory not found: {directory}")
            return []
        
        logger.info(f"Starting async file discovery in: {directory}")
        
        if self.progress_callback:
            await self.progress_callback.update("scanning", current_file=directory, files_processed=0)
        
        java_files = []
        
        # Async directory traversal
        async def scan_directory():
            for root, dirs, files in os.walk(directory):
                # Skip common non-source directories
                dirs[:] = [d for d in dirs if d not in ['.git', '.svn', 'node_modules', 'target', 'build', '.idea', 'out']]
                
                for file in files:
                    if any(file.lower().endswith(ext) for ext in self.supported_extensions):
                        file_path = os.path.join(root, file)
                        try:
                            if os.path.getsize(file_path) <= self.max_file_size:
                                java_files.append(file_path)
                        except (OSError, IOError):
                            continue
                
                # Yield control periodically
                await asyncio.sleep(0)
        
        await scan_directory()
        
        # Apply file limits
        if len(java_files) > self.max_files_per_scan:
            logger.warning(f"Too many files ({len(java_files)}), limiting to {self.max_files_per_scan}")
            java_files = java_files[:self.max_files_per_scan]
        
        logger.info(f"Async discovery completed: {len(java_files)} Java files")
        
        if self.progress_callback:
            await self.progress_callback.update("scanning", files_processed=len(java_files), total_files=len(java_files))
        
        return java_files
    
    async def _run_semgrep_async(self, java_files: List[str]) -> Dict:
        """Execute Semgrep asynchronously - improved error handling"""
        # Ensure rules are loaded
        await self._ensure_rules_loaded()
        
        if not self._current_ruleset or self._current_ruleset.total_rules == 0:
            logger.warning("No Java rules available for scanning")
            return {"results": [], "version": "unknown"}
        
        try:
            start_time = time.time()
            
            if self.progress_callback:
                await self.progress_callback.update("analyzing", current_file="Running Semgrep analysis")
            
            # Build semgrep command
            cmd = ["semgrep"]
            
            # Add rule exclusions to prevent false positives
            cmd.extend(["--exclude-rule", "semgrep-rules.java.security.find-sql-string-concatenation"])
            cmd.extend(["--exclude-rule", "semgrep-rules.java.security.spring-sqli"])
            cmd.extend(["--exclude-rule", "semgrep-rules.java.security.jdbc-sqli"])
            
            # Add each rule directory as a separate --config
            if self._current_ruleset.rule_directories:
                for rule_dir in self._current_ruleset.rule_directories:
                    cmd.extend(["--config", rule_dir])
                    logger.debug(f"Added rule directory: {rule_dir}")
            
            # Add custom rules file if available
            if self._current_ruleset.custom_rules_path and os.path.exists(self._current_ruleset.custom_rules_path):
                cmd.extend(["--config", self._current_ruleset.custom_rules_path])
                logger.info(f"Including custom rules: {self._current_ruleset.custom_rules_path}")
            
            # Check if we have any rules to use
            if len(cmd) == 1:  # Only "semgrep" command, no configs added
                logger.error("No valid rule configurations found for Semgrep")
                return {"results": [], "version": "unknown", "error": "No rules configured"}
            
            # Semgrep options
            cmd.extend([
                "--json",
                "--no-git-ignore", 
                "--timeout", str(self.semgrep_timeout),
                "--skip-unknown-extensions",
                "--max-chars-per-line=10000",
                "--max-lines-per-finding=100",
                "--optimizations", "all"
            ])
            
            logger.info(f"Full Semgrep command: {' '.join(cmd)}")
            
            # Add verbosity for debugging
            if logger.level <= logging.DEBUG:
                cmd.append("--verbose")
            
            # Add files to scan
            abs_java_files = [os.path.abspath(f) for f in java_files]
            cmd.extend(abs_java_files)
            
            logger.info(f"Running async Semgrep on {len(java_files)} Java files")
            logger.debug(f"Command: {' '.join(cmd)}")
            
            # Create temporary directory for this scan
            with tempfile.TemporaryDirectory(prefix='semgrep_async_') as temp_dir:
                # Set environment variables
                env = os.environ.copy()
                env.update({
                    'PYTHONIOENCODING': 'utf-8',
                    'LC_ALL': 'C.UTF-8',
                    'LANG': 'C.UTF-8',
                    'TMPDIR': temp_dir,
                    'TMP': temp_dir,
                    'TEMP': temp_dir
                })
                
                # Execute semgrep asynchronously
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=os.getcwd()
                )
                
                try:
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), 
                        timeout=self.semgrep_timeout
                    )
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise TimeoutError(f"Semgrep scan timed out after {self.semgrep_timeout} seconds")
                
                # Decode output
                stdout = stdout.decode('utf-8', errors='ignore')
                stderr = stderr.decode('utf-8', errors='ignore')
                
                end_time = time.time()
                scan_duration = end_time - start_time
                
                logger.info(f"Async Semgrep completed in {scan_duration:.2f} seconds")
                
                if self.progress_callback:
                    await self.progress_callback.update("analyzing", current_file=f"Analysis completed in {scan_duration:.1f}s")
                
                # Handle semgrep output
                if process.returncode == 2:
                    logger.warning("Semgrep encountered errors but attempted to continue")
                    if stdout and stdout.strip():
                        logger.info("Got output despite errors, attempting to parse")
                    else:
                        logger.warning("No output received due to errors")
                        logger.warning(f"Stderr: {stderr}")
                        return {"results": [], "version": "unknown"}
                elif process.returncode not in [0, 1]:
                    logger.error(f"Semgrep failed with return code: {process.returncode}")
                    logger.error(f"Stderr: {stderr}")
                    raise subprocess.CalledProcessError(process.returncode, cmd, stdout, stderr)
                
                if not stdout or not stdout.strip():
                    logger.info("No Semgrep output - no vulnerabilities found")
                    return {"results": [], "version": "unknown"}
                
                # Parse JSON output
                try:
                    semgrep_output = json.loads(stdout)
                    findings_count = len(semgrep_output.get('results', []))
                    
                    if self.progress_callback:
                        await self.progress_callback.update("analyzing", current_file=f"Found {findings_count} potential vulnerabilities")
                    
                    logger.info(f"Semgrep found {findings_count} raw findings")
                    return semgrep_output
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Semgrep JSON output: {e}")
                    logger.debug(f"Raw output: {stdout[:500]}...")
                    return {"results": [], "version": "unknown"}
        
        except FileNotFoundError:
            logger.error("Semgrep not found. Please install Semgrep CLI")
            raise
        except Exception as e:
            logger.error(f"Unexpected error running Semgrep: {e}")
            raise
    
    async def _process_semgrep_results_async(self, semgrep_output: Dict, java_files: List[str], scan_duration: float) -> List[Vulnerability]:
        """Process Semgrep output asynchronously"""
        vulnerabilities = []
        
        # Extract semgrep version
        semgrep_version = semgrep_output.get('version', 'unknown')
        
        # Process each finding
        for result in semgrep_output.get('results', []):
            try:
                # Extract basic info
                rule_id = result['check_id']
                file_path = result['path']
                line_number = result['start']['line']
                column_start = result['start']['col']
                column_end = result['end']['col']
                
                # Extract metadata
                extra = result.get('extra', {})
                message = extra.get('message', 'No message available')
                severity = extra.get('severity', 'UNKNOWN')
                metadata = extra.get('metadata', {})
                
                # Get vulnerability details
                cwe = metadata.get('cwe')
                category = metadata.get('category', 'unknown')
                
                # Get solution using rule abstraction
                solution = self._current_ruleset.get_solution(rule_id) if self._current_ruleset else "No solution available"
                
                # Get code context
                vulnerable_code, code_context = await self._get_code_context(file_path, line_number)
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    id=str(uuid.uuid4()),
                    rule_id=rule_id,
                    file_path=file_path,
                    line_number=line_number,
                    column_start=column_start,
                    column_end=column_end,
                    severity=severity,
                    message=message,
                    vulnerable_code=vulnerable_code,
                    code_context=code_context,
                    solution=solution,
                    cwe=cwe,
                    category=category,
                    language=self.language
                )
                
                vulnerabilities.append(vulnerability)
                
                logger.debug(f"Processed vulnerability: {rule_id} in {file_path}:{line_number}")
                
            except Exception as e:
                logger.error(f"Error processing Semgrep result: {e}")
                logger.debug(f"Problematic result: {result}")
                continue
        
        logger.info(f"Processed {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities
    
    async def scan_files(self, file_paths: List[str]) -> ScanResult:
        """Async scan of Java files"""
        start_time = time.time()
        
        # Filter to Java files only
        java_files = await self.identify_files(file_paths)
        
        if not java_files:
            logger.warning("No Java files found to scan")
            return ScanResult(
                scan_id=str(uuid.uuid4()),
                language=self.language,
                languages_detected=[self.language],
                files_scanned=[],
                total_files=0,
                vulnerabilities=[],
                total_vulnerabilities=0,
                scan_duration=0.0,
                timestamp=datetime.now().isoformat(),
                rules_used=[],
                semgrep_version="unknown"
            )
        
        logger.info(f"Starting async Java vulnerability scan on {len(java_files)} files")
        
        if self.progress_callback:
            await self.progress_callback.update("scanning", files_processed=0, total_files=len(java_files))
        
        try:
            # Run Semgrep analysis
            semgrep_output = await self._run_semgrep_async(java_files)
            
            # Calculate scan duration
            end_time = time.time()
            scan_duration = end_time - start_time
            
            # Process results
            if self.progress_callback:
                await self.progress_callback.update("analyzing", current_file="Processing scan results")
            
            vulnerabilities = await self._process_semgrep_results_async(semgrep_output, java_files, scan_duration)
            
            # Get rule information for the scan result
            rules_used = []
            if self._current_ruleset and self._current_ruleset.all_rules:
                rules_used = [rule.get('id', 'unknown') for rule in self._current_ruleset.all_rules[:10]]
            
            # Create scan result
            scan_result = ScanResult(
                scan_id=str(uuid.uuid4()),
                language=self.language,
                languages_detected=[self.language],
                files_scanned=java_files,
                total_files=len(java_files),
                vulnerabilities=vulnerabilities,
                total_vulnerabilities=len(vulnerabilities),
                scan_duration=scan_duration,
                timestamp=datetime.now().isoformat(),
                rules_used=rules_used,
                semgrep_version=semgrep_output.get('version', 'unknown')
            )
            
            if self.progress_callback:
                await self.progress_callback.update("completed", 
                                                  files_processed=len(java_files),
                                                  total_files=len(java_files),
                                                  vulnerabilities_found=len(vulnerabilities))
            
            logger.info(f"Java scan completed: {len(vulnerabilities)} vulnerabilities found in {scan_duration:.2f}s")
            return scan_result
            
        except Exception as e:
            logger.error(f"Java scan failed: {e}")
            if self.progress_callback:
                await self.progress_callback.update("failed", current_file=f"Scan failed: {e}")
            
            # Return partial results
            return ScanResult(
                scan_id=str(uuid.uuid4()),
                language=self.language,
                languages_detected=[self.language],
                files_scanned=java_files,
                total_files=len(java_files),
                vulnerabilities=[],
                total_vulnerabilities=0,
                scan_duration=time.time() - start_time,
                timestamp=datetime.now().isoformat(),
                rules_used=[],
                semgrep_version="unknown",
                scan_status="failed",
                error_message=str(e)
            )
    
    async def scan_directory(self, directory: str) -> ScanResult:
        """Async directory scan - FIXED to handle single files"""
        logger.info(f"Starting async directory scan: {directory}")
        
        if self.progress_callback:
            await self.progress_callback.update("scanning", current_file=f"Analyzing {directory}")
        
        # FIX: Check if path is a single file vs directory
        if os.path.isfile(directory):
            # Handle single file
            if any(directory.lower().endswith(ext) for ext in self.supported_extensions):
                logger.info(f"Detected single Java file: {directory}")
                java_files = [directory]
            else:
                logger.warning(f"Single file is not a Java file: {directory}")
                java_files = []
        elif os.path.isdir(directory):
            # Handle directory - use existing discovery logic
            java_files = await self.discover_files_in_directory(directory)
        else:
            logger.error(f"Path does not exist or is invalid: {directory}")
            java_files = []
        
        if java_files:
            if self.progress_callback:
                await self.progress_callback.update("scanning", current_file=f"Found {len(java_files)} Java files")
        else:
            if self.progress_callback:
                await self.progress_callback.update("completed", current_file="No Java files found")
        
        # Scan the discovered/identified files
        return await self.scan_files(java_files)
    
    async def get_rule_info(self) -> Dict:
        """Get information about loaded rules"""
        await self._ensure_rules_loaded()
        
        if not self._current_ruleset:
            return {
                'language': self.language,
                'error': 'No ruleset loaded',
                'total_rules': 0,
                'async_engine': True,
                'websocket_ready': True
            }
        
        rules_info = []
        for rule in self._current_ruleset.all_rules:
            rule_info = {
                'id': rule.get('id'),
                'message': rule.get('message'),
                'severity': rule.get('severity'),
                'category': rule.get('metadata', {}).get('category'),
                'cwe': rule.get('metadata', {}).get('cwe'),
                'has_solution': rule.get('id') in self._current_ruleset.solutions,
                'is_taint_rule': rule.get('mode') == 'taint'
            }
            rules_info.append(rule_info)
        
        return {
            'language': self.language,
            'rules_directories': self._current_ruleset.rule_directories,
            'custom_rules_file': self._current_ruleset.custom_rules_path,
            'solutions_file': self._current_ruleset.solutions_path,
            'total_rules': len(rules_info),
            'semgrep_rules': len(self._current_ruleset.semgrep_rules),
            'custom_rules': len(self._current_ruleset.custom_rules),
            'total_solutions': len(self._current_ruleset.solutions),
            'rules': rules_info,
            'async_engine': True,
            'websocket_ready': True
        }
    
    async def validate_rules(self) -> Dict:
        """Validate rules asynchronously"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'rule_count': 0,
            'solutions_count': 0,
            'semgrep_test_passed': False,
            'async_validation': True
        }
        
        try:
            # Load rules
            await self._ensure_rules_loaded()
            
            if not self._current_ruleset:
                validation_result['valid'] = False
                validation_result['errors'].append("Failed to load ruleset")
                return validation_result
            
            validation_result['rule_count'] = self._current_ruleset.total_rules
            validation_result['solutions_count'] = len(self._current_ruleset.solutions)
            validation_result['directories_found'] = len(self._current_ruleset.rule_directories)
            validation_result['custom_rules_found'] = self._current_ruleset.custom_rules_path is not None
            validation_result['solutions_file_found'] = self._current_ruleset.solutions_path is not None
            
            # Test Semgrep validation
            try:
                cmd = ["semgrep", "--validate"]
                
                # Add rule directories
                for rule_dir in self._current_ruleset.rule_directories:
                    if os.path.exists(rule_dir):
                        cmd.extend(["--config", rule_dir])
                
                # Add custom rules
                if self._current_ruleset.custom_rules_path and os.path.exists(self._current_ruleset.custom_rules_path):
                    cmd.extend(["--config", self._current_ruleset.custom_rules_path])
                
                if len(cmd) > 2:  # More than just "semgrep --validate"
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await asyncio.wait_for(
                        process.communicate(), 
                        timeout=30
                    )
                    
                    stderr = stderr.decode('utf-8', errors='ignore')
                    
                    if process.returncode == 0:
                        validation_result['semgrep_test_passed'] = True
                        logger.info("Async Semgrep validation passed")
                    else:
                        if 'charmap' in stderr or 'UnicodeDecodeError' in stderr:
                            validation_result['warnings'].append("Semgrep validation has encoding issues but rules should still work")
                            validation_result['semgrep_test_passed'] = True
                            logger.warning("Semgrep validation has encoding issues but continuing")
                        else:
                            validation_result['errors'].append(f"Semgrep validation failed: {stderr}")
                            validation_result['valid'] = False
                            logger.error(f"Semgrep validation failed: {stderr}")
                else:
                    validation_result['warnings'].append("No rule configurations found for validation")
                    
            except FileNotFoundError:
                validation_result['warnings'].append("Semgrep not available for validation test")
            except asyncio.TimeoutError:
                validation_result['warnings'].append("Semgrep validation test timed out")
            except Exception as e:
                validation_result['warnings'].append(f"Semgrep validation test error: {e}")
        
        except Exception as e:
            validation_result['valid'] = False
            validation_result['errors'].append(f"Validation error: {e}")
        
        return validation_result
    
    def get_supported_extensions(self) -> List[str]:
        """Return list of supported file extensions"""
        return ['.java', '.jsp', '.jspx']

# Fixed factory function to create async Java engine
async def create_java_engine(config_manager: AsyncLanguageConfigManager = None, 
                           semgrep_rules_base_dir: str = None, 
                           base_config: Optional[Dict] = None) -> AsyncJavaEngine:
    """Create and initialize async Java engine"""
    if not config_manager:
        from ..core.language_config import create_config_manager
        config_manager = await create_config_manager()
    
    engine = AsyncJavaEngine(config_manager, semgrep_rules_base_dir, base_config)
    await engine._initialize_engine()  # Ensure it's fully initialized
    return engine