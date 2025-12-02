#!/usr/bin/env python3
"""
Integrated Scanner Service - Complete Pipeline
Orchestrates the entire scanning process from path input to vulnerability results
"""

import os
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

# Import all our scanner components
from test_file_discovery import FileDiscoveryService, DiscoveryResult
from test_engine_selection import LanguageEngineSelector, ScanPlan, EngineSelection

# Import scanner core components
from scanner.core.language_config import create_config_manager, AsyncLanguageConfigManager
from scanner.core.rule_loader import get_async_rule_loader
from scanner.core.base_classes import ScanResult, Vulnerability
from scanner.engines.java_engine import create_java_engine

logger = logging.getLogger(__name__)

@dataclass
class ScanRequest:
    """Request object for scanning"""
    input_path: str
    scan_id: str
    languages: Optional[List[str]] = None  # None = auto-detect all
    options: Dict[str, Any] = None

@dataclass
class ScanResponse:
    """Complete scan response with all results"""
    scan_id: str
    request: ScanRequest
    discovery_result: DiscoveryResult
    scan_plan: ScanPlan
    scan_results: Dict[str, ScanResult]  # language -> ScanResult
    total_vulnerabilities: int
    total_files_scanned: int
    total_scan_duration: float
    pipeline_stages: Dict[str, float]  # stage -> duration
    timestamp: str
    status: str  # 'completed', 'failed', 'partial'
    errors: List[str]

class IntegratedScannerService:
    """
    Complete scanner service that orchestrates the entire pipeline
    """
    
    def __init__(self):
        self.config_manager: Optional[AsyncLanguageConfigManager] = None
        self.file_discovery: Optional[FileDiscoveryService] = None
        self.engine_selector: Optional[LanguageEngineSelector] = None
        self.rule_loader = None
        
        # Pipeline stage timings
        self._stage_timings = {}
        
    async def initialize(self):
        """Initialize all scanner components"""
        start_time = asyncio.get_event_loop().time()
        
        logger.info("Initializing Integrated Scanner Service...")
        
        # Initialize configuration manager
        self.config_manager = await create_config_manager()
        
        # Initialize rule loader
        self.rule_loader = get_async_rule_loader()
        
        # Configure rule loader with base paths
        base_config = {
            'semgrep_rules_base': 'semgrep-rules',
            'custom_security_rules_base': 'custom-security-rules',
            'solution_rules_base': 'solution-rules'
        }
        
        # Configure for all languages (we'll focus on Java for this test)
        language_configs = {
            'java': {
                'semgrep_rule_paths': ['java/security'],
                'custom_rules_filename': 'java-rules.yml',
                'solutions_filename': 'java-solutions.yml',
                'enabled': True
            }
        }
        
        await self.rule_loader.configure(base_config, language_configs)
        
        # Initialize file discovery service
        self.file_discovery = FileDiscoveryService(self.config_manager)
        await self.file_discovery.initialize()
        
        # Initialize engine selector
        self.engine_selector = LanguageEngineSelector(self.config_manager)
        await self.engine_selector.initialize()
        
        init_time = asyncio.get_event_loop().time() - start_time
        logger.info(f"Scanner service initialized in {init_time:.2f}s")
    
    async def scan(self, scan_request: ScanRequest) -> ScanResponse:
        """
        Execute complete scan pipeline
        
        Args:
            scan_request: Scan request with path and options
            
        Returns:
            Complete scan response with all results
        """
        pipeline_start = asyncio.get_event_loop().time()
        stage_timings = {}
        errors = []
        
        logger.info(f"Starting scan for: {scan_request.input_path}")
        logger.info(f"Scan ID: {scan_request.scan_id}")
        
        try:
            # Stage 1: File Discovery and Language Detection
            stage_start = asyncio.get_event_loop().time()
            logger.info("Stage 1: File Discovery and Language Detection")
            
            discovery_result = await self.file_discovery.discover_files(scan_request.input_path)
            
            stage_timings['file_discovery'] = asyncio.get_event_loop().time() - stage_start
            logger.info(f"File discovery completed in {stage_timings['file_discovery']:.2f}s")
            logger.info(f"Found {discovery_result.total_files_found} files, {len(discovery_result.supported_languages)} languages")
            
            # Stage 2: Engine Selection
            stage_start = asyncio.get_event_loop().time()
            logger.info("Stage 2: Language Engine Selection")
            
            scan_plan = await self.engine_selector.create_scan_plan(scan_request.input_path)
            
            stage_timings['engine_selection'] = asyncio.get_event_loop().time() - stage_start
            logger.info(f"Engine selection completed in {stage_timings['engine_selection']:.2f}s")
            logger.info(f"Selected {len(scan_plan.selected_engines)} engines for {scan_plan.total_files_to_scan} files")
            
            # Stage 3: Engine Creation and Rule Loading
            stage_start = asyncio.get_event_loop().time()
            logger.info("Stage 3: Engine Creation and Rule Loading")
            
            engines = await self.engine_selector.create_engines(scan_plan)
            
            # Load rules for each created engine
            for language, engine in engines.items():
                logger.info(f"Loading rules for {language} engine...")
                # Rules are loaded automatically when engine is used
                await self._ensure_engine_rules_loaded(language, engine)
            
            stage_timings['engine_creation'] = asyncio.get_event_loop().time() - stage_start
            logger.info(f"Engine creation and rule loading completed in {stage_timings['engine_creation']:.2f}s")
            
            # Stage 4: Execute Scans
            stage_start = asyncio.get_event_loop().time()
            logger.info("Stage 4: Execute Security Scans")
            
            scan_results = await self._execute_scans(engines, scan_plan)
            
            stage_timings['scan_execution'] = asyncio.get_event_loop().time() - stage_start
            logger.info(f"Scan execution completed in {stage_timings['scan_execution']:.2f}s")
            
            # Calculate totals
            total_vulnerabilities = sum(result.total_vulnerabilities for result in scan_results.values())
            total_files_scanned = sum(result.total_files for result in scan_results.values())
            
            total_duration = asyncio.get_event_loop().time() - pipeline_start
            
            # Create response
            response = ScanResponse(
                scan_id=scan_request.scan_id,
                request=scan_request,
                discovery_result=discovery_result,
                scan_plan=scan_plan,
                scan_results=scan_results,
                total_vulnerabilities=total_vulnerabilities,
                total_files_scanned=total_files_scanned,
                total_scan_duration=total_duration,
                pipeline_stages=stage_timings,
                timestamp=datetime.now().isoformat(),
                status='completed',
                errors=errors
            )
            
            logger.info(f"Scan completed successfully in {total_duration:.2f}s")
            logger.info(f"Total vulnerabilities found: {total_vulnerabilities}")
            
            return response
            
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            errors.append(str(e))
            
            # Return partial response
            return ScanResponse(
                scan_id=scan_request.scan_id,
                request=scan_request,
                discovery_result=discovery_result if 'discovery_result' in locals() else None,
                scan_plan=scan_plan if 'scan_plan' in locals() else None,
                scan_results={},
                total_vulnerabilities=0,
                total_files_scanned=0,
                total_scan_duration=asyncio.get_event_loop().time() - pipeline_start,
                pipeline_stages=stage_timings,
                timestamp=datetime.now().isoformat(),
                status='failed',
                errors=errors
            )
    
    async def _ensure_engine_rules_loaded(self, language: str, engine) -> None:
        """Ensure rules are loaded for an engine"""
        try:
            if hasattr(engine, '_ensure_rules_loaded'):
                await engine._ensure_rules_loaded()
                logger.info(f"Rules loaded for {language} engine")
            elif hasattr(engine, 'get_rule_info'):
                rule_info = await engine.get_rule_info()
                logger.info(f"{language} engine has {rule_info.get('total_rules', 0)} rules")
        except Exception as e:
            logger.error(f"Failed to load rules for {language}: {e}")
    
    async def _execute_scans(self, engines: Dict[str, Any], scan_plan: ScanPlan) -> Dict[str, ScanResult]:
        """Execute scans with all selected engines"""
        scan_results = {}
        
        # Create mapping of engine selections for easier access
        engine_selections = {sel.language: sel for sel in scan_plan.selected_engines}
        
        # Execute scans concurrently for all engines
        scan_tasks = []
        for language, engine in engines.items():
            if language in engine_selections:
                engine_selection = engine_selections[language]
                file_paths = [f.file_path for f in engine_selection.files_to_scan]
                
                logger.info(f"Starting {language} scan of {len(file_paths)} files")
                task = self._execute_single_engine_scan(language, engine, file_paths)
                scan_tasks.append((language, task))
        
        # Wait for all scans to complete
        for language, task in scan_tasks:
            try:
                result = await task
                scan_results[language] = result
                logger.info(f"{language} scan completed: {result.total_vulnerabilities} vulnerabilities")
            except Exception as e:
                logger.error(f"{language} scan failed: {e}")
                # Create empty result for failed scan
                scan_results[language] = ScanResult(
                    scan_id=scan_plan.discovery_result.timestamp,
                    language=language,
                    scan_status='failed',
                    error_message=str(e)
                )
        
        return scan_results
    
    async def _execute_single_engine_scan(self, language: str, engine, file_paths: List[str]) -> ScanResult:
        """Execute scan with a single engine"""
        logger.info(f"Executing {language} scan on {len(file_paths)} files")
        
        # Execute the scan
        if hasattr(engine, 'scan_files'):
            result = await engine.scan_files(file_paths)
        elif hasattr(engine, 'scan_directory'):
            # If we only have directory scan, use the parent directory
            parent_dir = os.path.dirname(file_paths[0]) if file_paths else ""
            result = await engine.scan_directory(parent_dir)
        else:
            raise NotImplementedError(f"Engine {language} does not implement scan_files or scan_directory")
        
        return result
    
    def export_results_json(self, response: ScanResponse, output_file: str) -> None:
        """Export scan results to JSON file"""
        try:
            # Convert to dictionary for JSON serialization
            response_dict = asdict(response)
            
            # Convert ScanResult objects to dictionaries
            if response.scan_results:
                response_dict['scan_results'] = {
                    lang: result.to_dict() if hasattr(result, 'to_dict') else asdict(result)
                    for lang, result in response.scan_results.items()
                }
            
            # Write to file
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(response_dict, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Results exported to: {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to export results: {e}")

# Complete integration test
async def test_integrated_scanner():
    """Test the complete integrated scanner pipeline"""
    
    # Initialize scanner service
    scanner = IntegratedScannerService()
    await scanner.initialize()
    
    # Create scan request
    scan_request = ScanRequest(
        input_path=r"C:\Users\nehru\app\app-32\java-files",
        scan_id="test_scan_001",
        languages=None,  # Auto-detect all
        options={}
    )
    
    print("=" * 100)
    print("INTEGRATED SCANNER PIPELINE TEST")
    print("=" * 100)
    print(f"Scanning: {scan_request.input_path}")
    print(f"Scan ID: {scan_request.scan_id}")
    
    try:
        # Execute complete scan
        response = await scanner.scan(scan_request)
        
        # Display results
        print(f"\nSCAN PIPELINE RESULTS:")
        print(f"Status: {response.status}")
        print(f"Total duration: {response.total_scan_duration:.2f} seconds")
        print(f"Total files scanned: {response.total_files_scanned}")
        print(f"Total vulnerabilities: {response.total_vulnerabilities}")
        
        # Show pipeline stage timings
        print(f"\nPIPELINE STAGE TIMINGS:")
        for stage, duration in response.pipeline_stages.items():
            percentage = (duration / response.total_scan_duration) * 100
            print(f"  {stage}: {duration:.2f}s ({percentage:.1f}%)")
        
        # Show discovery results
        if response.discovery_result:
            print(f"\nFILE DISCOVERY:")
            print(f"  Total files found: {response.discovery_result.total_files_found}")
            print(f"  Supported languages: {response.discovery_result.supported_languages}")
            print(f"  Discovery time: {response.discovery_result.discovery_duration:.2f}s")
        
        # Show engine selection
        if response.scan_plan:
            print(f"\nENGINE SELECTION:")
            for engine in response.scan_plan.selected_engines:
                print(f"  {engine.language}: {engine.file_count} files ({engine.engine_type})")
        
        # Show scan results by language
        print(f"\nSCAN RESULTS BY LANGUAGE:")
        for language, result in response.scan_results.items():
            print(f"  {language.upper()}:")
            print(f"    Files scanned: {result.total_files}")
            print(f"    Vulnerabilities: {result.total_vulnerabilities}")
            print(f"    Scan duration: {result.scan_duration:.2f}s")
            print(f"    Status: {result.scan_status}")
            
            if result.total_vulnerabilities > 0:
                print(f"    Sample vulnerabilities:")
                for i, vuln in enumerate(result.vulnerabilities[:3], 1):
                    print(f"      {i}. {vuln.rule_id} - {vuln.message[:60]}...")
        
        # Show any errors
        if response.errors:
            print(f"\nERRORS:")
            for error in response.errors:
                print(f"  - {error}")
        
        # Export results
        output_file = f"integrated_scan_results_{scan_request.scan_id}.json"
        scanner.export_results_json(response, output_file)
        
        print(f"\n" + "=" * 100)
        print("INTEGRATED SCANNER TEST COMPLETED")
        print("=" * 100)
        print(f"Results exported to: {output_file}")
        
        return response
        
    except Exception as e:
        print(f"Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    # Run the complete integration test
    import sys
    import logging
    
    # Setup detailed logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run test
    asyncio.run(test_integrated_scanner())