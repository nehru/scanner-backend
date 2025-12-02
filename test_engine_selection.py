#!/usr/bin/env python3
"""
Language Engine Selector Service
Integrates File Discovery, Language Detection, and Engine Selection
"""

import os
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

# Import the file discovery service we just created
from test_file_discovery import FileDiscoveryService, DiscoveryResult, DiscoveredFile

# Import your scanner components
from scanner.core.language_config import create_config_manager, AsyncLanguageConfigManager
from scanner.engines.java_engine import create_java_engine, AsyncJavaEngine

logger = logging.getLogger(__name__)

@dataclass
class EngineSelection:
    """Represents a selected language engine with its files"""
    language: str
    engine_type: str
    files_to_scan: List[DiscoveredFile]
    file_count: int
    total_size: int
    estimated_scan_time: float

@dataclass
class ScanPlan:
    """Complete scan plan with selected engines"""
    input_path: str
    discovery_result: DiscoveryResult
    selected_engines: List[EngineSelection]
    total_files_to_scan: int
    supported_languages: List[str]
    unsupported_languages: List[str]
    estimated_total_scan_time: float
    plan_creation_time: float
    timestamp: str

class LanguageEngineSelector:
    """
    Service that selects appropriate language engines based on discovered files
    Third stage of the scanner pipeline
    """
    
    def __init__(self, config_manager: AsyncLanguageConfigManager = None):
        self.config_manager = config_manager
        self.file_discovery = FileDiscoveryService(config_manager)
        
        # Available engines mapping
        self.available_engines = {
            'java': {
                'engine_class': 'AsyncJavaEngine',
                'factory_function': create_java_engine,
                'supported': True,
                'estimated_speed': 100  # files per second
            },
            'python': {
                'engine_class': 'AsyncPythonEngine', 
                'factory_function': None,  # Not implemented yet
                'supported': False,
                'estimated_speed': 120
            },
            'javascript': {
                'engine_class': 'AsyncJavaScriptEngine',
                'factory_function': None,  # Not implemented yet
                'supported': False,
                'estimated_speed': 110
            },
            # Add more engines as they're implemented
        }
        
        # Engine selection criteria
        self.min_files_threshold = 1  # Minimum files to justify engine loading
        self.max_files_per_engine = 10000  # Maximum files per engine instance
        
    async def initialize(self):
        """Initialize the service"""
        if not self.config_manager:
            self.config_manager = await create_config_manager()
        
        await self.file_discovery.initialize()
        
        logger.info("LanguageEngineSelector initialized")
        logger.info(f"Available engines: {list(self.available_engines.keys())}")
        logger.info(f"Supported engines: {[k for k, v in self.available_engines.items() if v['supported']]}")
    
    async def create_scan_plan(self, input_path: str) -> ScanPlan:
        """
        Create a complete scan plan for the given path
        
        Args:
            input_path: Path to file or directory to scan
            
        Returns:
            ScanPlan with selected engines and files
        """
        start_time = asyncio.get_event_loop().time()
        
        logger.info(f"Creating scan plan for: {input_path}")
        
        # Step 1: Discover files and detect languages
        discovery_result = await self.file_discovery.discover_files(input_path)
        
        # Step 2: Select engines based on discovered languages
        selected_engines = await self._select_engines(discovery_result)
        
        # Step 3: Calculate scan estimates
        total_files_to_scan = sum(engine.file_count for engine in selected_engines)
        estimated_total_time = sum(engine.estimated_scan_time for engine in selected_engines)
        
        # Step 4: Identify unsupported languages
        supported_languages = [engine.language for engine in selected_engines]
        unsupported_languages = [
            lang for lang in discovery_result.supported_languages 
            if lang not in supported_languages
        ]
        
        # Calculate planning duration
        end_time = asyncio.get_event_loop().time()
        plan_creation_time = end_time - start_time
        
        # Create scan plan
        scan_plan = ScanPlan(
            input_path=input_path,
            discovery_result=discovery_result,
            selected_engines=selected_engines,
            total_files_to_scan=total_files_to_scan,
            supported_languages=supported_languages,
            unsupported_languages=unsupported_languages,
            estimated_total_scan_time=estimated_total_time,
            plan_creation_time=plan_creation_time,
            timestamp=datetime.now().isoformat()
        )
        
        logger.info(f"Scan plan created in {plan_creation_time:.2f}s:")
        logger.info(f"  - Engines selected: {len(selected_engines)}")
        logger.info(f"  - Files to scan: {total_files_to_scan}")
        logger.info(f"  - Estimated time: {estimated_total_time:.1f}s")
        logger.info(f"  - Supported languages: {supported_languages}")
        if unsupported_languages:
            logger.warning(f"  - Unsupported languages: {unsupported_languages}")
        
        return scan_plan
    
    async def _select_engines(self, discovery_result: DiscoveryResult) -> List[EngineSelection]:
        """Select appropriate engines based on discovered files"""
        selected_engines = []
        
        for language, files in discovery_result.supported_files.items():
            # Check if we have an engine for this language
            if language not in self.available_engines:
                logger.warning(f"No engine configuration found for language: {language}")
                continue
            
            engine_config = self.available_engines[language]
            
            # Check if engine is supported/implemented
            if not engine_config['supported']:
                logger.info(f"Engine for {language} not yet implemented")
                continue
            
            # Check if we have enough files to justify loading this engine
            if len(files) < self.min_files_threshold:
                logger.debug(f"Skipping {language}: only {len(files)} files (below threshold)")
                continue
            
            # Calculate scan estimates
            total_size = sum(f.file_size for f in files)
            estimated_speed = engine_config['estimated_speed']
            estimated_scan_time = len(files) / estimated_speed
            
            # Create engine selection
            engine_selection = EngineSelection(
                language=language,
                engine_type=engine_config['engine_class'],
                files_to_scan=files,
                file_count=len(files),
                total_size=total_size,
                estimated_scan_time=estimated_scan_time
            )
            
            selected_engines.append(engine_selection)
            
            logger.info(f"Selected {language} engine for {len(files)} files ({total_size} bytes)")
        
        return selected_engines
    
    async def create_engines(self, scan_plan: ScanPlan) -> Dict[str, Any]:
        """
        Actually create the selected language engines
        
        Args:
            scan_plan: Scan plan with selected engines
            
        Returns:
            Dictionary mapping language to engine instance
        """
        created_engines = {}
        
        for engine_selection in scan_plan.selected_engines:
            language = engine_selection.language
            
            logger.info(f"Creating {language} engine...")
            
            try:
                if language == 'java':
                    engine = await create_java_engine(self.config_manager)
                    created_engines[language] = engine
                    logger.info(f"Successfully created {language} engine")
                else:
                    logger.warning(f"Engine creation not implemented for {language}")
                    
            except Exception as e:
                logger.error(f"Failed to create {language} engine: {e}")
                continue
        
        logger.info(f"Created {len(created_engines)} engines: {list(created_engines.keys())}")
        return created_engines
    
    def get_available_engines(self) -> Dict[str, Dict]:
        """Get information about available engines"""
        return {
            lang: {
                'engine_class': config['engine_class'],
                'supported': config['supported'],
                'estimated_speed': config['estimated_speed']
            }
            for lang, config in self.available_engines.items()
        }
    
    async def validate_scan_plan(self, scan_plan: ScanPlan) -> Tuple[bool, List[str]]:
        """
        Validate a scan plan before execution
        
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Check if any engines were selected
        if not scan_plan.selected_engines:
            issues.append("No engines selected - no supported languages found")
        
        # Check if all files are accessible
        for engine_selection in scan_plan.selected_engines:
            for file_info in engine_selection.files_to_scan:
                if not os.path.exists(file_info.file_path):
                    issues.append(f"File no longer exists: {file_info.file_path}")
                elif not os.access(file_info.file_path, os.R_OK):
                    issues.append(f"File not readable: {file_info.file_path}")
        
        # Check estimated scan time
        if scan_plan.estimated_total_scan_time > 300:  # 5 minutes
            issues.append(f"Estimated scan time is very long: {scan_plan.estimated_total_scan_time:.1f}s")
        
        # Check total files
        if scan_plan.total_files_to_scan > 10000:
            issues.append(f"Very large number of files to scan: {scan_plan.total_files_to_scan}")
        
        is_valid = len(issues) == 0
        return is_valid, issues

# Integration test function
async def test_engine_selection():
    """Test the complete integration of file discovery and engine selection"""
    
    # Initialize the selector service
    selector = LanguageEngineSelector()
    await selector.initialize()
    
    # Test with your Java files directory
    test_path = r"C:\Users\nehru\app\app-32\java-files"
    
    print("=" * 80)
    print("LANGUAGE ENGINE SELECTOR TEST")
    print("=" * 80)
    print(f"Testing path: {test_path}")
    
    try:
        # Create scan plan
        print("\n1. Creating scan plan...")
        scan_plan = await selector.create_scan_plan(test_path)
        
        # Display scan plan
        print(f"\nSCAN PLAN RESULTS:")
        print(f"  Input path: {scan_plan.input_path}")
        print(f"  Total files discovered: {scan_plan.discovery_result.total_files_found}")
        print(f"  Files to scan: {scan_plan.total_files_to_scan}")
        print(f"  Supported languages: {scan_plan.supported_languages}")
        print(f"  Unsupported languages: {scan_plan.unsupported_languages}")
        print(f"  Estimated scan time: {scan_plan.estimated_total_scan_time:.1f} seconds")
        print(f"  Plan creation time: {scan_plan.plan_creation_time:.2f} seconds")
        
        # Show selected engines
        print(f"\nSELECTED ENGINES ({len(scan_plan.selected_engines)}):")
        for engine in scan_plan.selected_engines:
            print(f"  - {engine.language.upper()} Engine ({engine.engine_type})")
            print(f"    Files: {engine.file_count}")
            print(f"    Size: {engine.total_size:,} bytes")
            print(f"    Estimated time: {engine.estimated_scan_time:.1f}s")
        
        # Validate scan plan
        print(f"\n2. Validating scan plan...")
        is_valid, issues = await selector.validate_scan_plan(scan_plan)
        print(f"  Plan valid: {is_valid}")
        if issues:
            print(f"  Issues found:")
            for issue in issues:
                print(f"    - {issue}")
        
        # Create engines
        print(f"\n3. Creating engines...")
        engines = await selector.create_engines(scan_plan)
        
        print(f"\nCREATED ENGINES ({len(engines)}):")
        for language, engine in engines.items():
            engine_type = type(engine).__name__
            print(f"  - {language}: {engine_type}")
            
            # Test engine functionality
            if hasattr(engine, 'get_supported_extensions'):
                extensions = engine.get_supported_extensions()
                print(f"    Supported extensions: {extensions}")
        
        # Show available vs created engines
        available_engines = selector.get_available_engines()
        print(f"\nENGINE AVAILABILITY:")
        for lang, config in available_engines.items():
            status = "CREATED" if lang in engines else ("AVAILABLE" if config['supported'] else "NOT IMPLEMENTED")
            print(f"  - {lang}: {status} ({config['engine_class']})")
        
        print("\n" + "=" * 80)
        print("ENGINE SELECTION TEST COMPLETED")
        print("=" * 80)
        
        return scan_plan, engines
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None

if __name__ == "__main__":
    # Run the integration test
    import sys
    import logging
    
    # Setup logging
    logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
    
    # Run test
    asyncio.run(test_engine_selection())