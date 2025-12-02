#!/usr/bin/env python3
"""
Complete Scanner Pipeline Test
Tests the entire flow from file path input to JSON response output
"""

import os
import asyncio
import json
import logging
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime

# Import all scanner components
from test_file_discovery import FileDiscoveryService
from test_engine_selection import LanguageEngineSelector
from scanner.core.language_config import create_config_manager
from scanner.core.rule_loader import get_async_rule_loader
from scanner.core.base_classes import ScanResult, Vulnerability
from scanner.engines.java_engine import create_java_engine

logger = logging.getLogger(__name__)

class CompleteScannerPipeline:
    """Complete scanner pipeline from file path to JSON response"""
    
    def __init__(self):
        self.config_manager = None
        self.file_discovery = None
        self.engine_selector = None
        self.rule_loader = None
        
    async def initialize(self):
        """Initialize all pipeline components"""
        logger.info("=== INITIALIZING SCANNER PIPELINE ===")
        
        # 1. Initialize Language Config Manager
        logger.info("1. Initializing AsyncLanguageConfigManager...")
        self.config_manager = await create_config_manager()
        logger.info("   ✓ Language config manager ready")
        
        # 2. Initialize Rule Loader
        logger.info("2. Initializing AsyncRuleLoader...")
        self.rule_loader = get_async_rule_loader()
        
        base_config = {
            'semgrep_rules_base': 'semgrep-rules',
            'custom_security_rules_base': 'custom-security-rules',
            'solution_rules_base': 'solution-rules'
        }
        
        language_configs = {
            'java': {
                'semgrep_rule_paths': ['java/security'],
                'custom_rules_filename': 'java-rules.yml',
                'solutions_filename': 'java-solutions.yml',
                'enabled': True
            }
        }
        
        await self.rule_loader.configure(base_config, language_configs)
        logger.info("   ✓ Rule loader configured")
        
        # 3. Initialize File Discovery Service
        logger.info("3. Initializing FileDiscoveryService...")
        self.file_discovery = FileDiscoveryService(self.config_manager)
        await self.file_discovery.initialize()
        logger.info("   ✓ File discovery service ready")
        
        # 4. Initialize Engine Selector
        logger.info("4. Initializing LanguageEngineSelector...")
        self.engine_selector = LanguageEngineSelector(self.config_manager)
        await self.engine_selector.initialize()
        logger.info("   ✓ Engine selector ready")
        
        logger.info("=== PIPELINE INITIALIZATION COMPLETE ===\n")
    
    async def scan_path_to_json(self, input_path: str) -> Dict[str, Any]:
        """
        Complete pipeline: File path input → JSON response output
        
        Args:
            input_path: File or directory path to scan
            
        Returns:
            Complete JSON response ready for API clients
        """
        scan_id = str(uuid.uuid4())
        pipeline_start = asyncio.get_event_loop().time()
        
        logger.info(f"=== STARTING COMPLETE SCAN PIPELINE ===")
        logger.info(f"Input Path: {input_path}")
        logger.info(f"Scan ID: {scan_id}")
        logger.info("")
        
        try:
            # STAGE 1: Backend Receives File/Dir Path & File Discovery
            logger.info("STAGE 1: Backend Receives File/Dir Path & File Discovery")
            stage1_start = asyncio.get_event_loop().time()
            
            # Validate input path
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"Path does not exist: {input_path}")
            
            # Discover files and detect extensions
            discovery_result = await self.file_discovery.discover_files(input_path)
            
            stage1_time = asyncio.get_event_loop().time() - stage1_start
            logger.info(f"   ✓ Found {discovery_result.total_files_found} files in {stage1_time:.2f}s")
            logger.info(f"   ✓ Detected languages: {discovery_result.supported_languages}")
            logger.info("")
            
            # STAGE 2: AsyncLanguageConfigManager & Select Language Engine
            logger.info("STAGE 2: AsyncLanguageConfigManager & Select Language Engine")
            stage2_start = asyncio.get_event_loop().time()
            
            # Create scan plan and select engines
            scan_plan = await self.engine_selector.create_scan_plan(input_path)
            
            # Create selected engines
            engines = await self.engine_selector.create_engines(scan_plan)
            
            stage2_time = asyncio.get_event_loop().time() - stage2_start
            logger.info(f"   ✓ Selected {len(scan_plan.selected_engines)} engines in {stage2_time:.2f}s")
            logger.info(f"   ✓ Created engines: {list(engines.keys())}")
            logger.info("")
            
            # STAGE 3: AsyncRuleLoader - Load Rules
            logger.info("STAGE 3: AsyncRuleLoader - Load Rules")
            stage3_start = asyncio.get_event_loop().time()
            
            rule_info = {}
            for language, engine in engines.items():
                logger.info(f"   Loading rules for {language}...")
                
                # Ensure rules are loaded
                if hasattr(engine, '_ensure_rules_loaded'):
                    await engine._ensure_rules_loaded()
                
                # Get rule information
                if hasattr(engine, 'get_rule_info'):
                    engine_rule_info = await engine.get_rule_info()
                    rule_info[language] = engine_rule_info
                    logger.info(f"   ✓ {language}: {engine_rule_info.get('total_rules', 0)} rules, {engine_rule_info.get('total_solutions', 0)} solutions")
            
            stage3_time = asyncio.get_event_loop().time() - stage3_start
            logger.info(f"   ✓ Rules loaded in {stage3_time:.2f}s")
            logger.info("")
            
            # STAGE 4: Execute Semgrep (Build command, Run async, Parse output)
            logger.info("STAGE 4: Execute Semgrep (Build command, Run async, Parse output)")
            stage4_start = asyncio.get_event_loop().time()
            
            scan_results = {}
            
            # Execute scans for each language
            for engine_selection in scan_plan.selected_engines:
                language = engine_selection.language
                if language in engines:
                    engine = engines[language]
                    file_paths = [f.file_path for f in engine_selection.files_to_scan]
                    
                    logger.info(f"   Executing {language} scan on {len(file_paths)} files...")
                    
                    # Execute scan
                    scan_result = await engine.scan_files(file_paths)
                    scan_results[language] = scan_result
                    
                    logger.info(f"   ✓ {language}: {scan_result.total_vulnerabilities} vulnerabilities in {scan_result.scan_duration:.2f}s")
            
            stage4_time = asyncio.get_event_loop().time() - stage4_start
            logger.info(f"   ✓ All scans completed in {stage4_time:.2f}s")
            logger.info("")
            
            # STAGE 5: Process Results (Map solutions, CWE mapping, Create ScanResult)
            logger.info("STAGE 5: Process Results (Map solutions, CWE mapping, Create ScanResult)")
            stage5_start = asyncio.get_event_loop().time()
            
            # Aggregate results from all engines
            total_vulnerabilities = 0
            total_files_scanned = 0
            all_vulnerabilities = []
            
            for language, result in scan_results.items():
                total_vulnerabilities += result.total_vulnerabilities
                total_files_scanned += result.total_files
                all_vulnerabilities.extend(result.vulnerabilities)
                
                logger.info(f"   ✓ {language}: {result.total_vulnerabilities} vulnerabilities processed")
                
                # Verify solutions are mapped
                mapped_solutions = sum(1 for v in result.vulnerabilities if v.solution and v.solution != "No solution available")
                logger.info(f"   ✓ {language}: {mapped_solutions}/{result.total_vulnerabilities} vulnerabilities have solutions")
            
            stage5_time = asyncio.get_event_loop().time() - stage5_start
            logger.info(f"   ✓ Results processed in {stage5_time:.2f}s")
            logger.info("")
            
            # STAGE 6: Return JSON Response to Caller
            logger.info("STAGE 6: Return JSON Response to Caller")
            stage6_start = asyncio.get_event_loop().time()
            
            total_pipeline_time = asyncio.get_event_loop().time() - pipeline_start
            
            # Create complete JSON response
            json_response = {
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "status": "completed",
                "input_path": input_path,
                "summary": {
                    "total_files_discovered": discovery_result.total_files_found,
                    "total_files_scanned": total_files_scanned,
                    "total_vulnerabilities": total_vulnerabilities,
                    "languages_detected": discovery_result.supported_languages,
                    "engines_used": list(engines.keys()),
                    "scan_duration_seconds": total_pipeline_time
                },
                "pipeline_stages": {
                    "file_discovery": stage1_time,
                    "engine_selection": stage2_time,
                    "rule_loading": stage3_time,
                    "scan_execution": stage4_time,
                    "result_processing": stage5_time
                },
                "discovery_results": {
                    "total_files_found": discovery_result.total_files_found,
                    "supported_languages": discovery_result.supported_languages,
                    "files_by_language": {
                        lang: len(files) for lang, files in discovery_result.supported_files.items()
                    }
                },
                "rule_information": rule_info,
                "scan_results": {
                    language: {
                        "language": result.language,
                        "files_scanned": result.total_files,
                        "vulnerabilities_found": result.total_vulnerabilities,
                        "scan_duration": result.scan_duration,
                        "semgrep_version": result.semgrep_version,
                        "vulnerabilities": [
                            {
                                "id": vuln.id,
                                "rule_id": vuln.rule_id,
                                "file_path": os.path.relpath(vuln.file_path, input_path),
                                "line_number": vuln.line_number,
                                "severity": vuln.severity,
                                "message": vuln.message,
                                "category": vuln.category,
                                "cwe": vuln.cwe,
                                "vulnerable_code": vuln.vulnerable_code,
                                "solution": vuln.solution,
                                "confidence": vuln.confidence
                            }
                            for vuln in result.vulnerabilities
                        ]
                    }
                    for language, result in scan_results.items()
                }
            }
            
            stage6_time = asyncio.get_event_loop().time() - stage6_start
            logger.info(f"   ✓ JSON response created in {stage6_time:.2f}s")
            logger.info("")
            
            # Log final summary
            logger.info("=== SCAN PIPELINE COMPLETED SUCCESSFULLY ===")
            logger.info(f"Total Duration: {total_pipeline_time:.2f} seconds")
            logger.info(f"Files Scanned: {total_files_scanned}")
            logger.info(f"Vulnerabilities Found: {total_vulnerabilities}")
            logger.info(f"Languages Processed: {list(engines.keys())}")
            logger.info("=" * 50)
            
            return json_response
            
        except Exception as e:
            logger.error(f"Pipeline failed at stage: {e}")
            
            # Return error response
            return {
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "status": "failed",
                "input_path": input_path,
                "error": str(e),
                "scan_duration_seconds": asyncio.get_event_loop().time() - pipeline_start
            }

async def test_complete_pipeline():
    """Test the complete scanner pipeline from file path to JSON response"""
    
    # Test path
    test_path = r"C:\Users\nehru\app\app-32\java-files"
    
    print("=" * 100)
    print("COMPLETE SCANNER PIPELINE TEST")
    print("File Path Input → JSON Response Output")
    print("=" * 100)
    print(f"Test Path: {test_path}")
    print()
    
    try:
        # Initialize pipeline
        pipeline = CompleteScannerPipeline()
        await pipeline.initialize()
        
        # Execute complete scan
        json_response = await pipeline.scan_path_to_json(test_path)
        
        # Display JSON response summary
        print("\n" + "=" * 100)
        print("FINAL JSON RESPONSE SUMMARY")
        print("=" * 100)
        print(f"Status: {json_response.get('status')}")
        print(f"Scan ID: {json_response.get('scan_id')}")
        print(f"Total Duration: {json_response.get('summary', {}).get('scan_duration_seconds', 0):.2f}s")
        print(f"Files Scanned: {json_response.get('summary', {}).get('total_files_scanned', 0)}")
        print(f"Vulnerabilities: {json_response.get('summary', {}).get('total_vulnerabilities', 0)}")
        print(f"Languages: {json_response.get('summary', {}).get('languages_detected', [])}")
        
        # Show pipeline stage breakdown
        stages = json_response.get('pipeline_stages', {})
        if stages:
            print(f"\nPipeline Stage Breakdown:")
            for stage, duration in stages.items():
                print(f"  {stage}: {duration:.2f}s")
        
        # Show vulnerabilities by language
        scan_results = json_response.get('scan_results', {})
        if scan_results:
            print(f"\nVulnerabilities by Language:")
            for language, results in scan_results.items():
                vuln_count = results.get('vulnerabilities_found', 0)
                file_count = results.get('files_scanned', 0)
                print(f"  {language.upper()}: {vuln_count} vulnerabilities in {file_count} files")
                
                # Show sample vulnerabilities
                if vuln_count > 0:
                    vulnerabilities = results.get('vulnerabilities', [])
                    for i, vuln in enumerate(vulnerabilities[:3], 1):
                        print(f"    {i}. {vuln.get('rule_id')} - {vuln.get('message', '')[:50]}...")
        
        # Export complete JSON response
        output_file = f"complete_scan_response_{json_response.get('scan_id')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(json_response, f, indent=2, ensure_ascii=False)
        
        print(f"\nComplete JSON response exported to: {output_file}")
        print(f"Response size: {len(json.dumps(json_response)):,} characters")
        
        print("\n" + "=" * 100)
        print("COMPLETE PIPELINE TEST SUCCESSFUL")
        print("File Path → Discovery → Engines → Rules → Semgrep → Results → JSON")
        print("=" * 100)
        
        return json_response
        
    except Exception as e:
        print(f"\nPipeline test failed: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    # Configure detailed logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Run complete pipeline test
    asyncio.run(test_complete_pipeline())