#!/usr/bin/env python3
"""
Real Java Files Scanner Test
Scan actual Java files directory and show detailed vulnerability results
"""

import asyncio
import os
import json
import logging
from datetime import datetime
from pathlib import Path

# Configure logging to see what's happening
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Your Java files directory
JAVA_FILES_DIR = r"C:\Users\nehru\app\app-32\java-files"

async def scan_real_java_files():
    """Scan real Java files and display detailed results"""
    
    print("=" * 80)
    print("SCANNING REAL JAVA FILES")
    print("=" * 80)
    print(f"Target directory: {JAVA_FILES_DIR}")
    print(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Check if directory exists
        if not os.path.exists(JAVA_FILES_DIR):
            print(f"❌ Directory not found: {JAVA_FILES_DIR}")
            return
        
        # Import your scanner components
        from scanner.core.language_config import create_config_manager
        from scanner.engines.java_engine import create_java_engine
        
        print("🔧 Setting up Java scanner...")
        
        # Create config manager and Java engine
        config_manager = await create_config_manager()
        java_engine = await create_java_engine(config_manager)
        
        print("✅ Java scanner initialized")
        print()
        
        # Discover Java files in the directory
        print("🔍 Discovering Java files...")
        discovered_files = await java_engine.discover_files_in_directory(JAVA_FILES_DIR)
        
        if not discovered_files:
            print("❌ No Java files found in the directory")
            return
        
        print(f"📁 Found {len(discovered_files)} Java files:")
        for i, file_path in enumerate(discovered_files[:10], 1):  # Show first 10
            relative_path = os.path.relpath(file_path, JAVA_FILES_DIR)
            print(f"   {i:2d}. {relative_path}")
        
        if len(discovered_files) > 10:
            print(f"   ... and {len(discovered_files) - 10} more files")
        print()
        
        # Run the security scan
        print("🔍 Starting security scan...")
        print("   This may take a few minutes depending on the number of files...")
        print()
        
        scan_result = await java_engine.scan_directory(JAVA_FILES_DIR)
        
        # Display scan summary
        print("=" * 80)
        print("SCAN RESULTS SUMMARY")
        print("=" * 80)
        print(f"📊 Scan Statistics:")
        print(f"   • Files scanned: {scan_result.total_files}")
        print(f"   • Total vulnerabilities: {scan_result.total_vulnerabilities}")
        print(f"   • Scan duration: {scan_result.scan_duration:.2f} seconds")
        print(f"   • Semgrep version: {scan_result.semgrep_version}")
        print()
        
        if scan_result.total_vulnerabilities == 0:
            print("✅ No security vulnerabilities found!")
            print("   Your Java code appears to be secure.")
            return
        
        # Group vulnerabilities by severity
        severity_groups = {}
        for vuln in scan_result.vulnerabilities:
            severity = vuln.severity.upper()
            if severity not in severity_groups:
                severity_groups[severity] = []
            severity_groups[severity].append(vuln)
        
        # Display vulnerabilities by severity
        severity_order = ['ERROR', 'WARNING', 'INFO']
        
        for severity in severity_order:
            if severity in severity_groups:
                vulns = severity_groups[severity]
                print(f"🚨 {severity} LEVEL ({len(vulns)} issues)")
                print("-" * 50)
                
                for i, vuln in enumerate(vulns, 1):
                    relative_path = os.path.relpath(vuln.file_path, JAVA_FILES_DIR)
                    print(f"{i:2d}. {vuln.rule_id}")
                    print(f"    📁 File: {relative_path}:{vuln.line_number}")
                    print(f"    📝 Issue: {vuln.message}")
                    
                    if vuln.cwe:
                        print(f"    🏷️  CWE: {vuln.cwe}")
                    
                    if vuln.category:
                        print(f"    📂 Category: {vuln.category}")
                    
                    # Show vulnerable code
                    if vuln.vulnerable_code:
                        print(f"    💥 Code: {vuln.vulnerable_code[:100]}...")
                    
                    # Show solution if available
                    if vuln.solution and vuln.solution != "No solution available":
                        solution_preview = vuln.solution[:200].replace('\n', ' ')
                        print(f"    💡 Solution: {solution_preview}...")
                    
                    print()
        
        # Show most vulnerable files
        file_vuln_count = {}
        for vuln in scan_result.vulnerabilities:
            file_path = vuln.file_path
            if file_path not in file_vuln_count:
                file_vuln_count[file_path] = 0
            file_vuln_count[file_path] += 1
        
        if file_vuln_count:
            print("📈 MOST VULNERABLE FILES")
            print("-" * 50)
            sorted_files = sorted(file_vuln_count.items(), key=lambda x: x[1], reverse=True)
            
            for i, (file_path, count) in enumerate(sorted_files[:10], 1):
                relative_path = os.path.relpath(file_path, JAVA_FILES_DIR)
                print(f"{i:2d}. {relative_path} ({count} issues)")
            print()
        
        # Show vulnerability categories breakdown
        category_count = {}
        for vuln in scan_result.vulnerabilities:
            category = vuln.category or 'unknown'
            category_count[category] = category_count.get(category, 0) + 1
        
        if category_count:
            print("📊 VULNERABILITY CATEGORIES")
            print("-" * 50)
            for category, count in sorted(category_count.items(), key=lambda x: x[1], reverse=True):
                print(f"   • {category}: {count} issues")
            print()
        
        # Export detailed results to JSON
        await save_scan_results(scan_result, JAVA_FILES_DIR)
        
        print("=" * 80)
        print("SCAN COMPLETED")
        print("=" * 80)
        print(f"✅ Detailed results saved to 'java_scan_results.json'")
        print(f"⏱️  Total scan time: {scan_result.scan_duration:.2f} seconds")
        
    except Exception as e:
        print(f"❌ Scan failed with error: {e}")
        logger.exception("Scan error details:")

async def save_scan_results(scan_result, base_dir):
    """Save detailed scan results to JSON file"""
    
    # Convert to dict with relative paths
    results_dict = scan_result.to_dict()
    
    # Convert absolute paths to relative paths for cleaner output
    for vuln in results_dict['vulnerabilities']:
        if vuln['file_path'].startswith(base_dir):
            vuln['file_path'] = os.path.relpath(vuln['file_path'], base_dir)
    
    # Also convert files_scanned
    results_dict['files_scanned'] = [
        os.path.relpath(f, base_dir) if f.startswith(base_dir) else f 
        for f in results_dict['files_scanned']
    ]
    
    # Save to JSON file
    output_file = 'java_scan_results.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results_dict, f, indent=2, ensure_ascii=False)
    
    print(f"📄 Full results exported to: {output_file}")

async def quick_stats_only():
    """Quick scan to just show statistics without detailed output"""
    
    print("🔍 Quick Statistics Scan")
    print("-" * 30)
    
    try:
        from scanner.core.language_config import create_config_manager
        from scanner.engines.java_engine import create_java_engine
        
        config_manager = await create_config_manager()
        java_engine = await create_java_engine(config_manager)
        
        discovered_files = await java_engine.discover_files_in_directory(JAVA_FILES_DIR)
        print(f"Java files found: {len(discovered_files)}")
        
        if discovered_files:
            scan_result = await java_engine.scan_directory(JAVA_FILES_DIR)
            print(f"Vulnerabilities found: {scan_result.total_vulnerabilities}")
            print(f"Scan time: {scan_result.scan_duration:.1f}s")
            
            if scan_result.total_vulnerabilities > 0:
                severity_count = {}
                for vuln in scan_result.vulnerabilities:
                    sev = vuln.severity.upper()
                    severity_count[sev] = severity_count.get(sev, 0) + 1
                
                for severity, count in severity_count.items():
                    print(f"  {severity}: {count}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    import sys
    
    print("Java Files Security Scanner")
    print("Choose scan type:")
    print("1. Full detailed scan (recommended)")
    print("2. Quick statistics only")
    
    if len(sys.argv) > 1 and sys.argv[1] == 'quick':
        asyncio.run(quick_stats_only())
    else:
        asyncio.run(scan_real_java_files())