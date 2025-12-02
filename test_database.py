#!/usr/bin/env python3
"""
test_database.py - Test the database manager functionality
Run this script to verify database operations work correctly
"""

import asyncio
import sys
import os
import time
from datetime import datetime

# Add the current directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from scanner.core.base_classes import Vulnerability
from database.db_manager import AsyncDatabaseManager

async def test_database_operations():
    """Test all database operations"""
    print("🔧 Testing Database Manager")
    print("=" * 50)
    
    # Initialize database manager
    db_manager = AsyncDatabaseManager("test_vulnerability_scanner.db")
    
    try:
        # Test 1: Initialize database
        print("1. Initializing database...")
        await db_manager.initialize()
        print("✓ Database initialized successfully")
        
        # Test 2: Create repository
        print("\n2. Creating repository...")
        repo_id = await db_manager.create_repository(
            name="Test Java Project", 
            path="/test/project/path",
            repo_type="local"
        )
        print(f"✓ Repository created: {repo_id}")
        
        # Test 3: Create scan session
        print("\n3. Creating scan session...")
        scan_id = "test_scan_123"
        await db_manager.create_scan_session(
            scan_id=scan_id,
            repository_id=repo_id,
            scan_path="/test/project/path",
            language="java"
        )
        print(f"✓ Scan session created: {scan_id}")
        
        # Test 4: Create test vulnerabilities
        print("\n4. Creating test vulnerabilities...")
        
        # Create test vulnerability 1
        vuln1 = Vulnerability(
            id="test_vuln_1",
            rule_id="java.security.sql-injection",
            file_path="/test/project/UserController.java",
            line_number=45,
            column_start=20,
            column_end=35,
            severity="HIGH",
            message="SQL injection vulnerability detected",
            vulnerable_code="query = \"SELECT * FROM users WHERE id = \" + userId;",
            code_context=[
                {"line_number": 43, "content": "public User getUserById(String userId) {", "is_vulnerable": False},
                {"line_number": 44, "content": "    String query;", "is_vulnerable": False},
                {"line_number": 45, "content": "    query = \"SELECT * FROM users WHERE id = \" + userId;", "is_vulnerable": True},
                {"line_number": 46, "content": "    return database.execute(query);", "is_vulnerable": False},
                {"line_number": 47, "content": "}", "is_vulnerable": False}
            ],
            solution="Use prepared statements to prevent SQL injection",
            cwe="CWE-89",
            category="security",
            language="java",
            confidence="HIGH"
        )
        
        vuln1_id = await db_manager.store_vulnerability(scan_id, vuln1)
        print(f"✓ Vulnerability 1 stored: {vuln1_id}")
        
        # Create test vulnerability 2
        vuln2 = Vulnerability(
            id="test_vuln_2", 
            rule_id="java.security.xss",
            file_path="/test/project/WebController.java",
            line_number=12,
            column_start=10,
            column_end=25,
            severity="MEDIUM",
            message="Cross-site scripting (XSS) vulnerability",
            vulnerable_code="response.getWriter().write(userInput);",
            code_context=[
                {"line_number": 10, "content": "@RequestMapping(\"/display\")", "is_vulnerable": False},
                {"line_number": 11, "content": "public void displayMessage(String userInput, HttpServletResponse response) {", "is_vulnerable": False},
                {"line_number": 12, "content": "    response.getWriter().write(userInput);", "is_vulnerable": True},
                {"line_number": 13, "content": "}", "is_vulnerable": False}
            ],
            solution="Sanitize user input before displaying",
            cwe="CWE-79",
            category="security",
            language="java",
            confidence="MEDIUM"
        )
        
        vuln2_id = await db_manager.store_vulnerability(scan_id, vuln2)
        print(f"✓ Vulnerability 2 stored: {vuln2_id}")
        
        # Test 5: Update scan status
        print("\n5. Updating scan status...")
        await db_manager.update_scan_status(
            scan_id=scan_id,
            status="completed",
            total_files=15,
            total_vulnerabilities=2
        )
        print("✓ Scan status updated to completed")
        
        # Test 6: Retrieve scan with vulnerabilities
        print("\n6. Retrieving scan results...")
        scan_result = await db_manager.get_scan_with_vulnerabilities(scan_id)
        
        if scan_result:
            print(f"✓ Scan retrieved: {scan_result['scan_id']}")
            print(f"  - Repository: {scan_result['repository_name']}")
            print(f"  - Status: {scan_result['status']}")
            print(f"  - Total files: {scan_result['total_files']}")
            print(f"  - Total vulnerabilities: {scan_result['total_vulnerabilities']}")
            print(f"  - Vulnerabilities found: {len(scan_result['vulnerabilities'])}")
            
            for i, vuln in enumerate(scan_result['vulnerabilities']):
                print(f"    Vuln {i+1}: {vuln['severity']} - {vuln['rule_id']} in {os.path.basename(vuln['file_path'])}")
                print(f"             Line {vuln['line_number']}: {vuln['message']}")
        else:
            print("✗ Failed to retrieve scan results")
            return False
        
        # Test 7: Get all repositories
        print("\n7. Getting all repositories...")
        repositories = await db_manager.get_all_repositories()
        print(f"✓ Found {len(repositories)} repositories:")
        for repo in repositories:
            print(f"  - {repo['name']} ({repo['total_scans']} scans)")
        
        # Test 8: Get database stats
        print("\n8. Getting database statistics...")
        stats = await db_manager.get_database_stats()
        print("✓ Database statistics:")
        print(f"  - Repositories: {stats['repositories_count']}")
        print(f"  - Scans: {stats['scans_count']}")
        print(f"  - Vulnerabilities: {stats['vulnerabilities_count']}")
        print(f"  - Code contexts: {stats['code_context_count']}")
        print(f"  - Database size: {stats['database_size_mb']} MB")
        print(f"  - Scans in last 24h: {stats['scans_last_24h']}")
        
        print("\n🎉 All database tests passed!")
        return True
        
    except Exception as e:
        print(f"\n✗ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_cleanup_operations():
    """Test cleanup operations"""
    print("\n🧹 Testing Cleanup Operations")
    print("=" * 50)
    
    db_manager = AsyncDatabaseManager("test_vulnerability_scanner.db")
    
    try:
        # Test cleanup (should not remove recent records)
        print("1. Testing cleanup of old records...")
        cleanup_stats = await db_manager.cleanup_old_records(retention_days=30)
        print(f"✓ Cleanup completed:")
        print(f"  - Scans removed: {cleanup_stats['scans_removed']}")
        print(f"  - Vulnerabilities removed: {cleanup_stats['vulnerabilities_removed']}")
        print(f"  - Contexts removed: {cleanup_stats['contexts_removed']}")
        
        return True
        
    except Exception as e:
        print(f"✗ Cleanup test failed: {e}")
        return False

def cleanup_test_database():
    """Remove test database file"""
    try:
        if os.path.exists("test_vulnerability_scanner.db"):
            os.remove("test_vulnerability_scanner.db")
            print("🗑️  Test database file removed")
    except Exception as e:
        print(f"Warning: Could not remove test database: {e}")

async def main():
    """Run all tests"""
    print("Starting Database Manager Tests")
    print("=" * 70)
    
    # Clean up any existing test database
    cleanup_test_database()
    
    success = True
    
    # Run basic operations test
    success = await test_database_operations()
    
    if success:
        # Run cleanup test
        success = await test_cleanup_operations()
    
    print("\n" + "=" * 70)
    
    if success:
        print("🎉 ALL TESTS PASSED - Database manager is working correctly!")
        print("✓ Ready to integrate with scanner")
    else:
        print("❌ TESTS FAILED - Please check the errors above")
        return 1
    
    # Clean up test database
    cleanup_test_database()
    
    return 0

if __name__ == "__main__":
    # Run the async test
    exit_code = asyncio.run(main())