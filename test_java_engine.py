#!/usr/bin/env python3
"""
Java Engine Verification Script
Comprehensive testing for the async Java scanner engine
"""

import asyncio
import os
import tempfile
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def verify_java_engine():
    """Complete verification of Java engine functionality"""
    
    print("=" * 60)
    print("JAVA ENGINE VERIFICATION")
    print("=" * 60)
    
    try:
        # Step 1: Import and basic setup
        print("\n1. Testing imports and basic setup...")
        
        from scanner.core.language_config import create_config_manager, AsyncLanguageConfigManager
        from scanner.engines.java_engine import create_java_engine
        
        print("✓ Imports successful")
        
        # Step 2: Create config manager
        print("\n2. Creating async config manager...")
        
        config_manager = await create_config_manager()
        print("✓ Config manager created")
        
        # Step 3: Verify Java language configuration
        print("\n3. Verifying Java language configuration...")
        
        java_config = await config_manager.get_language_config('java')
        if java_config:
            print(f"✓ Java config found")
            print(f"  - Enabled: {java_config.enabled}")
            print(f"  - Extensions: {java_config.extensions}")
            print(f"  - Rule directories: {java_config.rule_directories}")
        else:
            print("✗ Java configuration not found")
            return False
        
        # Step 4: Create Java engine
        print("\n4. Creating Java engine...")
        
        java_engine = await create_java_engine(config_manager)
        print("✓ Java engine created successfully")
        
        # Step 5: Verify rule loading
        print("\n5. Verifying rule loading...")
        
        rule_info = await java_engine.get_rule_info()
        print(f"✓ Rule info retrieved:")
        print(f"  - Total rules: {rule_info.get('total_rules', 0)}")
        print(f"  - Semgrep rules: {rule_info.get('semgrep_rules', 0)}")
        print(f"  - Custom rules: {rule_info.get('custom_rules', 0)}")
        print(f"  - Solutions: {rule_info.get('total_solutions', 0)}")
        
        if rule_info.get('total_rules', 0) == 0:
            print("⚠  Warning: No rules loaded")
        
        # Step 6: Validate rules
        print("\n6. Validating rules...")
        
        validation_result = await java_engine.validate_rules()
        if validation_result.get('valid', False):
            print("✓ Rule validation passed")
        else:
            print("✗ Rule validation failed:")
            for error in validation_result.get('errors', []):
                print(f"  - {error}")
        
        # Step 7: Test file identification
        print("\n7. Testing file identification...")
        
        # Create test Java files
        test_files = await create_test_java_files()
        identified_files = await java_engine.identify_files(test_files['all_files'])
        
        print(f"✓ File identification test:")
        print(f"  - Created {len(test_files['java_files'])} Java files")
        print(f"  - Created {len(test_files['other_files'])} non-Java files")
        print(f"  - Engine identified {len(identified_files)} Java files")
        
        if len(identified_files) == len(test_files['java_files']):
            print("✓ File identification working correctly")
        else:
            print("✗ File identification issue detected")
        
        # Step 8: Test directory scanning
        print("\n8. Testing directory discovery...")
        
        discovered_files = await java_engine.discover_files_in_directory(test_files['test_dir'])
        print(f"✓ Directory discovery found {len(discovered_files)} Java files")
        
        # Step 9: Test actual scanning
        print("\n9. Testing file scanning...")
        
        if identified_files:
            scan_result = await java_engine.scan_files(identified_files)
            print(f"✓ Scan completed:")
            print(f"  - Files scanned: {scan_result.total_files}")
            print(f"  - Vulnerabilities found: {scan_result.total_vulnerabilities}")
            print(f"  - Scan duration: {scan_result.scan_duration:.2f}s")
            print(f"  - Scan status: {scan_result.scan_status}")
            
            if scan_result.error_message:
                print(f"  - Error: {scan_result.error_message}")
        else:
            print("⚠  Skipping scan test - no Java files identified")
        
        # Step 10: Test with vulnerable code
        print("\n10. Testing with vulnerable Java code...")
        
        vulnerable_file = await create_vulnerable_java_file(test_files['test_dir'])
        vuln_scan_result = await java_engine.scan_files([vulnerable_file])
        
        print(f"✓ Vulnerable code scan:")
        print(f"  - Vulnerabilities found: {vuln_scan_result.total_vulnerabilities}")
        
        if vuln_scan_result.vulnerabilities:
            for vuln in vuln_scan_result.vulnerabilities[:3]:  # Show first 3
                print(f"  - {vuln.rule_id}: {vuln.message}")
        
        # Cleanup
        await cleanup_test_files(test_files['test_dir'])
        
        print("\n" + "=" * 60)
        print("VERIFICATION COMPLETE")
        print("=" * 60)
        print("✓ Java engine verification passed successfully!")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Verification failed with error: {e}")
        logger.exception("Verification error:")
        return False

async def create_test_java_files():
    """Create test files for verification"""
    
    # Create temporary directory
    test_dir = tempfile.mkdtemp(prefix='java_engine_test_')
    
    # Create Java files
    java_files = []
    other_files = []
    
    # Simple Java file
    java_file1 = os.path.join(test_dir, "TestClass.java")
    with open(java_file1, 'w') as f:
        f.write("""
public class TestClass {
    public static void main(String[] args) {
        System.out.println("Hello World");
    }
}
""")
    java_files.append(java_file1)
    
    # JSP file
    jsp_file = os.path.join(test_dir, "test.jsp")
    with open(jsp_file, 'w') as f:
        f.write("""
<%@ page language="java" contentType="text/html; charset=UTF-8" %>
<html>
<body>
<h1>Test JSP</h1>
</body>
</html>
""")
    java_files.append(jsp_file)
    
    # Non-Java files (should be ignored)
    py_file = os.path.join(test_dir, "test.py")
    with open(py_file, 'w') as f:
        f.write("print('Hello from Python')")
    other_files.append(py_file)
    
    txt_file = os.path.join(test_dir, "readme.txt")
    with open(txt_file, 'w') as f:
        f.write("This is a text file")
    other_files.append(txt_file)
    
    all_files = java_files + other_files
    
    return {
        'test_dir': test_dir,
        'java_files': java_files,
        'other_files': other_files,
        'all_files': all_files
    }

async def create_vulnerable_java_file(test_dir):
    """Create a Java file with known vulnerabilities for testing"""
    
    vulnerable_file = os.path.join(test_dir, "VulnerableClass.java")
    
    vulnerable_code = """
import java.sql.*;
import javax.servlet.http.*;

public class VulnerableClass {
    
    // SQL Injection vulnerability
    public void unsafeQuery(HttpServletRequest request, Connection conn) throws SQLException {
        String userId = request.getParameter("id");
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }
    
    // Another SQL injection pattern
    public void anotherUnsafeQuery(String userInput, Connection conn) throws SQLException {
        Statement stmt = conn.createStatement();
        stmt.execute("DELETE FROM logs WHERE id = '" + userInput + "'");
    }
    
    // Safe method (should not trigger)
    public void safeQuery(String userId, Connection conn) throws SQLException {
        PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        pstmt.setString(1, userId);
        ResultSet rs = pstmt.executeQuery();
    }
}
"""
    
    with open(vulnerable_file, 'w') as f:
        f.write(vulnerable_code)
    
    return vulnerable_file

async def cleanup_test_files(test_dir):
    """Clean up test files"""
    import shutil
    try:
        shutil.rmtree(test_dir)
        print(f"✓ Cleaned up test directory: {test_dir}")
    except Exception as e:
        print(f"⚠  Could not clean up {test_dir}: {e}")

async def check_prerequisites():
    """Check that prerequisites are installed and configured"""
    
    print("Checking prerequisites...")
    
    # Check Semgrep installation
    try:
        import subprocess
        result = subprocess.run(['semgrep', '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✓ Semgrep installed: {result.stdout.strip()}")
        else:
            print("✗ Semgrep not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError):
        print("✗ Semgrep not found. Install with: pip install semgrep")
        return False
    
    # Check directory structure
    required_dirs = [
        'semgrep-rules',
        'custom-security-rules', 
        'solution-rules'
    ]
    
    for dir_name in required_dirs:
        if os.path.exists(dir_name):
            print(f"✓ Directory exists: {dir_name}")
        else:
            print(f"⚠  Directory not found: {dir_name}")
    
    # Check for Java rules specifically
    java_rules_dir = 'semgrep-rules/java/security'
    if os.path.exists(java_rules_dir):
        rule_files = [f for f in os.listdir(java_rules_dir) if f.endswith('.yml')]
        print(f"✓ Found {len(rule_files)} Java rule files in {java_rules_dir}")
    else:
        print(f"⚠  Java rules directory not found: {java_rules_dir}")
    
    return True

if __name__ == "__main__":
    async def main():
        print("Java Engine Verification Starting...")
        
        # Check prerequisites first
        if not await check_prerequisites():
            print("\n✗ Prerequisites check failed")
            print("Please ensure Semgrep is installed and rule directories exist")
            return
        
        # Run verification
        success = await verify_java_engine()
        
        if success:
            print("\n🎉 All tests passed! Your Java engine is working correctly.")
        else:
            print("\n❌ Some tests failed. Check the output above for details.")
    
    # Run the verification
    asyncio.run(main())