#!/usr/bin/env python3
"""
test_retention_policies.py - Test the retention policy manager functionality
Creates test data and verifies cleanup operations work correctly
"""

import asyncio
import sys
import os
import time
from datetime import datetime, timedelta
import logging

# Add the current directory to path so we can import our modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database.db_manager import AsyncDatabaseManager
from database.retention_manager import RetentionPolicyManager, RetentionConfig
from scanner.core.base_classes import Vulnerability

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def create_test_data(db_manager: AsyncDatabaseManager, num_repos: int = 3, scans_per_repo: int = 5):
    """Create test data with old and recent scans"""
    print(f"📊 Creating test data: {num_repos} repos, {scans_per_repo} scans each...")
    
    current_time = time.time()
    
    for repo_idx in range(num_repos):
        # Create repository
        repo_name = f"Test Repository {repo_idx + 1}"
        repo_path = f"/test/repo_{repo_idx + 1}"
        repo_id = await db_manager.create_repository(repo_name, repo_path, "test")
        
        print(f"✓ Created repository: {repo_name} ({repo_id})")
        
        for scan_idx in range(scans_per_repo):
            # Create scans with different ages
            if scan_idx < 2:
                # Recent scans (last 30 days)
                scan_time = current_time - (scan_idx * 24 * 60 * 60)  # Days ago
            elif scan_idx < 4:
                # Old scans (45-75 days ago)
                scan_time = current_time - ((45 + scan_idx * 15) * 24 * 60 * 60)
            else:
                # Very old scans (90+ days ago)
                scan_time = current_time - ((90 + scan_idx * 10) * 24 * 60 * 60)
            
            # Create scan session with backdated time
            scan_id = f"test_scan_{repo_idx}_{scan_idx}_{int(scan_time)}"
            
            # Manually insert with custom timestamp
            import aiosqlite
            async with aiosqlite.connect(db_manager.db_path) as db:
                await db.execute('''
                    INSERT INTO scans 
                    (scan_id, repository_id, scan_path, language, status, created_at, completed_at, total_files, total_vulnerabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (scan_id, repo_id, repo_path, "java", "completed", int(scan_time), int(scan_time + 300), 10, 2))
                
                # Create test vulnerabilities for each scan
                for vuln_idx in range(2):
                    vuln_id = f"vuln_{scan_id}_{vuln_idx}"
                    await db.execute('''
                        INSERT INTO vulnerabilities 
                        (vulnerability_id, scan_id, rule_id, file_path, line_number, severity, message, vulnerable_code, language, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        vuln_id, scan_id, "test.rule.injection", f"/test/TestFile{vuln_idx}.java",
                        10 + vuln_idx, "HIGH", f"Test vulnerability {vuln_idx}", 
                        f"String query = input{vuln_idx};", "java", int(scan_time)
                    ))
                    
                    # Create code context
                    for ctx_idx in range(3):
                        await db.execute('''
                            INSERT INTO code_context (vulnerability_id, line_number, content, is_vulnerable)
                            VALUES (?, ?, ?, ?)
                        ''', (vuln_id, 9 + ctx_idx, f"Line {9 + ctx_idx}: test code", 1 if ctx_idx == 1 else 0))
                
                await db.commit()
            
            days_ago = (current_time - scan_time) / (24 * 60 * 60)
            print(f"  ✓ Created scan: {scan_id} ({days_ago:.0f} days old)")
    
    print(f"📊 Test data created successfully!")

async def test_retention_preview(retention_manager: RetentionPolicyManager):
    """Test the cleanup preview functionality"""
    print("\n🔍 Testing Cleanup Preview...")
    
    try:
        preview = await retention_manager.get_cleanup_preview()
        
        print("✓ Cleanup Preview:")
        print(f"  - Current database size: {preview['current_database_size_mb']:.2f} MB")
        print(f"  - Retention policy: {preview['retention_policy_days']} days")
        print(f"  - Size limit: {preview['size_limit_mb']} MB")
        print(f"  - Cleanup needed: {preview['cleanup_needed']}")
        
        age_cleanup = preview['age_based_cleanup']
        if age_cleanup['scans_to_remove'] > 0:
            print(f"  - Age-based cleanup: {age_cleanup['scans_to_remove']} scans to remove")
            print(f"    Oldest scan: {age_cleanup['oldest_scan_date']}")
        else:
            print("  - Age-based cleanup: No old scans to remove")
        
        size_cleanup = preview['size_based_cleanup']
        if size_cleanup['scans_to_remove'] > 0:
            print(f"  - Size-based cleanup: {size_cleanup['scans_to_remove']} scans to remove")
            print(f"    Estimated size freed: {size_cleanup['estimated_size_freed_mb']:.2f} MB")
        else:
            print("  - Size-based cleanup: No cleanup needed")
        
        orphaned = preview['orphaned_data']
        print(f"  - Orphaned repositories: {orphaned['orphaned_repositories']}")
        print(f"  - Orphaned contexts: {orphaned['orphaned_contexts']}")
        
        return preview['cleanup_needed']
        
    except Exception as e:
        print(f"✗ Preview test failed: {e}")
        return False

async def test_age_based_cleanup(retention_manager: RetentionPolicyManager):
    """Test age-based cleanup functionality"""
    print("\n🗓️  Testing Age-Based Cleanup...")
    
    try:
        # Get initial stats
        initial_stats = await retention_manager.db_manager.get_database_stats()
        print(f"Initial stats: {initial_stats['scans_count']} scans, {initial_stats['vulnerabilities_count']} vulnerabilities")
        
        # Run age-based cleanup
        cleanup_stats = await retention_manager.cleanup_by_age()
        
        # Get final stats
        final_stats = await retention_manager.db_manager.get_database_stats()
        
        print("✓ Age-based cleanup completed:")
        print(f"  - Scans removed: {cleanup_stats.scans_removed}")
        print(f"  - Vulnerabilities removed: {cleanup_stats.vulnerabilities_removed}")
        print(f"  - Code contexts removed: {cleanup_stats.code_contexts_removed}")
        print(f"  - Size freed: {cleanup_stats.size_freed_mb:.3f} MB")
        print(f"  - Reason: {cleanup_stats.cleanup_reason}")
        
        print(f"Database after cleanup: {final_stats['scans_count']} scans, {final_stats['vulnerabilities_count']} vulnerabilities")
        
        # Verify cleanup worked
        scans_actually_removed = initial_stats['scans_count'] - final_stats['scans_count']
        vulns_actually_removed = initial_stats['vulnerabilities_count'] - final_stats['vulnerabilities_count']
        
        if scans_actually_removed == cleanup_stats.scans_removed and vulns_actually_removed == cleanup_stats.vulnerabilities_removed:
            print("✓ Cleanup counts match database changes")
            return True
        else:
            print(f"✗ Cleanup counts mismatch: reported {cleanup_stats.scans_removed}, actual {scans_actually_removed}")
            return False
        
    except Exception as e:
        print(f"✗ Age-based cleanup test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_size_based_cleanup(retention_manager: RetentionPolicyManager):
    """Test size-based cleanup functionality"""
    print("\n💾 Testing Size-Based Cleanup...")
    
    try:
        # Get initial size
        initial_size = await retention_manager._get_database_size_mb()
        print(f"Initial database size: {initial_size:.3f} MB")
        print(f"Size limit configured: {retention_manager.config.max_database_size_mb} MB")
        
        # Temporarily lower the size limit to force cleanup
        original_limit = retention_manager.config.max_database_size_mb
        retention_manager.config.max_database_size_mb = max(0.01, initial_size * 0.8)  # Force cleanup to 80% of current size
        retention_manager.config.target_size_after_cleanup_mb = max(0.005, initial_size * 0.6)  # Target 60% of current size
        
        print(f"Temporarily set size limit to {retention_manager.config.max_database_size_mb:.3f} MB to test cleanup")
        
        # Get initial stats
        initial_stats = await retention_manager.db_manager.get_database_stats()
        
        # Run size-based cleanup
        cleanup_stats = await retention_manager.cleanup_by_size()
        
        # Get final stats
        final_stats = await retention_manager.db_manager.get_database_stats()
        final_size = await retention_manager._get_database_size_mb()
        
        print("✓ Size-based cleanup completed:")
        print(f"  - Scans removed: {cleanup_stats.scans_removed}")
        print(f"  - Vulnerabilities removed: {cleanup_stats.vulnerabilities_removed}")
        print(f"  - Code contexts removed: {cleanup_stats.code_contexts_removed}")
        print(f"  - Size freed: {cleanup_stats.size_freed_mb:.3f} MB")
        print(f"  - Database size: {initial_size:.3f} MB → {final_size:.3f} MB")
        
        # Restore original limit
        retention_manager.config.max_database_size_mb = original_limit
        retention_manager.config.target_size_after_cleanup_mb = original_limit - 1024  # 1GB less
        
        return cleanup_stats.scans_removed > 0
        
    except Exception as e:
        print(f"✗ Size-based cleanup test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_orphaned_cleanup(retention_manager: RetentionPolicyManager):
    """Test orphaned data cleanup"""
    print("\n🧹 Testing Orphaned Data Cleanup...")
    
    try:
        # Create some orphaned data manually
        import aiosqlite
        async with aiosqlite.connect(retention_manager.db_manager.db_path) as db:
            # Create orphaned repository
            await db.execute('''
                INSERT INTO repositories (repository_id, name, url, type, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', ("orphaned_repo", "Orphaned Repo", "/orphaned", "test", int(time.time()), int(time.time())))
            
            # Create orphaned code context
            await db.execute('''
                INSERT INTO code_context (vulnerability_id, line_number, content, is_vulnerable)
                VALUES (?, ?, ?, ?)
            ''', ("nonexistent_vuln", 1, "orphaned context", 0))
            
            await db.commit()
        
        print("Created orphaned test data")
        
        # Run orphaned cleanup
        cleanup_stats = await retention_manager.cleanup_orphaned_data()
        
        print("✓ Orphaned data cleanup completed:")
        print(f"  - Orphaned repositories removed: {cleanup_stats.repositories_removed}")
        print(f"  - Orphaned code contexts removed: {cleanup_stats.code_contexts_removed}")
        
        return cleanup_stats.repositories_removed > 0 or cleanup_stats.code_contexts_removed > 0
        
    except Exception as e:
        print(f"✗ Orphaned cleanup test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_retention_config(retention_manager: RetentionPolicyManager):
    """Test retention configuration updates"""
    print("\n⚙️  Testing Retention Configuration...")
    
    try:
        # Get initial config
        initial_config = retention_manager.get_config()
        print(f"Initial max retention days: {initial_config['max_retention_days']}")
        
        # Update config
        await retention_manager.update_config(max_retention_days=30, min_scans_to_keep=5)
        
        # Verify update
        updated_config = retention_manager.get_config()
        
        if updated_config['max_retention_days'] == 30 and updated_config['min_scans_to_keep'] == 5:
            print("✓ Configuration update successful")
            
            # Restore original config
            await retention_manager.update_config(
                max_retention_days=initial_config['max_retention_days'],
                min_scans_to_keep=initial_config['min_scans_to_keep']
            )
            
            return True
        else:
            print("✗ Configuration update failed")
            return False
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

async def test_background_scheduler(retention_manager: RetentionPolicyManager):
    """Test that background scheduler is working"""
    print("\n⏰ Testing Background Scheduler...")
    
    try:
        # Check if scheduler is running
        status = retention_manager.get_status()
        
        print(f"✓ Scheduler status:")
        print(f"  - Is running: {status['is_running']}")
        print(f"  - Cleanup interval: {status['config']['cleanup_interval_hours']} hours")
        print(f"  - Last cleanup: {status['last_cleanup_ago_hours']} hours ago" if status['last_cleanup_ago_hours'] else "  - Last cleanup: Never")
        print(f"  - Next cleanup: {status['next_cleanup_in_hours']} hours" if status['next_cleanup_in_hours'] else "  - Next cleanup: Soon")
        
        return status['is_running']
        
    except Exception as e:
        print(f"✗ Background scheduler test failed: {e}")
        return False

async def run_all_retention_tests():
    """Run all retention policy tests"""
    print("🧪 Starting Retention Policy Tests")
    print("=" * 80)
    
    # Initialize database manager
    db_manager = AsyncDatabaseManager("test_retention_scanner.db")
    await db_manager.initialize()
    print("✓ Test database initialized")
    
    # Initialize retention manager with test config
    test_config = RetentionConfig(
        max_retention_days=60,     # 60 days retention
        min_scans_to_keep=3,       # Keep at least 3 scans
        max_database_size_mb=10,   # 10MB limit for testing
        target_size_after_cleanup_mb=8,  # 8MB target
        cleanup_interval_hours=1,  # 1 hour for testing
        startup_cleanup_enabled=False  # Don't run startup cleanup during tests
    )
    
    retention_manager = RetentionPolicyManager(db_manager, test_config)
    await retention_manager.start_background_cleanup()
    print("✓ Test retention manager initialized")
    
    test_results = {}
    
    try:
        # Create test data
        await create_test_data(db_manager, num_repos=2, scans_per_repo=4)
        
        # Run tests
        test_results["preview"] = await test_retention_preview(retention_manager)
        test_results["age_cleanup"] = await test_age_based_cleanup(retention_manager)
        test_results["size_cleanup"] = await test_size_based_cleanup(retention_manager)
        test_results["orphaned_cleanup"] = await test_orphaned_cleanup(retention_manager)
        test_results["config_update"] = await test_retention_config(retention_manager)
        test_results["background_scheduler"] = await test_background_scheduler(retention_manager)
        
        # Final database stats
        print("\n📊 Final Database Stats:")
        final_stats = await db_manager.get_database_stats()
        print(f"  - Repositories: {final_stats['repositories_count']}")
        print(f"  - Scans: {final_stats['scans_count']}")
        print(f"  - Vulnerabilities: {final_stats['vulnerabilities_count']}")
        print(f"  - Code contexts: {final_stats['code_context_count']}")
        print(f"  - Database size: {final_stats['database_size_mb']:.3f} MB")
        
    except Exception as e:
        print(f"✗ Test execution failed: {e}")
        import traceback
        traceback.print_exc()
        test_results["execution_error"] = str(e)
    
    finally:
        # Cleanup
        await retention_manager.stop_background_cleanup()
        print("✓ Retention manager stopped")
    
    # Summary
    print("\n" + "=" * 80)
    print("🎯 Test Results Summary:")
    
    passed_tests = 0
    total_tests = 0
    
    for test_name, result in test_results.items():
        if test_name == "execution_error":
            continue
            
        total_tests += 1
        status = "PASS" if result else "FAIL"
        emoji = "✅" if result else "❌"
        print(f"  {emoji} {test_name.replace('_', ' ').title()}: {status}")
        
        if result:
            passed_tests += 1
    
    print(f"\n📈 Overall Results: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 ALL RETENTION TESTS PASSED!")
        print("✓ Retention policies are working correctly")
        print("✓ Ready for production use")
        success = True
    else:
        print("❌ SOME TESTS FAILED")
        print("Please review the errors above before deployment")
        success = False
    
    # Clean up test database
    try:
        if os.path.exists("test_retention_scanner.db"):
            os.remove("test_retention_scanner.db")
            print("🗑️  Test database file removed")
    except Exception as e:
        print(f"Warning: Could not remove test database: {e}")
    
    return success

async def main():
    """Run the retention tests"""
    try:
        success = await run_all_retention_tests()
        return 0 if success else 1
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)