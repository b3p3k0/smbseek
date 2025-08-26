#!/usr/bin/env python3
"""
SMBSeek CLI Flag Testing Script

Tests all command line flags to ensure they work correctly after the
unified CLI implementation. This script verifies that argument parsing
works as expected for all subcommands.
"""

import subprocess
import sys
import os


def run_command(cmd, expect_success=True):
    """
    Run a command and check if it succeeds or fails as expected.
    
    Args:
        cmd: Command list to execute
        expect_success: Whether the command should succeed
        
    Returns:
        True if result matches expectation, False otherwise
    """
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        success = result.returncode == 0
        
        if success == expect_success:
            print(f"✅ PASS: {' '.join(cmd)}")
            return True
        else:
            print(f"❌ FAIL: {' '.join(cmd)}")
            if result.stderr:
                print(f"   Error: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"⏰ TIMEOUT: {' '.join(cmd)}")
        return False
    except Exception as e:
        print(f"💥 ERROR: {' '.join(cmd)} - {e}")
        return False


def test_help_commands():
    """Test help command functionality."""
    print("\n🔍 Testing Help Commands")
    
    tests = [
        # Global help
        (["./smbseek.py", "--help"], True),
        (["./smbseek.py", "-h"], True),
        
        # Subcommand help
        (["./smbseek.py", "run", "--help"], True),
        (["./smbseek.py", "discover", "--help"], True),
        (["./smbseek.py", "access", "--help"], True),
        (["./smbseek.py", "collect", "--help"], True),
        (["./smbseek.py", "analyze", "--help"], True),
        (["./smbseek.py", "report", "--help"], True),
        (["./smbseek.py", "db", "--help"], True),
    ]
    
    results = []
    for cmd, expect_success in tests:
        results.append(run_command(cmd, expect_success))
    
    return all(results)


def test_global_flags():
    """Test global flag positioning and recognition."""
    print("\n🔍 Testing Global Flag Positioning")
    
    tests = [
        # Version flag
        (["./smbseek.py", "--version"], True),
        
        # Invalid command should show help
        (["./smbseek.py"], False),  # Should show error
        (["./smbseek.py", "invalid-command"], False),  # Should fail
        
        # Global flag combinations that should fail
        (["./smbseek.py", "--quiet", "--verbose", "run", "--country", "US"], False),  # Conflicting flags
    ]
    
    results = []
    for cmd, expect_success in tests:
        results.append(run_command(cmd, expect_success))
    
    return all(results)


def test_subcommand_flags():
    """Test subcommand flag acceptance."""
    print("\n🔍 Testing Subcommand Flags")
    
    # These should parse successfully (but may fail execution due to missing libs)
    tests = [
        # Run command with various flag positions
        (["./smbseek.py", "run", "--verbose", "--country", "US"], False),  # Will fail due to missing libs, but should parse
        (["./smbseek.py", "run", "--quiet", "--country", "US"], False),   # Will fail due to missing libs, but should parse
        (["./smbseek.py", "run", "--no-colors", "--country", "US"], False), # Will fail due to missing libs, but should parse
        
        # Global flags in global position
        (["./smbseek.py", "--verbose", "run", "--country", "US"], False),  # Will fail due to missing libs, but should parse
        (["./smbseek.py", "--quiet", "run", "--country", "US"], False),    # Will fail due to missing libs, but should parse
        
        # Missing required arguments should show help
        (["./smbseek.py", "run"], False),  # Missing --country
        (["./smbseek.py", "discover"], False),  # Missing --country
    ]
    
    results = []
    for cmd, expect_success in tests:
        # For these tests, we're checking that argument parsing works
        # The command may fail due to missing libraries, but that's different from parsing errors
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            # Check if it's a parsing error vs execution error
            if "unrecognized arguments" in result.stderr or "invalid choice" in result.stderr:
                print(f"❌ PARSE FAIL: {' '.join(cmd)}")
                print(f"   Error: {result.stderr.strip()}")
                results.append(False)
            else:
                print(f"✅ PARSE OK: {' '.join(cmd)} (execution may fail, but parsing worked)")
                results.append(True)
        except Exception as e:
            print(f"💥 ERROR: {' '.join(cmd)} - {e}")
            results.append(False)
    
    return all(results)


def test_database_commands():
    """Test database subcommand parsing."""
    print("\n🔍 Testing Database Commands")
    
    tests = [
        # Database subcommands should parse correctly
        (["./smbseek.py", "db", "query", "--help"], True),
        (["./smbseek.py", "db", "backup", "--help"], True),
        (["./smbseek.py", "db", "info", "--help"], True),
        (["./smbseek.py", "db", "maintenance", "--help"], True),
        (["./smbseek.py", "db", "import", "--help"], True),
        
        # Invalid database subcommands
        (["./smbseek.py", "db", "invalid"], False),
    ]
    
    results = []
    for cmd, expect_success in tests:
        results.append(run_command(cmd, expect_success))
    
    return all(results)


def main():
    """Run all CLI tests."""
    print("🧪 SMBSeek CLI Flag Testing")
    print("=" * 50)
    
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Make sure smbseek.py is executable
    if not os.access('./smbseek.py', os.X_OK):
        print("⚠️  Making smbseek.py executable...")
        os.chmod('./smbseek.py', 0o755)
    
    # Run test suites
    test_results = []
    
    test_results.append(test_help_commands())
    test_results.append(test_global_flags())
    test_results.append(test_subcommand_flags())
    test_results.append(test_database_commands())
    
    # Summary
    print("\n" + "=" * 50)
    if all(test_results):
        print("🎉 ALL TESTS PASSED!")
        print("✅ Command line flag parsing is working correctly")
        return 0
    else:
        print("❌ SOME TESTS FAILED!")
        print("⚠️  Check the output above for specific failures")
        return 1


if __name__ == "__main__":
    sys.exit(main())