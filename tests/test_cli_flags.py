#!/usr/bin/env python3
"""
SMBSeek CLI Flag Testing Script - Updated for 3.0.0

Tests the unified CLI interface to ensure argument parsing works correctly
and deprecation warnings are properly displayed.
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
            if result.stdout:
                print(f"   Output: {result.stdout.strip()[:100]}")
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

        # Version
        (["./smbseek.py", "--version"], True),
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

        # Cautious flag
        (["./smbseek.py", "--cautious", "--help"], True),
        (["./smbseek.py", "--help", "--cautious"], True),
        # SMB1 override flag
        (["./smbseek.py", "--enable-smb1", "--help"], True),
        (["./smbseek.py", "--help", "--enable-smb1"], True),
        (["./smbseek.py", "--cautious", "--enable-smb1", "--help"], True),

        # Risky flag should fail (no longer exists)
        (["./smbseek.py", "--risky", "--country", "US"], False),

        # Invalid arguments should fail
        (["./smbseek.py", "--invalid-flag"], False),

        # Conflicting flags should fail
        (["./smbseek.py", "--quiet", "--verbose"], False),
    ]

    # Note: Running without arguments will start a scan with default configuration
    # This is expected behavior - the tool doesn't require --country if config has defaults

    results = []
    for cmd, expect_success in tests:
        results.append(run_command(cmd, expect_success))

    return all(results)


def test_deprecation_warnings():
    """Test that deprecated commands show warnings."""
    print("\n🔍 Testing Deprecation Warnings")

    def check_deprecation_warning(cmd, should_continue=True):
        """Check if command shows deprecation warning."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            has_warning = "DEPRECATED" in output
            expected_exit = 0 if should_continue else 1
            correct_exit = result.returncode == expected_exit

            if has_warning and correct_exit:
                print(f"✅ PASS: {' '.join(cmd)} (shows deprecation warning)")
                return True
            else:
                print(f"❌ FAIL: {' '.join(cmd)} (warning: {has_warning}, exit: {result.returncode})")
                return False

        except Exception as e:
            print(f"💥 ERROR: {' '.join(cmd)} - {e}")
            return False

    tests = [
        # Deprecated subcommands that should continue with warning
        (["./smbseek.py", "run", "--help"], True),
        (["./smbseek.py", "discover", "--help"], True),
        (["./smbseek.py", "access", "--help"], True),

        # Deprecated subcommands that should fail with warning
        (["./smbseek.py", "collect"], False),
        (["./smbseek.py", "analyze"], False),
        (["./smbseek.py", "report"], False),
        (["./smbseek.py", "db"], False),
    ]

    results = []
    for cmd, should_continue in tests:
        results.append(check_deprecation_warning(cmd, should_continue))

    return all(results)


def test_unified_interface():
    """Test the unified command interface (without actually running scans)."""
    print("\n🔍 Testing Unified Interface")

    tests = [
        # These should parse successfully but may fail due to missing Shodan API key
        (["./smbseek.py", "--country", "US", "--help"], True),
        (["./smbseek.py", "--help"], True),
        (["./smbseek.py", "--verbose", "--help"], True),
        (["./smbseek.py", "--quiet", "--help"], True),
        (["./smbseek.py", "--no-colors", "--help"], True),
    ]

    results = []
    for cmd, expect_success in tests:
        results.append(run_command(cmd, expect_success))

    return all(results)


def test_force_hosts_parsing():
    """Test --force-hosts argument parsing and validation."""
    print("\n🔍 Testing Force Hosts Parsing")

    def check_force_hosts_parsing(cmd, expect_success):
        """Check if force hosts parsing works as expected."""
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

    tests = [
        # Valid IP addresses
        (["./smbseek.py", "--force-hosts", "192.168.1.1", "--help"], True),
        (["./smbseek.py", "--force-hosts", "192.168.1.1,10.0.0.1", "--help"], True),
        (["./smbseek.py", "--force-hosts", "192.168.1.1, 10.0.0.1", "--help"], True),  # Spaces
        (["./smbseek.py", "--force-hosts", "::1", "--help"], True),  # IPv6
        (["./smbseek.py", "--force-hosts", "::1,2001:db8::1", "--help"], True),  # IPv6 list
        (["./smbseek.py", "--force-hosts", "192.168.1.1", "--force-hosts", "10.0.0.1", "--help"], True),  # Repeated

        # Invalid inputs
        (["./smbseek.py", "--force-hosts", "", "--help"], False),  # Empty
        (["./smbseek.py", "--force-hosts", "invalid", "--help"], False),  # Invalid IP
        (["./smbseek.py", "--force-hosts", "google.com", "--help"], False),  # Hostname
        (["./smbseek.py", "--force-hosts", "192.168.1.256", "--help"], False),  # Invalid IPv4
        (["./smbseek.py", "--force-hosts", "192.168.1.1,invalid", "--help"], False),  # Mixed valid/invalid
    ]

    results = []
    for cmd, expect_success in tests:
        results.append(check_force_hosts_parsing(cmd, expect_success))

    return all(results)


def test_standalone_deprecated_scripts():
    """Test standalone deprecated command scripts."""
    print("\n🔍 Testing Standalone Deprecated Scripts")

    tests = [
        # These should show deprecation warnings but exit with success
        (["python3", "commands/collect.py"], True),
        (["python3", "commands/analyze.py"], True),
        (["python3", "commands/report.py"], True),
        (["python3", "commands/database.py"], True),
        (["python3", "commands/run.py"], True),
    ]

    def check_standalone_deprecation(cmd):
        """Check standalone script deprecation."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr

            has_warning = "DEPRECATED" in output
            success_exit = result.returncode == 0

            if has_warning and success_exit:
                print(f"✅ PASS: {' '.join(cmd)} (standalone deprecation)")
                return True
            else:
                print(f"❌ FAIL: {' '.join(cmd)} (warning: {has_warning}, exit: {result.returncode})")
                return False

        except Exception as e:
            print(f"💥 ERROR: {' '.join(cmd)} - {e}")
            return False

    results = []
    for cmd, _ in tests:
        results.append(check_standalone_deprecation(cmd))

    return all(results)


def main():
    """Run all CLI tests."""
    print("🧪 SMBSeek CLI Testing Suite - Version 3.0.0")
    print("=" * 50)

    all_passed = True

    # Run test suites
    test_suites = [
        ("Help Commands", test_help_commands),
        ("Global Flags", test_global_flags),
        ("Deprecation Warnings", test_deprecation_warnings),
        ("Unified Interface", test_unified_interface),
        ("Force Hosts Parsing", test_force_hosts_parsing),
        ("Standalone Scripts", test_standalone_deprecated_scripts),
    ]

    for suite_name, test_func in test_suites:
        print(f"\n{'='*20} {suite_name} {'='*20}")
        try:
            result = test_func()
            if result:
                print(f"✅ {suite_name}: ALL TESTS PASSED")
            else:
                print(f"❌ {suite_name}: SOME TESTS FAILED")
                all_passed = False
        except Exception as e:
            print(f"💥 {suite_name}: TEST SUITE ERROR - {e}")
            all_passed = False

    # Final results
    print("\n" + "="*50)
    if all_passed:
        print("🎉 ALL CLI TESTS PASSED!")
        return 0
    else:
        print("❌ SOME CLI TESTS FAILED!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
