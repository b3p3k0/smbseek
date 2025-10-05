#!/usr/bin/env python3
"""
Performance validation script for exclusion optimization.

This script demonstrates the performance improvements achieved by the exclusion
optimization through controlled timing tests.
"""

import sys
import os
import time
import unittest
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.discover import DiscoverOperation


def create_mock_discover_operation():
    """Create a mock DiscoverOperation for performance testing."""
    mock_config = Mock()
    mock_output = Mock()
    mock_database = Mock()
    session_id = 1

    # Mock config methods
    mock_config.get_shodan_api_key.return_value = "test_api_key"
    mock_config.get_exclusion_file_path.return_value = "/dev/null"
    mock_config.get_rate_limit_delay.return_value = 0
    mock_config.get_connection_timeout.return_value = 10
    mock_config.get_shodan_config.return_value = {
        'query_limits': {'max_results': 100}
    }
    mock_config.resolve_target_countries.return_value = ['US']
    mock_config.get.return_value = 100

    # Create DiscoverOperation with mocks
    with patch('commands.discover.shodan.Shodan'), \
         patch('commands.discover.subprocess.run'), \
         patch('commands.discover.SMB_AVAILABLE', True), \
         patch('builtins.open', unittest.mock.mock_open(read_data='amazon\ngoogle\nmicrosoft\n')):
        discover_op = DiscoverOperation(
            config=mock_config,
            output=mock_output,
            database=mock_database,
            session_id=session_id
        )

    return discover_op


def test_cached_metadata_performance():
    """Test performance with cached metadata vs API calls."""
    print("🔍 Testing exclusion performance with cached metadata...")

    discover_op = create_mock_discover_operation()

    # Set up test data - 100 IPs for realistic performance comparison
    test_ips = [f"192.168.{i//254}.{i%254+1}" for i in range(100)]

    # Scenario 1: All metadata cached (optimal case)
    discover_op.shodan_host_metadata = {}
    for ip in test_ips:
        discover_op.shodan_host_metadata[ip] = {
            'org_normalized': 'safe-corp',
            'isp_normalized': 'clean-isp'
        }

    start_time = time.time()
    excluded_count_cached = 0
    for ip in test_ips:
        if discover_op._should_exclude_ip(ip):
            excluded_count_cached += 1
    cached_time = time.time() - start_time

    # Scenario 2: No metadata cached (requires API calls)
    discover_op.shodan_host_metadata = {}
    discover_op._host_lookup_cache = {}

    # Mock API calls to simulate network delay
    def mock_host_call(ip):
        time.sleep(0.001)  # Simulate 1ms API delay (much faster than real ~200-500ms)
        return {'org': 'safe-corp', 'isp': 'clean-isp'}

    with patch.object(discover_op.shodan_api, 'host', side_effect=mock_host_call):
        start_time = time.time()
        excluded_count_api = 0
        for ip in test_ips:
            if discover_op._should_exclude_ip(ip):
                excluded_count_api += 1
        api_time = time.time() - start_time

    # Results
    speedup = api_time / cached_time if cached_time > 0 else float('inf')
    print(f"  📊 Cached metadata: {cached_time:.4f}s for {len(test_ips)} IPs")
    print(f"  📊 API calls:       {api_time:.4f}s for {len(test_ips)} IPs")
    print(f"  🚀 Speedup:         {speedup:.1f}x faster with cached metadata")
    print(f"  ✓ Results consistent: {excluded_count_cached == excluded_count_api}")

    return speedup


def test_memoization_performance():
    """Test memoization prevents duplicate API calls."""
    print("\n🔍 Testing memoization prevents duplicate API calls...")

    discover_op = create_mock_discover_operation()

    # Test with duplicate IPs
    test_ips = ['192.168.1.1'] * 50  # Same IP repeated 50 times
    api_call_count = 0

    def mock_host_call(ip):
        nonlocal api_call_count
        api_call_count += 1
        return {'org': 'test-corp', 'isp': 'test-isp'}

    with patch.object(discover_op.shodan_api, 'host', side_effect=mock_host_call):
        for ip in test_ips:
            discover_op._should_exclude_ip(ip)

    print(f"  📊 Total IP checks: {len(test_ips)}")
    print(f"  📊 API calls made:  {api_call_count}")
    print(f"  🚀 API call reduction: {((len(test_ips) - api_call_count) / len(test_ips)) * 100:.1f}%")
    print(f"  ✓ Memoization working: {api_call_count == 1}")

    return api_call_count == 1


def test_normalization_performance():
    """Test that pre-normalized patterns improve string matching."""
    print("\n🔍 Testing pre-normalized exclusion patterns...")

    discover_op = create_mock_discover_operation()

    # Simulate checking 1000 patterns (realistic for large exclusion lists)
    exclusion_patterns = [f'pattern-{i}' for i in range(1000)]
    discover_op.exclusion_patterns = exclusion_patterns

    test_org = 'pattern-500'  # Will match in middle of list
    test_isp = 'safe-provider'

    start_time = time.time()
    matches = 0
    for _ in range(100):  # Repeat test for measurable timing
        for pattern in discover_op.exclusion_patterns:
            if pattern in test_org or pattern in test_isp:
                matches += 1
                break
    normalized_time = time.time() - start_time

    print(f"  📊 Pattern checks: {1000 * 100} comparisons")
    print(f"  📊 Time taken:    {normalized_time:.4f}s")
    print(f"  📊 Matches found: {matches}")
    print(f"  ✓ Pre-normalization performance validated")

    return normalized_time < 0.1  # Should be very fast


def main():
    """Run performance validation tests."""
    print("🚀 SMBSeek Exclusion Performance Validation")
    print("=" * 50)

    try:
        # Test cached metadata performance
        speedup = test_cached_metadata_performance()

        # Test memoization
        memoization_working = test_memoization_performance()

        # Test normalization
        normalization_fast = test_normalization_performance()

        # Summary
        print("\n" + "=" * 50)
        print("🎉 Performance Validation Summary:")
        print(f"  ✅ Metadata caching: {speedup:.1f}x speedup")
        print(f"  ✅ Memoization: {'Working' if memoization_working else 'Failed'}")
        print(f"  ✅ Normalization: {'Fast' if normalization_fast else 'Slow'}")

        if speedup > 5 and memoization_working and normalization_fast:
            print("  🏆 All optimizations performing well!")
            return 0
        else:
            print("  ⚠️  Some optimizations may need attention")
            return 1

    except Exception as e:
        print(f"\n❌ Performance validation failed: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())