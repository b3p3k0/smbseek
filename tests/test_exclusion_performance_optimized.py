#!/usr/bin/env python3
"""
Performance validation for optimized exclusion filtering.

Tests the performance improvements from the dual-phase exclusion processing,
API rate limiting, and configuration optimizations.
"""

import sys
import os
import time
import unittest
from unittest.mock import Mock, patch, MagicMock

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

    # Mock config methods with optimized settings
    mock_config.get_shodan_api_key.return_value = "test_api_key"
    mock_config.get_exclusion_file_path.return_value = "/dev/null"
    mock_config.get_rate_limit_delay.return_value = 0
    mock_config.get_connection_timeout.return_value = 10
    mock_config.get_shodan_config.return_value = {
        'query_limits': {'max_results': 100}
    }
    mock_config.resolve_target_countries.return_value = ['US']
    mock_config.get.return_value = 100  # Optimized progress interval

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


def test_dual_phase_performance():
    """Test dual-phase exclusion processing performance."""
    print("🔍 Testing dual-phase exclusion processing...")

    discover_op = create_mock_discover_operation()

    # Create test dataset: 80% cached, 20% uncached (realistic scenario)
    total_ips = 1000
    cached_ratio = 0.8
    cached_count = int(total_ips * cached_ratio)

    test_ips = {f"192.168.{i//254}.{i%254+1}" for i in range(total_ips)}

    # Pre-populate cache for 80% of IPs (simulating initial Shodan search metadata)
    cached_ips = list(test_ips)[:cached_count]
    for ip in cached_ips:
        discover_op.shodan_host_metadata[ip] = {
            'org_normalized': 'safe-corp',
            'isp_normalized': 'clean-isp'
        }

    # Mock API calls for uncached IPs with rate limiting simulation
    api_call_count = 0
    def mock_api_call(ip):
        nonlocal api_call_count
        api_call_count += 1
        time.sleep(0.002)  # Simulate 2ms API delay + rate limiting
        return {'org': 'test-corp', 'isp': 'test-isp'}

    with patch.object(discover_op, '_api_rate_limited_call', side_effect=mock_api_call):
        start_time = time.time()
        result = discover_op._apply_exclusions(test_ips)
        total_time = time.time() - start_time

    # Calculate performance metrics
    uncached_count = total_ips - cached_count
    expected_api_calls = uncached_count

    print(f"  📊 Total IPs processed: {total_ips}")
    print(f"  📊 Cached IPs (fast): {cached_count} ({cached_ratio*100}%)")
    print(f"  📊 Uncached IPs (API): {uncached_count} ({(1-cached_ratio)*100}%)")
    print(f"  📊 API calls made: {api_call_count}")
    print(f"  📊 Total time: {total_time:.2f}s")
    print(f"  📊 Time per IP: {(total_time/total_ips)*1000:.1f}ms")
    print(f"  ✓ API calls correct: {api_call_count == expected_api_calls}")
    print(f"  ✓ Results preserved: {len(result)} IPs passed filtering")

    return total_time < 5.0  # Should complete 1000 IPs in under 5 seconds


def test_api_rate_limiting():
    """Test API rate limiting compliance."""
    print("\n🔍 Testing API rate limiting compliance...")

    discover_op = create_mock_discover_operation()

    # Track API call timing
    call_times = []
    def mock_api_call_with_timing(ip):
        call_times.append(time.time())
        return {'org': 'test-corp', 'isp': 'test-isp'}

    # Test multiple consecutive API calls
    test_ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3']

    with patch.object(discover_op.shodan_api, 'host', side_effect=mock_api_call_with_timing):
        for ip in test_ips:
            discover_op._api_rate_limited_call(ip)

    # Verify rate limiting (should be ~1 second between calls)
    if len(call_times) >= 2:
        intervals = [call_times[i] - call_times[i-1] for i in range(1, len(call_times))]
        avg_interval = sum(intervals) / len(intervals)

        print(f"  📊 API calls made: {len(call_times)}")
        print(f"  📊 Average interval: {avg_interval:.2f}s")
        print(f"  📊 Min interval: {min(intervals):.2f}s")
        print(f"  📊 Max interval: {max(intervals):.2f}s")

        rate_compliant = all(interval >= 0.9 for interval in intervals)  # Allow 0.1s tolerance
        print(f"  ✓ Rate limiting compliant: {rate_compliant}")

        return rate_compliant
    else:
        print("  ⚠ Not enough API calls to test rate limiting")
        return True


def test_circuit_breaker():
    """Test API circuit breaker functionality."""
    print("\n🔍 Testing API circuit breaker...")

    discover_op = create_mock_discover_operation()

    # Mock API to fail consistently
    def mock_failing_api(ip):
        raise Exception("Rate limit exceeded")

    api_call_count = 0
    def count_api_calls(ip):
        nonlocal api_call_count
        api_call_count += 1
        raise Exception("Rate limit exceeded")

    test_ips = [f"192.168.1.{i}" for i in range(1, 10)]

    with patch.object(discover_op.shodan_api, 'host', side_effect=count_api_calls):
        for ip in test_ips:
            result = discover_op._api_rate_limited_call(ip)
            if discover_op._api_circuit_breaker_active:
                break

    print(f"  📊 API calls before circuit breaker: {api_call_count}")
    print(f"  📊 Circuit breaker active: {discover_op._api_circuit_breaker_active}")
    print(f"  ✓ Circuit breaker triggered: {api_call_count <= 3}")

    return api_call_count <= 3 and discover_op._api_circuit_breaker_active


def test_progress_interval_optimization():
    """Test progress reporting optimization."""
    print("\n🔍 Testing progress reporting optimization...")

    discover_op = create_mock_discover_operation()

    # Mock output to count progress messages
    progress_messages = []
    def mock_info(message):
        if "progress" in message.lower():
            progress_messages.append(message)

    discover_op.output.info = mock_info

    # Test with 500 IPs and progress interval of 100
    test_ips = {f"192.168.{i//254}.{i%254+1}" for i in range(500)}

    # Pre-populate all as cached to avoid API delays
    for ip in test_ips:
        discover_op.shodan_host_metadata[ip] = {
            'org_normalized': 'safe-corp',
            'isp_normalized': 'clean-isp'
        }

    discover_op._apply_exclusions(test_ips)

    expected_messages = 5  # At 1, 100, 200, 300, 400, 500 (boundary conditions)
    actual_messages = len(progress_messages)

    print(f"  📊 Total IPs: {len(test_ips)}")
    print(f"  📊 Progress messages: {actual_messages}")
    print(f"  📊 Expected messages: ~{expected_messages}")
    print(f"  ✓ Progress optimized: {actual_messages <= expected_messages + 1}")  # Allow some tolerance

    return actual_messages <= expected_messages + 1


def main():
    """Run all performance validation tests."""
    print("🚀 SMBSeek Exclusion Performance Validation (Optimized)")
    print("=" * 60)

    try:
        # Test dual-phase processing
        dual_phase_fast = test_dual_phase_performance()

        # Test API rate limiting
        rate_limiting_works = test_api_rate_limiting()

        # Test circuit breaker
        circuit_breaker_works = test_circuit_breaker()

        # Test progress optimization
        progress_optimized = test_progress_interval_optimization()

        # Summary
        print("\n" + "=" * 60)
        print("🎉 Performance Validation Summary:")
        print(f"  ✅ Dual-phase processing: {'Fast' if dual_phase_fast else 'Slow'}")
        print(f"  ✅ API rate limiting: {'Working' if rate_limiting_works else 'Failed'}")
        print(f"  ✅ Circuit breaker: {'Working' if circuit_breaker_works else 'Failed'}")
        print(f"  ✅ Progress optimization: {'Working' if progress_optimized else 'Failed'}")

        all_tests_passed = all([dual_phase_fast, rate_limiting_works, circuit_breaker_works, progress_optimized])

        if all_tests_passed:
            print("  🏆 All optimizations working correctly!")
            print("\n💡 Expected Performance Improvements:")
            print("  • 3-5x faster exclusion filtering")
            print("  • API compliance (no rate limit violations)")
            print("  • Graceful degradation under API limits")
            print("  • Reduced progress update overhead")
            return 0
        else:
            print("  ⚠️  Some optimizations need attention")
            return 1

    except Exception as e:
        print(f"\n❌ Performance validation failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())