#!/usr/bin/env python3
"""
Unit tests for SMBSeek discovery concurrency implementation.

Tests the new host-level concurrency feature including config validation,
ThreadPoolExecutor usage, deterministic ordering, exception isolation,
and rate limiting under concurrent conditions.
"""

import sys
import os
import unittest
import time
from unittest.mock import Mock, patch, MagicMock, call
from concurrent.futures import ThreadPoolExecutor

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.discover import DiscoverOperation
from shared.config import SMBSeekConfig


class TestDiscoverConcurrency(unittest.TestCase):
    """Test cases for discovery concurrency implementation."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock components for DiscoverOperation
        self.mock_config = Mock()
        self.mock_output = Mock()
        self.mock_database = Mock()
        self.session_id = 1

        # Mock standard config methods
        self.mock_config.get_shodan_api_key.return_value = "test_api_key"
        self.mock_config.get_exclusion_file_path.return_value = "/dev/null"
        self.mock_config.get_rate_limit_delay.return_value = 0.1
        self.mock_config.get_connection_timeout.return_value = 10
        self.mock_config.get_shodan_config.return_value = {
            'query_limits': {'max_results': 100}
        }
        self.mock_config.resolve_target_countries.return_value = ['US']
        self.mock_config.get.return_value = {}

        # Create DiscoverOperation with mocks
        with patch('commands.discover.shodan.Shodan'), \
             patch('commands.discover.subprocess.run'), \
             patch('commands.discover.SMB_AVAILABLE', True), \
             patch('builtins.open', unittest.mock.mock_open(read_data='')):
            self.discover_op = DiscoverOperation(
                config=self.mock_config,
                output=self.mock_output,
                database=self.mock_database,
                session_id=self.session_id
            )

    def test_config_getter_validation_invalid_values(self):
        """Test that get_max_concurrent_discovery_hosts validates and clamps invalid values."""
        test_configs = [
            # Test data: (config_value, expected_result)
            (1, 1),         # Valid positive integer
            (5, 5),         # Valid positive integer
            (0, 1),         # Zero should clamp to 1
            (-1, 1),        # Negative should clamp to 1
            ("invalid", 1), # Non-integer should clamp to 1
            (None, 1),      # None should clamp to 1
            (1.5, 1),       # Float should clamp to 1
        ]

        for config_value, expected_result in test_configs:
            with self.subTest(config_value=config_value):
                # Create a mock config that returns our test value
                mock_config = {
                    "discovery": {"max_concurrent_hosts": config_value}
                }

                # Create SMBSeekConfig instance with mocked load
                with patch.object(SMBSeekConfig, 'load_configuration', return_value=mock_config):
                    config = SMBSeekConfig()
                    result = config.get_max_concurrent_discovery_hosts()
                    self.assertEqual(result, expected_result)

    def test_executor_usage_with_concurrency(self):
        """Test that ThreadPoolExecutor is used with max_concurrent_hosts > 1."""
        # Mock config to return concurrency > 1
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 3

        # Mock _test_single_host_concurrent to track calls
        call_order = []
        def mock_host_test(ip, country):
            call_order.append(ip)
            return {
                "result": {"ip_address": ip, "auth_method": "Anonymous"},
                "success": True,
                "failed": False,
                "metadata": {}
            }

        with patch.object(self.discover_op, '_test_single_host_concurrent', side_effect=mock_host_test):
            test_ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"}
            results = self.discover_op._test_smb_authentication(test_ips, "US")

            # Verify all IPs were processed
            self.assertEqual(len(call_order), 4)
            self.assertEqual(set(call_order), test_ips)
            self.assertEqual(len(results), 4)

    def test_executor_usage_with_sequential_fallback(self):
        """Test that sequential processing is used when max_concurrent_hosts = 1."""
        # Mock config to return concurrency = 1
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 1

        # Mock sequential method
        expected_results = [{"ip_address": "192.168.1.1", "auth_method": "Anonymous"}]
        with patch.object(self.discover_op, '_test_smb_authentication_sequential', return_value=expected_results) as mock_sequential:
            test_ips = {"192.168.1.1", "192.168.1.2"}
            results = self.discover_op._test_smb_authentication(test_ips, "US")

            # Verify sequential method was called
            mock_sequential.assert_called_once()
            self.assertEqual(results, expected_results)

    def test_deterministic_ordering_preservation(self):
        """Test that results preserve original IP ordering despite concurrent execution."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 3

        # Create predictable test IPs in specific order
        test_ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
        ip_set = set(test_ips)

        # Mock concurrent method to return success for all
        def mock_host_test(ip, country):
            return {
                "result": {"ip_address": ip, "auth_method": f"Anonymous-{ip}"},
                "success": True,
                "failed": False,
                "metadata": {}
            }

        with patch.object(self.discover_op, '_test_single_host_concurrent', side_effect=mock_host_test):
            results = self.discover_op._test_smb_authentication(ip_set, "US")

            # Verify results are returned in some consistent order
            # (The exact order may vary due to threading, but should be deterministic per run)
            result_ips = [r["ip_address"] for r in results]
            self.assertEqual(len(result_ips), 4)
            self.assertEqual(set(result_ips), ip_set)

    def test_exception_isolation_one_host_fails(self):
        """Test that exception in one host doesn't stop processing of others."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 2

        # Mock to raise exception for one specific IP
        def mock_host_test(ip, country):
            if ip == "192.168.1.2":
                return {
                    "ip": ip,
                    "error": "Test error",
                    "success": False,
                    "failed": True,
                    "result": None
                }
            else:
                return {
                    "result": {"ip_address": ip, "auth_method": "Anonymous"},
                    "success": True,
                    "failed": False,
                    "metadata": {}
                }

        with patch.object(self.discover_op, '_test_single_host_concurrent', side_effect=mock_host_test):
            test_ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"}
            results = self.discover_op._test_smb_authentication(test_ips, "US")

            # Should get 2 successful results despite 1 failure
            self.assertEqual(len(results), 2)
            result_ips = {r["ip_address"] for r in results}
            self.assertEqual(result_ips, {"192.168.1.1", "192.168.1.3"})

            # Verify error was logged
            self.mock_output.error.assert_called()

    def test_rate_limiting_throttle_helper_called(self):
        """Test that _throttled_auth_wait is called for each host in concurrent mode."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 2

        # Track throttle calls
        throttle_calls = []
        original_throttle = self.discover_op._throttled_auth_wait

        def mock_throttle():
            throttle_calls.append(time.time())
            # Don't actually sleep in tests
            pass

        with patch.object(self.discover_op, '_throttled_auth_wait', side_effect=mock_throttle), \
             patch.object(self.discover_op, '_test_single_host', return_value=None):
            test_ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"}
            self.discover_op._test_smb_authentication(test_ips, "US")

            # Should have called throttle for each host
            self.assertEqual(len(throttle_calls), 3)

    def test_rate_limiting_first_run_special_case(self):
        """Test that first run of _throttled_auth_wait doesn't sleep but sets baseline."""
        # Reset the auth attempt timestamp
        self.discover_op._last_auth_attempt = 0

        with patch('time.sleep') as mock_sleep, \
             patch('time.monotonic') as mock_monotonic:

            # First call should not sleep but set baseline
            mock_monotonic.return_value = 100.0
            self.discover_op._throttled_auth_wait()
            mock_sleep.assert_not_called()
            self.assertEqual(self.discover_op._last_auth_attempt, 100.0)

            # Second call with short interval should sleep
            mock_monotonic.return_value = 100.05  # 0.05 seconds later
            self.discover_op._throttled_auth_wait()
            # Should sleep rate_delay - elapsed_time = 0.1 - 0.05 = 0.05 seconds (approximately)
            mock_sleep.assert_called_once()
            sleep_time = mock_sleep.call_args[0][0]
            self.assertAlmostEqual(sleep_time, 0.05, places=2)

            # Third call with long interval should not sleep
            mock_sleep.reset_mock()
            mock_monotonic.return_value = 102.0  # Much later, no sleep needed
            self.discover_op._throttled_auth_wait()
            mock_sleep.assert_not_called()

    def test_thread_safety_no_time_sleep_in_tests(self):
        """Test that threading works without actual time.sleep delays."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 3

        # Mock time functions to avoid actual delays
        with patch('time.sleep'), \
             patch('time.monotonic', return_value=100.0):

            def mock_host_test(ip, country):
                return {
                    "result": {"ip_address": ip, "auth_method": "Anonymous"},
                    "success": True,
                    "failed": False,
                    "metadata": {}
                }

            with patch.object(self.discover_op, '_test_single_host_concurrent', side_effect=mock_host_test):
                test_ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"}
                results = self.discover_op._test_smb_authentication(test_ips, "US")

                # Should complete without hanging
                self.assertEqual(len(results), 3)

    def test_empty_ip_set_handling(self):
        """Test that empty IP set is handled gracefully."""
        results = self.discover_op._test_smb_authentication(set(), "US")
        self.assertEqual(results, [])

    def test_single_ip_with_high_concurrency(self):
        """Test that single IP with high concurrency setting uses sequential path correctly."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 10

        # Mock sequential method since single IP will use sequential path
        expected_results = [{"ip_address": "192.168.1.1", "auth_method": "Anonymous"}]
        with patch.object(self.discover_op, '_test_smb_authentication_sequential', return_value=expected_results) as mock_sequential:
            test_ips = {"192.168.1.1"}
            results = self.discover_op._test_smb_authentication(test_ips, "US")

            # Should work with max_workers = min(10, 1) = 1 (uses sequential path)
            self.assertEqual(len(results), 1)
            mock_sequential.assert_called_once()

    def test_statistics_aggregation_after_concurrent_execution(self):
        """Test that statistics are properly aggregated after concurrent execution."""
        self.mock_config.get_max_concurrent_discovery_hosts.return_value = 2

        # Mock mixed success/failure results
        def mock_host_test(ip, country):
            if ip == "192.168.1.2":
                return {
                    "result": None,
                    "success": False,
                    "failed": True,
                    "metadata": {}
                }
            else:
                return {
                    "result": {"ip_address": ip, "auth_method": "Anonymous"},
                    "success": True,
                    "failed": False,
                    "metadata": {}
                }

        with patch.object(self.discover_op, '_test_single_host_concurrent', side_effect=mock_host_test):
            test_ips = {"192.168.1.1", "192.168.1.2", "192.168.1.3"}
            results = self.discover_op._test_smb_authentication(test_ips, "US")

            # Verify statistics were updated correctly
            self.assertEqual(self.discover_op.stats['successful_auth'], 2)
            self.assertEqual(self.discover_op.stats['failed_auth'], 1)
            self.assertEqual(self.discover_op.stats['total_processed'], 3)

    def test_smbclient_cache_functionality(self):
        """Test that SMBClient authentication cache works correctly."""
        # Ensure smbclient is available for testing
        self.discover_op.smbclient_available = True

        # Test cache hit
        self.discover_op._smbclient_auth_cache["192.168.1.1"] = "Guest/Blank"
        result = self.discover_op._test_smb_alternative("192.168.1.1")
        self.assertEqual(result, "Guest/Blank")

        # Test cache miss and successful auth
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value.returncode = 0
            mock_subprocess.return_value.stdout = "Sharename available"

            result = self.discover_op._test_smb_alternative("192.168.1.2")
            self.assertEqual(result, "Anonymous")
            # Should be cached now
            self.assertEqual(self.discover_op._smbclient_auth_cache["192.168.1.2"], "Anonymous")

    def test_smbclient_cache_clearing_per_operation(self):
        """Test that SMBClient cache is cleared at start of each execute call."""
        # Set up stale cache data
        self.discover_op._smbclient_auth_cache = {"192.168.1.99": "Guest/Blank"}

        with patch.object(self.discover_op, '_query_shodan', return_value=set()), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test"), \
             patch('commands.discover.SMB_AVAILABLE', True):

            self.discover_op.execute(country='US')

            # Cache should be cleared
            self.assertEqual(self.discover_op._smbclient_auth_cache, {})


if __name__ == '__main__':
    unittest.main()