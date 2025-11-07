#!/usr/bin/env python3
"""
Unit tests for SMBSeek access command concurrency functionality.

Tests the concurrent host processing with ThreadPoolExecutor, configuration
validation, error handling, and deterministic result ordering.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock
import time
import threading

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.access import AccessOperation
from shared.config import SMBSeekConfig


class TestAccessConcurrency(unittest.TestCase):
    """Test cases for access operation concurrency."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock components for AccessOperation
        self.mock_config = Mock()
        self.mock_output = Mock()
        self.mock_database = Mock()
        self.session_id = 1

        # Create AccessOperation with mocks
        self.access_op = AccessOperation(
            config=self.mock_config,
            output=self.mock_output,
            database=self.mock_database,
            session_id=self.session_id
        )

    def test_config_validation_positive_values(self):
        """Test config validation accepts valid positive values."""
        # Create actual config with different max_concurrent_hosts values
        test_cases = [1, 2, 5, 10, 100]

        for value in test_cases:
            config_data = {
                "access": {"max_concurrent_hosts": value},
                "output": {"colors_enabled": True}
            }
            config = SMBSeekConfig()
            config.config = config_data

            result = config.get_max_concurrent_hosts()
            self.assertEqual(result, value, f"Should return {value} for valid input")

    def test_config_validation_invalid_values(self):
        """Test config validation falls back to 1 for invalid values."""
        invalid_cases = [0, -1, -10, "invalid", None, 1.5, []]

        for invalid_value in invalid_cases:
            config_data = {
                "access": {"max_concurrent_hosts": invalid_value},
                "output": {"colors_enabled": True}
            }
            config = SMBSeekConfig()
            config.config = config_data

            result = config.get_max_concurrent_hosts()
            self.assertEqual(result, 1, f"Should fallback to 1 for invalid value: {invalid_value}")

    def test_config_validation_missing_section(self):
        """Test config validation falls back to 1 when access section missing."""
        config_data = {"output": {"colors_enabled": True}}
        config = SMBSeekConfig()
        config.config = config_data

        result = config.get_max_concurrent_hosts()
        self.assertEqual(result, 1, "Should fallback to 1 when access section missing")

    def test_concurrent_execution_with_mocking(self):
        """Test concurrent execution processes all hosts with correct call count."""
        with patch('commands.access.SMB_AVAILABLE', True), \
             patch('commands.access.get_standard_timestamp') as mock_timestamp:

            mock_timestamp.return_value = "2025-10-04T10:00:00"

            # Set up config to return 2 concurrent hosts
            self.mock_config.get_max_concurrent_hosts.return_value = 2

            # Create test host data
            test_hosts = [
                {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/guest'},
                {'ip_address': '192.168.1.2', 'country': 'US', 'auth_method': 'anonymous'},
                {'ip_address': '192.168.1.3', 'country': 'CA', 'auth_method': 'guest/blank'},
                {'ip_address': '192.168.1.4', 'country': 'GB', 'auth_method': 'guest/guest'}
            ]

            # Mock database method
            self.mock_database.get_authenticated_hosts.return_value = test_hosts

            # Track process_target calls to verify concurrency and ordering
            call_count = 0
            call_order = []
            call_times = []
            call_lock = threading.Lock()

            def mock_process_target(host, host_position=None):
                nonlocal call_count
                with call_lock:
                    call_count += 1
                    call_order.append(host['ip_address'])
                    call_times.append(time.time())

                # Simulate some processing time to test concurrency
                time.sleep(0.1)

                return {
                    'ip_address': host['ip_address'],
                    'country': host['country'],
                    'auth_method': host['auth_method'],
                    'timestamp': mock_timestamp.return_value,
                    'shares_found': ['share1', 'share2'],
                    'accessible_shares': ['share1'],
                    'share_details': [{'share_name': 'share1', 'accessible': True}]
                }

            # Mock _save_and_summarize_results
            self.access_op._save_and_summarize_results = Mock(return_value=(2, 4, []))

            # Patch process_target method
            with patch.object(self.access_op, 'process_target', side_effect=mock_process_target):
                result = self.access_op.execute(target_ips={'192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'})

            # Verify all hosts were processed
            self.assertEqual(call_count, 4, "Should call process_target exactly 4 times")

            # Verify results maintain deterministic order
            self.assertEqual(len(self.access_op.results), 4, "Should have 4 results")
            result_ips = [r['ip_address'] for r in self.access_op.results]
            expected_ips = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']
            self.assertEqual(result_ips, expected_ips, "Results should maintain original host order")

            # Verify concurrent execution (calls should overlap in time)
            if len(call_times) >= 2:
                time_diff = call_times[1] - call_times[0]
                self.assertLess(time_diff, 0.05, "Calls should start concurrently (within 50ms)")

    def test_pool_size_clamping(self):
        """Test pool size is properly clamped to available hosts."""
        with patch('commands.access.SMB_AVAILABLE', True):
            # Test case: more workers than hosts
            self.mock_config.get_max_concurrent_hosts.return_value = 10

            test_hosts = [
                {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/guest'},
                {'ip_address': '192.168.1.2', 'country': 'US', 'auth_method': 'anonymous'}
            ]

            self.mock_database.get_authenticated_hosts.return_value = test_hosts

            # Mock process_target to return simple results
            def mock_process_target(host, host_position=None):
                return {
                    'ip_address': host['ip_address'],
                    'country': host['country'],
                    'auth_method': host['auth_method'],
                    'timestamp': '2025-10-04T10:00:00',
                    'shares_found': [],
                    'accessible_shares': [],
                    'share_details': []
                }

            self.access_op._save_and_summarize_results = Mock(return_value=(0, 0, []))

            with patch.object(self.access_op, 'process_target', side_effect=mock_process_target):
                # Should not raise any errors despite having more workers than hosts
                result = self.access_op.execute(target_ips={'192.168.1.1', '192.168.1.2'})

            # Verify execution completed successfully
            self.assertEqual(len(self.access_op.results), 2, "Should process both hosts")

    def test_empty_host_list_handling(self):
        """Test graceful handling of empty host list."""
        with patch('commands.access.SMB_AVAILABLE', True):
            self.mock_config.get_max_concurrent_hosts.return_value = 5
            self.mock_database.get_authenticated_hosts.return_value = []

            result = self.access_op.execute(target_ips=set())

            # Should return empty result without errors
            self.assertEqual(result.accessible_hosts, 0)
            self.assertEqual(result.accessible_shares, 0)
            self.assertEqual(result.share_details, [])

    def test_exception_handling_maintains_structure(self):
        """Test that exceptions in individual hosts don't crash entire operation."""
        with patch('commands.access.SMB_AVAILABLE', True), \
             patch('commands.access.get_standard_timestamp') as mock_timestamp:

            mock_timestamp.return_value = "2025-10-04T10:00:00"

            self.mock_config.get_max_concurrent_hosts.return_value = 2

            test_hosts = [
                {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/guest'},
                {'ip_address': '192.168.1.2', 'country': 'US', 'auth_method': 'anonymous'},
                {'ip_address': '192.168.1.3', 'country': 'CA', 'auth_method': 'guest/guest'}
            ]

            self.mock_database.get_authenticated_hosts.return_value = test_hosts

            def mock_process_target(host, host_position=None):
                if host['ip_address'] == '192.168.1.2':
                    raise Exception("Simulated processing error")

                return {
                    'ip_address': host['ip_address'],
                    'country': host['country'],
                    'auth_method': host['auth_method'],
                    'timestamp': mock_timestamp.return_value,
                    'shares_found': ['share1'],
                    'accessible_shares': ['share1'],
                    'share_details': [{'share_name': 'share1', 'accessible': True}]
                }

            self.access_op._save_and_summarize_results = Mock(return_value=(2, 2, []))

            with patch.object(self.access_op, 'process_target', side_effect=mock_process_target):
                result = self.access_op.execute(target_ips={'192.168.1.1', '192.168.1.2', '192.168.1.3'})

            # Verify all results are present
            self.assertEqual(len(self.access_op.results), 3, "Should have 3 results including error")

            # Verify error result structure
            error_result = self.access_op.results[1]  # Second host (index 1) should have error
            self.assertEqual(error_result['ip_address'], '192.168.1.2')
            self.assertIn('error', error_result)
            self.assertEqual(error_result['shares_found'], [])
            self.assertEqual(error_result['accessible_shares'], [])
            self.assertEqual(error_result['share_details'], [])

            # Verify successful results are unaffected
            success_result = self.access_op.results[0]
            self.assertEqual(success_result['ip_address'], '192.168.1.1')
            self.assertNotIn('error', success_result)

    def test_thread_safe_output_no_exceptions(self):
        """Smoke test to verify thread-safe output doesn't throw exceptions."""
        with patch('commands.access.SMB_AVAILABLE', True):
            self.mock_config.get_max_concurrent_hosts.return_value = 3

            test_hosts = [
                {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/guest'},
                {'ip_address': '192.168.1.2', 'country': 'US', 'auth_method': 'anonymous'}
            ]

            self.mock_database.get_authenticated_hosts.return_value = test_hosts

            # Create a real output manager to test thread safety
            from shared.config import SMBSeekConfig
            from shared.output import SMBSeekOutput

            config = SMBSeekConfig()
            real_output = SMBSeekOutput(config, quiet=False, verbose=True, no_colors=True)

            # Replace mock output with real one for this test
            self.access_op.output = real_output

            def mock_process_target(host, host_position=None):
                # Call various output methods from different threads
                real_output.info(f"Processing {host['ip_address']}")
                real_output.success(f"Connected to {host['ip_address']}")
                real_output.warning(f"Warning for {host['ip_address']}")
                real_output.error(f"Error for {host['ip_address']}")

                return {
                    'ip_address': host['ip_address'],
                    'country': host['country'],
                    'auth_method': host['auth_method'],
                    'timestamp': '2025-10-04T10:00:00',
                    'shares_found': [],
                    'accessible_shares': [],
                    'share_details': []
                }

            self.access_op._save_and_summarize_results = Mock(return_value=(0, 0, []))

            # Should not raise any threading-related exceptions
            with patch.object(self.access_op, 'process_target', side_effect=mock_process_target):
                try:
                    result = self.access_op.execute(target_ips={'192.168.1.1', '192.168.1.2'})
                except Exception as e:
                    self.fail(f"Thread-safe output test raised exception: {e}")


class TestConfigValidationIntegration(unittest.TestCase):
    """Integration tests for configuration validation."""

    def test_default_config_values(self):
        """Test that default configuration includes access.max_concurrent_hosts."""
        config = SMBSeekConfig()

        # Should have access section with max_concurrent_hosts defaulting to 1
        access_config = config.get("access")
        self.assertIsNotNone(access_config, "Should have access configuration section")
        self.assertGreaterEqual(access_config.get("max_concurrent_hosts", 0), 1,
                                "Configured concurrency should be at least 1")

        # Getter method should reflect configured value
        self.assertGreaterEqual(config.get_max_concurrent_hosts(), 1,
                                "Getter should return a positive concurrency value")


if __name__ == '__main__':
    # Run tests without requiring network access
    print("Running SMBSeek access concurrency tests...")
    print("Note: These tests use mock data and do not make network connections.")

    unittest.main(verbosity=2)
