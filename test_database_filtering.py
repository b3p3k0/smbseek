#!/usr/bin/env python3
"""
Unit tests for SMBSeek database filtering functionality.

Tests the get_authenticated_hosts method with IP filtering to ensure
correct behavior and prevent regression of filtering logic.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.database import SMBSeekWorkflowDatabase


class TestDatabaseFiltering(unittest.TestCase):
    """Test cases for database filtering logic."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock components for SMBSeekWorkflowDatabase
        self.mock_config = Mock()
        self.mock_config.get_database_path.return_value = ":memory:"

        # Mock the database manager and its execute_query method
        with patch('shared.database.DatabaseManager') as mock_db_manager_class:
            mock_db_manager = Mock()
            mock_db_manager_class.return_value = mock_db_manager

            # Create workflow database with mocked dependencies
            self.workflow_db = SMBSeekWorkflowDatabase(self.mock_config, verbose=False)
            self.workflow_db.db_manager = mock_db_manager

            # Store reference to mock for easier access in tests
            self.mock_db_manager = mock_db_manager

    def test_get_authenticated_hosts_no_filter(self):
        """Test get_authenticated_hosts with no IP filter returns all hosts."""
        # Mock database response with two hosts
        mock_rows = [
            {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/blank',
             'last_seen': '2023-01-01 10:00:00', 'accessible_shares': 'share1,share2'},
            {'ip_address': '192.168.1.2', 'country': 'CA', 'auth_method': 'anonymous',
             'last_seen': '2023-01-01 11:00:00', 'accessible_shares': 'share3'}
        ]
        self.mock_db_manager.execute_query.return_value = mock_rows

        # Call method with no IP filter
        result = self.workflow_db.get_authenticated_hosts(ip_filter=None)

        # Verify all hosts returned and shares properly parsed
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]['ip_address'], '192.168.1.1')
        self.assertEqual(result[0]['accessible_shares'], ['share1', 'share2'])
        self.assertEqual(result[1]['ip_address'], '192.168.1.2')
        self.assertEqual(result[1]['accessible_shares'], ['share3'])

        # Verify query called with empty params (no IP filter)
        self.mock_db_manager.execute_query.assert_called_once()
        args, kwargs = self.mock_db_manager.execute_query.call_args
        self.assertEqual(args[1], ())  # Empty params tuple

    def test_get_authenticated_hosts_with_specific_ip(self):
        """Test get_authenticated_hosts with specific IP filter returns only matching host."""
        # Mock database response with one matching host
        mock_rows = [
            {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/blank',
             'last_seen': '2023-01-01 10:00:00', 'accessible_shares': 'share1,share2'}
        ]
        self.mock_db_manager.execute_query.return_value = mock_rows

        # Call method with specific IP filter
        result = self.workflow_db.get_authenticated_hosts(ip_filter=['192.168.1.1'])

        # Verify only matching host returned
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip_address'], '192.168.1.1')
        self.assertEqual(result[0]['accessible_shares'], ['share1', 'share2'])

        # Verify query called with IP parameter
        self.mock_db_manager.execute_query.assert_called_once()
        args, kwargs = self.mock_db_manager.execute_query.call_args
        query, params = args
        self.assertIn('IN (?)', query)  # Should have IN clause
        self.assertEqual(params, ('192.168.1.1',))  # Should have IP in params

    def test_get_authenticated_hosts_empty_filter_list(self):
        """Test get_authenticated_hosts with empty IP filter returns empty list immediately."""
        # Call method with empty IP filter
        result = self.workflow_db.get_authenticated_hosts(ip_filter=[])

        # Verify empty list returned without database call
        self.assertEqual(result, [])
        self.mock_db_manager.execute_query.assert_not_called()

    def test_get_authenticated_hosts_whitespace_only_filter(self):
        """Test get_authenticated_hosts with whitespace-only IPs returns empty list."""
        # Call method with whitespace-only IP filter
        result = self.workflow_db.get_authenticated_hosts(ip_filter=['  ', '\t', ''])

        # Verify empty list returned without database call
        self.assertEqual(result, [])
        self.mock_db_manager.execute_query.assert_not_called()

    def test_get_authenticated_hosts_multiple_ips_with_duplicates(self):
        """Test get_authenticated_hosts with multiple IPs removes duplicates."""
        # Mock database response
        mock_rows = [
            {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/blank',
             'last_seen': '2023-01-01 10:00:00', 'accessible_shares': 'share1'},
            {'ip_address': '192.168.1.2', 'country': 'CA', 'auth_method': 'anonymous',
             'last_seen': '2023-01-01 11:00:00', 'accessible_shares': 'share2'}
        ]
        self.mock_db_manager.execute_query.return_value = mock_rows

        # Call method with duplicate IPs in filter
        result = self.workflow_db.get_authenticated_hosts(
            ip_filter=['192.168.1.1', '192.168.1.2', '192.168.1.1', ' 192.168.1.2 ']
        )

        # Verify results
        self.assertEqual(len(result), 2)

        # Verify query called with deduplicated and trimmed IPs
        self.mock_db_manager.execute_query.assert_called_once()
        args, kwargs = self.mock_db_manager.execute_query.call_args
        query, params = args
        self.assertIn('IN (?,?)', query)  # Should have two placeholders
        self.assertEqual(params, ('192.168.1.1', '192.168.1.2'))  # Deduplicated params

    def test_get_authenticated_hosts_combined_recent_and_ip_filter(self):
        """Test get_authenticated_hosts with both recent_hours and ip_filter parameters."""
        # Mock database response
        mock_rows = [
            {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/blank',
             'last_seen': '2023-01-01 10:00:00', 'accessible_shares': 'share1'}
        ]
        self.mock_db_manager.execute_query.return_value = mock_rows

        # Call method with both filters
        result = self.workflow_db.get_authenticated_hosts(
            recent_hours=24,
            ip_filter=['192.168.1.1']
        )

        # Verify results
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip_address'], '192.168.1.1')

        # Verify query includes both time and IP filtering
        self.mock_db_manager.execute_query.assert_called_once()
        args, kwargs = self.mock_db_manager.execute_query.call_args
        query, params = args
        self.assertIn("datetime('now', 'localtime', '-24 hours')", query)  # Time filter
        self.assertIn('IN (?)', query)  # IP filter
        self.assertEqual(params, ('192.168.1.1',))  # IP params

    def test_get_authenticated_hosts_no_accessible_shares(self):
        """Test get_authenticated_hosts handles hosts with no accessible shares."""
        # Mock database response with host having no accessible shares
        mock_rows = [
            {'ip_address': '192.168.1.1', 'country': 'US', 'auth_method': 'guest/blank',
             'last_seen': '2023-01-01 10:00:00', 'accessible_shares': None}
        ]
        self.mock_db_manager.execute_query.return_value = mock_rows

        # Call method
        result = self.workflow_db.get_authenticated_hosts(ip_filter=['192.168.1.1'])

        # Verify result handles None accessible_shares correctly
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ip_address'], '192.168.1.1')
        self.assertEqual(result[0]['accessible_shares'], [])  # Should be empty list


if __name__ == '__main__':
    unittest.main()