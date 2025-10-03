#!/usr/bin/env python3
"""
Unit tests for SMBSeek discovery command country metadata handling.

Tests the new Shodan metadata capture, filtering alignment, and database
storage of individual host country information.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.discover import DiscoverOperation, DiscoverResult


class TestDiscoverMetadata(unittest.TestCase):
    """Test cases for Shodan metadata capture and processing."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock components for DiscoverOperation
        self.mock_config = Mock()
        self.mock_output = Mock()
        self.mock_database = Mock()
        self.session_id = 1

        # Mock config methods
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
             patch('commands.discover.SMB_AVAILABLE', True):
            self.discover_op = DiscoverOperation(
                config=self.mock_config,
                output=self.mock_output,
                database=self.mock_database,
                session_id=self.session_id
            )

    def test_metadata_capture_from_shodan(self):
        """Test that Shodan location metadata is properly captured."""
        # Mock Shodan search response with varied location data
        mock_shodan_results = {
            'matches': [
                {
                    'ip_str': '192.168.1.1',
                    'location': {
                        'country_name': 'United States',
                        'country_code': 'US'
                    }
                },
                {
                    'ip_str': '192.168.1.2',
                    'country_name': 'Canada',  # Top-level fallback
                    'country_code': 'CA'
                },
                {
                    'ip_str': '192.168.1.3',
                    'location': {
                        'country_name': 'Mexico'
                        # Missing country_code
                    }
                },
                {
                    'ip_str': '192.168.1.4'
                    # No location data at all
                }
            ]
        }

        self.discover_op.shodan_api.search.return_value = mock_shodan_results

        # Execute _query_shodan
        result_ips = self.discover_op._query_shodan('US')

        # Verify IPs were extracted
        expected_ips = {'192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4'}
        self.assertEqual(result_ips, expected_ips)

        # Verify metadata was captured correctly
        expected_metadata = {
            '192.168.1.1': {
                'country_name': 'United States',
                'country_code': 'US'
            },
            '192.168.1.2': {
                'country_name': 'Canada',
                'country_code': 'CA'
            },
            '192.168.1.3': {
                'country_name': 'Mexico'
            },
            '192.168.1.4': {}
        }
        self.assertEqual(self.discover_op.shodan_host_metadata, expected_metadata)

    def test_metadata_first_complete_record_wins(self):
        """Test that first complete record wins for duplicate IPs."""
        mock_shodan_results = {
            'matches': [
                {
                    'ip_str': '192.168.1.1',
                    'location': {
                        'country_name': 'United States',
                        'country_code': 'US'
                    }
                },
                {
                    'ip_str': '192.168.1.1',  # Duplicate IP
                    'location': {
                        'country_name': 'Canada',  # Different country
                        'country_code': 'CA'
                    }
                }
            ]
        }

        self.discover_op.shodan_api.search.return_value = mock_shodan_results
        result_ips = self.discover_op._query_shodan('US')

        # Should keep first complete record
        expected_metadata = {
            '192.168.1.1': {
                'country_name': 'United States',
                'country_code': 'US'
            }
        }
        self.assertEqual(self.discover_op.shodan_host_metadata, expected_metadata)

    def test_metadata_alignment_during_exclusions(self):
        """Test that metadata is removed when IPs are excluded."""
        # Set up initial metadata
        self.discover_op.shodan_host_metadata = {
            '192.168.1.1': {'country_name': 'United States', 'country_code': 'US'},
            '192.168.1.2': {'country_name': 'Canada', 'country_code': 'CA'},
            '192.168.1.3': {'country_name': 'Mexico', 'country_code': 'MX'}
        }

        # Mock exclusions to reject one IP and setup required exclusions list
        self.discover_op.exclusions = ['test_exclusion']  # Need non-empty list for method to run
        with patch.object(self.discover_op, '_should_exclude_ip') as mock_exclude:
            mock_exclude.side_effect = lambda ip: ip == '192.168.1.2'

            input_ips = {'192.168.1.1', '192.168.1.2', '192.168.1.3'}
            filtered_ips = self.discover_op._apply_exclusions(input_ips)

            # Verify IP was excluded
            expected_filtered = {'192.168.1.1', '192.168.1.3'}
            self.assertEqual(filtered_ips, expected_filtered)

            # Verify metadata was also removed for excluded IP
            expected_metadata = {
                '192.168.1.1': {'country_name': 'United States', 'country_code': 'US'},
                '192.168.1.3': {'country_name': 'Mexico', 'country_code': 'MX'}
            }
            self.assertEqual(self.discover_op.shodan_host_metadata, expected_metadata)

    def test_metadata_trimming_after_database_filtering(self):
        """Test metadata trimming to match hosts_to_scan."""
        # Set up initial metadata
        self.discover_op.shodan_host_metadata = {
            '192.168.1.1': {'country_name': 'United States', 'country_code': 'US'},
            '192.168.1.2': {'country_name': 'Canada', 'country_code': 'CA'},
            '192.168.1.3': {'country_name': 'Mexico', 'country_code': 'MX'}
        }

        # Mock database filtering to return subset
        hosts_to_scan = {'192.168.1.1', '192.168.1.3'}
        filter_stats = {}
        self.mock_database.get_new_hosts_filter.return_value = (hosts_to_scan, filter_stats)

        # Set up other mocks for execute method
        with patch.object(self.discover_op, '_query_shodan') as mock_query, \
             patch.object(self.discover_op, '_apply_exclusions') as mock_exclude, \
             patch.object(self.discover_op, '_build_targeted_query') as mock_build, \
             patch('commands.discover.SMB_AVAILABLE', True):

            mock_query.return_value = {'192.168.1.1', '192.168.1.2', '192.168.1.3'}
            mock_exclude.return_value = {'192.168.1.1', '192.168.1.2', '192.168.1.3'}
            mock_build.return_value = "test query"

            # Call execute with no hosts to scan (to avoid authentication)
            self.mock_database.get_new_hosts_filter.return_value = (set(), {})
            result = self.discover_op.execute(country='US')

            # Verify metadata was trimmed to empty set
            self.assertEqual(self.discover_op.shodan_host_metadata, {})

    def test_authentication_uses_metadata_lookup(self):
        """Test that authentication uses metadata lookup with CLI fallback."""
        # Set up metadata
        self.discover_op.shodan_host_metadata = {
            '192.168.1.1': {'country_name': 'United States', 'country_code': 'US'},
            '192.168.1.2': {}  # No metadata
        }

        with patch.object(self.discover_op, '_check_port', return_value=True), \
             patch.object(self.discover_op, '_test_smb_auth', return_value=True):

            # Test with metadata available
            result1 = self.discover_op._test_single_host('192.168.1.1', 'CLI_Country')
            self.assertEqual(result1['country'], 'United States')
            self.assertEqual(result1['country_code'], 'US')

            # Test with no metadata (uses CLI fallback)
            result2 = self.discover_op._test_single_host('192.168.1.2', 'CLI_Country')
            self.assertEqual(result2['country'], 'CLI_Country')
            self.assertIsNone(result2['country_code'])

            # Test with no metadata and no CLI fallback
            result3 = self.discover_op._test_single_host('192.168.1.2', None)
            self.assertEqual(result3['country'], 'Unknown')
            self.assertIsNone(result3['country_code'])

    def test_smbclient_fallback_preserves_metadata(self):
        """Test that smbclient fallback also uses metadata lookup."""
        self.discover_op.smbclient_available = True
        self.discover_op.shodan_host_metadata = {
            '192.168.1.1': {'country_name': 'Canada', 'country_code': 'CA'}
        }

        with patch.object(self.discover_op, '_check_port', return_value=True), \
             patch.object(self.discover_op, '_test_smb_auth', return_value=False), \
             patch.object(self.discover_op, '_test_smb_alternative', return_value='Guest/Blank'):

            result = self.discover_op._test_single_host('192.168.1.1', 'CLI_Country')

            self.assertEqual(result['country'], 'Canada')
            self.assertEqual(result['country_code'], 'CA')
            self.assertEqual(result['auth_method'], 'Guest/Blank (smbclient)')

    def test_database_storage_includes_country_code(self):
        """Test that database storage includes both country fields."""
        with patch('db_manager.SMBSeekDataAccessLayer') as mock_dal_class:
            mock_dal = mock_dal_class.return_value
            mock_dal.get_or_create_server.return_value = 1

            successful_hosts = [
                {
                    'ip_address': '192.168.1.1',
                    'country': 'United States',
                    'country_code': 'US',
                    'auth_method': 'Anonymous'
                },
                {
                    'ip_address': '192.168.1.2',
                    'country': 'Unknown',
                    'country_code': None,
                    'auth_method': 'Guest/Blank'
                }
            ]

            result_ips = self.discover_op._save_to_database(successful_hosts, 'CLI_Country')

            # Verify both calls included country_code parameter
            expected_calls = [
                unittest.mock.call(
                    ip_address='192.168.1.1',
                    country='United States',
                    auth_method='Anonymous',
                    country_code='US'
                ),
                unittest.mock.call(
                    ip_address='192.168.1.2',
                    country='Unknown',
                    auth_method='Guest/Blank',
                    country_code=None
                )
            ]
            mock_dal.get_or_create_server.assert_has_calls(expected_calls)

    def test_metadata_cleared_on_each_execute(self):
        """Test that metadata is cleared at start of each execute call."""
        # Set up stale metadata
        self.discover_op.shodan_host_metadata = {'192.168.1.99': {'country_name': 'Stale'}}

        with patch.object(self.discover_op, '_query_shodan', return_value=set()), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test"), \
             patch('commands.discover.SMB_AVAILABLE', True):

            self.discover_op.execute(country='US')

            # Metadata should be cleared even if no new results
            self.assertEqual(self.discover_op.shodan_host_metadata, {})


if __name__ == '__main__':
    unittest.main()