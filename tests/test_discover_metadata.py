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

        # Create DiscoverOperation with mocks and empty exclusion file
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

        # Verify metadata was captured correctly including org/ISP
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

    def test_org_isp_metadata_capture_from_shodan(self):
        """Test that org/ISP metadata is captured from Shodan results with safe normalization."""
        mock_shodan_results = {
            'matches': [
                {
                    'ip_str': '192.168.1.1',
                    'org': 'Example Corp',
                    'isp': 'Internet Service Provider'
                },
                {
                    'ip_str': '192.168.1.2',
                    'org': None,  # Test None handling
                    'isp': 'Another ISP'
                },
                {
                    'ip_str': '192.168.1.3'
                    # No org/ISP fields at all
                }
            ]
        }

        self.discover_op.shodan_api.search.return_value = mock_shodan_results
        result_ips = self.discover_op._query_shodan('US')

        # Verify org/ISP metadata was captured with safe normalization
        expected_metadata = {
            '192.168.1.1': {
                'org': 'Example Corp',
                'org_normalized': 'example corp',
                'isp': 'Internet Service Provider',
                'isp_normalized': 'internet service provider'
            },
            '192.168.1.2': {
                'isp': 'Another ISP',
                'isp_normalized': 'another isp'
            },
            '192.168.1.3': {}
        }
        self.assertEqual(self.discover_op.shodan_host_metadata, expected_metadata)

    def test_dual_exclusion_storage(self):
        """Test that exclusions are stored in both original and normalized forms."""
        # Mock exclusion file content
        with patch('builtins.open', unittest.mock.mock_open(read_data='Example Corp\nAnother ISP\n# Comment\n')):
            exclusions = self.discover_op._load_exclusions()
            # Manually update the instance variable since the method returned the list
            self.discover_op.exclusions = exclusions

        # Verify original exclusions preserved
        self.assertEqual(exclusions, ['Example Corp', 'Another ISP'])
        self.assertEqual(self.discover_op.exclusions, ['Example Corp', 'Another ISP'])

        # Verify normalized patterns created
        self.assertEqual(self.discover_op.exclusion_patterns, ['example corp', 'another isp'])

    def test_should_exclude_ip_api_unavailable(self):
        """Test that _should_exclude_ip returns False when API unavailable."""
        self.discover_op.shodan_api = None
        result = self.discover_op._should_exclude_ip('192.168.1.1')
        self.assertFalse(result)

    def test_should_exclude_ip_uses_cached_metadata(self):
        """Test that _should_exclude_ip uses cached metadata without API calls."""
        # Set up exclusion patterns
        self.discover_op.exclusion_patterns = ['example corp', 'test isp']

        # Set up cached metadata
        self.discover_op.shodan_host_metadata = {
            '192.168.1.1': {
                'org_normalized': 'example corp inc',  # Should match 'example corp'
                'isp_normalized': 'safe provider'
            },
            '192.168.1.2': {
                'org_normalized': 'safe company',
                'isp_normalized': 'clean provider'
            },
            '192.168.1.3': {
                'org_normalized': '',  # Empty but present
                'isp_normalized': ''
            }
        }

        with patch.object(self.discover_op.shodan_api, 'host') as mock_api:
            # Test exclusion match
            result1 = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertTrue(result1)

            # Test no exclusion match
            result2 = self.discover_op._should_exclude_ip('192.168.1.2')
            self.assertFalse(result2)

            # Test empty strings (should not exclude)
            result3 = self.discover_op._should_exclude_ip('192.168.1.3')
            self.assertFalse(result3)

            # Verify API was never called
            mock_api.assert_not_called()

    def test_should_exclude_ip_memoization(self):
        """Test that API calls are memoized and not repeated."""
        self.discover_op.exclusion_patterns = ['badcorp']

        with patch.object(self.discover_op.shodan_api, 'host') as mock_api:
            # First call - API returns data
            mock_api.return_value = {'org': 'GoodCorp', 'isp': 'CleanISP'}

            result1 = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertFalse(result1)

            # Second call to same IP - should use cache
            result2 = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertFalse(result2)

            # Verify API was called only once
            self.assertEqual(mock_api.call_count, 1)

            # Verify both caches were updated
            self.assertIn('192.168.1.1', self.discover_op._host_lookup_cache)
            self.assertIn('org_normalized', self.discover_op.shodan_host_metadata['192.168.1.1'])

    def test_should_exclude_ip_api_failure_memoization(self):
        """Test that API failures are cached to prevent retry loops."""
        self.discover_op.exclusion_patterns = ['badcorp']

        with patch.object(self.discover_op.shodan_api, 'host') as mock_api:
            # First call - API fails
            mock_api.side_effect = Exception("API Error")

            result1 = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertFalse(result1)  # Fail open

            # Second call to same IP - should use cached failure
            mock_api.side_effect = None
            mock_api.return_value = {'org': 'BadCorp', 'isp': 'BadISP'}

            result2 = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertFalse(result2)  # Still uses cached failure

            # Verify API was called only once (failure cached)
            self.assertEqual(mock_api.call_count, 1)
            self.assertEqual(self.discover_op._host_lookup_cache['192.168.1.1'], None)

    def test_should_exclude_ip_safe_normalization(self):
        """Test safe normalization handles None values from API."""
        self.discover_op.exclusion_patterns = ['badcorp']

        with patch.object(self.discover_op.shodan_api, 'host') as mock_api:
            # API returns None values
            mock_api.return_value = {'org': None, 'isp': None}

            result = self.discover_op._should_exclude_ip('192.168.1.1')
            self.assertFalse(result)

            # Verify empty strings were stored (safe normalization)
            metadata = self.discover_op.shodan_host_metadata['192.168.1.1']
            self.assertEqual(metadata['org_normalized'], '')
            self.assertEqual(metadata['isp_normalized'], '')

    def test_exclusions_preserve_original_casing_for_query_building(self):
        """Test that original exclusion casing is preserved for Shodan query building."""
        self.discover_op.exclusions = ['Example Corp', 'Another-ISP']

        # Test that _build_targeted_query uses original casing
        query = self.discover_op._build_targeted_query(['US'])

        # Should contain original casing in org exclusions
        self.assertIn('-org:"Example Corp"', query)
        self.assertIn('-org:"Another-ISP"', query)

    def test_apply_exclusions_configurable_progress_interval(self):
        """Test configurable progress interval with safe integer conversion."""
        # Test default interval
        self.mock_config.get.return_value = None
        filtered_ips = self.discover_op._apply_exclusions({'192.168.1.1'})
        # Should not raise exception

        # Test string interval (should convert safely)
        self.mock_config.get.return_value = "50"
        filtered_ips = self.discover_op._apply_exclusions({'192.168.1.1'})
        # Should not raise exception

        # Test invalid interval (should use default)
        self.mock_config.get.return_value = "invalid"
        filtered_ips = self.discover_op._apply_exclusions({'192.168.1.1'})
        # Should not raise exception

    def test_memoization_cache_cleared_per_operation(self):
        """Test that memoization cache is cleared at start of each execute call."""
        # Set up stale cache data
        self.discover_op._host_lookup_cache = {'192.168.1.99': {'org': 'Stale'}}

        with patch.object(self.discover_op, '_query_shodan', return_value=set()), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test"), \
             patch('commands.discover.SMB_AVAILABLE', True):

            self.discover_op.execute(country='US')

            # Cache should be cleared
            self.assertEqual(self.discover_op._host_lookup_cache, {})

    def test_forced_hosts_bypass_database_filtering(self):
        """Test that forced hosts bypass database filtering and appear in results."""
        # Set up forced hosts
        force_hosts = {'192.168.1.100', '10.0.0.50'}

        # Mock Shodan to return different IPs
        mock_shodan_results = {'192.168.1.1', '192.168.1.2'}

        # Mock database filtering to exclude the forced host that's in Shodan results
        mock_filtered_hosts = {'192.168.1.1'}  # Excludes forced host in Shodan
        filter_stats = {
            'total_from_shodan': 2,
            'new_hosts': 1,
            'known_hosts': 1,
            'to_scan': 1,
            'recently_scanned': 1,
            'failed_hosts': 0
        }

        with patch.object(self.discover_op, '_query_shodan', return_value=mock_shodan_results), \
             patch.object(self.discover_op, '_apply_exclusions', side_effect=lambda x: x), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test query"), \
             patch.object(self.discover_op, '_test_smb_authentication', return_value=[]), \
             patch.object(self.discover_op, '_save_to_database', return_value=set()), \
             patch('commands.discover.SMB_AVAILABLE', True):

            # Mock database filtering
            self.mock_database.get_new_hosts_filter.return_value = (mock_filtered_hosts, filter_stats)
            self.mock_database.display_scan_statistics = Mock()

            # Execute with forced hosts
            result = self.discover_op.execute(country='US', force_hosts=force_hosts)

            # Verify forced hosts are added to Shodan results
            expected_shodan_union = mock_shodan_results.union(force_hosts)

            # Verify both forced hosts have placeholder metadata
            self.assertIn('192.168.1.100', self.discover_op.shodan_host_metadata)
            self.assertIn('10.0.0.50', self.discover_op.shodan_host_metadata)
            self.assertEqual(self.discover_op.shodan_host_metadata['192.168.1.100']['country_name'], 'Unknown')
            self.assertEqual(self.discover_op.shodan_host_metadata['10.0.0.50']['country_name'], 'Unknown')

            # Verify stats were updated with forced hosts
            call_args = self.mock_database.display_scan_statistics.call_args
            updated_stats = call_args[0][0]
            self.assertEqual(updated_stats['forced_hosts'], 2)
            self.assertEqual(updated_stats['to_scan'], 3)  # 1 filtered + 2 forced

    def test_forced_hosts_not_in_shodan_results(self):
        """Test that forced hosts not in Shodan results are still processed."""
        # Forced host completely separate from Shodan results
        force_hosts = {'172.16.0.100'}

        # Mock Shodan results
        mock_shodan_results = {'192.168.1.1', '192.168.1.2'}

        with patch.object(self.discover_op, '_query_shodan', return_value=mock_shodan_results), \
             patch.object(self.discover_op, '_apply_exclusions', side_effect=lambda x: x), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test query"), \
             patch.object(self.discover_op, '_test_smb_authentication', return_value=[]), \
             patch.object(self.discover_op, '_save_to_database', return_value=set()), \
             patch('commands.discover.SMB_AVAILABLE', True):

            # Mock database filtering to return all Shodan results
            filter_stats = {'total_from_shodan': 2, 'to_scan': 2}
            self.mock_database.get_new_hosts_filter.return_value = (mock_shodan_results, filter_stats)
            self.mock_database.display_scan_statistics = Mock()

            # Execute with forced hosts
            result = self.discover_op.execute(country='US', force_hosts=force_hosts)

            # Verify forced host has placeholder metadata
            self.assertIn('172.16.0.100', self.discover_op.shodan_host_metadata)
            self.assertEqual(self.discover_op.shodan_host_metadata['172.16.0.100']['country_name'], 'Unknown')

    def test_forced_hosts_preserve_existing_metadata(self):
        """Test that forced hosts with existing Shodan metadata preserve that metadata."""
        # Forced host that's also in Shodan results
        force_hosts = {'192.168.1.1'}

        # Mock Shodan results with metadata
        mock_shodan_results = {'192.168.1.1', '192.168.1.2'}

        def mock_query_shodan(country):
            """Mock that populates metadata like real _query_shodan"""
            # Populate metadata for Shodan results
            self.discover_op.shodan_host_metadata['192.168.1.1'] = {
                'country_name': 'United States',
                'country_code': 'US'
            }
            self.discover_op.shodan_host_metadata['192.168.1.2'] = {
                'country_name': 'Canada',
                'country_code': 'CA'
            }
            return mock_shodan_results

        with patch.object(self.discover_op, '_query_shodan', side_effect=mock_query_shodan), \
             patch.object(self.discover_op, '_apply_exclusions', side_effect=lambda x: x), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test query"), \
             patch.object(self.discover_op, '_test_smb_authentication', return_value=[]), \
             patch.object(self.discover_op, '_save_to_database', return_value=set()), \
             patch('commands.discover.SMB_AVAILABLE', True):

            # Mock database filtering to exclude the forced host initially
            mock_filtered_hosts = {'192.168.1.2'}  # Excludes the forced host
            filter_stats = {'total_from_shodan': 2, 'to_scan': 1}
            self.mock_database.get_new_hosts_filter.return_value = (mock_filtered_hosts, filter_stats)
            self.mock_database.display_scan_statistics = Mock()

            # Execute with forced hosts
            result = self.discover_op.execute(country='US', force_hosts=force_hosts)

            # Verify forced host preserves original Shodan metadata (not replaced with Unknown)
            self.assertEqual(self.discover_op.shodan_host_metadata['192.168.1.1']['country_name'], 'United States')
            self.assertEqual(self.discover_op.shodan_host_metadata['192.168.1.1']['country_code'], 'US')

    def test_no_forced_hosts_default_behavior(self):
        """Test that when no forced hosts provided, behavior is unchanged."""
        mock_shodan_results = {'192.168.1.1', '192.168.1.2'}

        with patch.object(self.discover_op, '_query_shodan', return_value=mock_shodan_results), \
             patch.object(self.discover_op, '_apply_exclusions', side_effect=lambda x: x), \
             patch.object(self.discover_op, '_build_targeted_query', return_value="test query"), \
             patch.object(self.discover_op, '_test_smb_authentication', return_value=[]), \
             patch.object(self.discover_op, '_save_to_database', return_value=set()), \
             patch('commands.discover.SMB_AVAILABLE', True):

            filter_stats = {'total_from_shodan': 2, 'to_scan': 2}
            self.mock_database.get_new_hosts_filter.return_value = (mock_shodan_results, filter_stats)
            self.mock_database.display_scan_statistics = Mock()

            # Execute without forced hosts
            result = self.discover_op.execute(country='US')

            # Verify no forced_hosts key in stats
            call_args = self.mock_database.display_scan_statistics.call_args
            updated_stats = call_args[0][0]
            self.assertNotIn('forced_hosts', updated_stats)


if __name__ == '__main__':
    unittest.main()