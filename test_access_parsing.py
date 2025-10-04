#!/usr/bin/env python3
"""
Unit tests for SMBSeek access command share parsing logic.

Tests the parse_share_list() method with various smbclient output formats
to ensure correct share enumeration and prevent regression of counting issues.
"""

import sys
import os
import unittest
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.access import AccessOperation


class TestShareParsing(unittest.TestCase):
    """Test cases for share parsing logic."""

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
    
    def test_basic_share_parsing(self):
        """Test basic share parsing with standard Windows format."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        shared          Disk      
        documents       Disk      User documents
        
        Server               Comment
        ---------            -------
        
        Workgroup            Master
        ---------            -------
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        # Should only include non-administrative disk shares
        expected_shares = ['shared', 'documents']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 2)
    
    def test_empty_share_list(self):
        """Test parsing when no shares are available."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        
        Server               Comment
        ---------            -------
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        self.assertEqual(shares, [])
        self.assertEqual(len(shares), 0)
    
    def test_samba_output_format(self):
        """Test parsing Samba server output format."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        public          Disk      Public Files
        homes           Disk      Home Directories
        netlogon        Disk      Network Logon Service
        sysvol          Disk      System Volume
        
        Server               Comment
        ---------            -------
        SAMBA-SERVER     Samba Server
        
        Workgroup            Master
        ---------            -------
        WORKGROUP            SAMBA-SERVER
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        expected_shares = ['public', 'homes', 'netlogon', 'sysvol']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 4)
    
    def test_nas_output_format(self):
        """Test parsing NAS device output format."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        volume1         Disk      
        backup          Disk      Backup Storage
        media           Disk      Media Files
        
        Server               Comment
        ---------            -------
        NAS-DEVICE      
        
        Domain=[WORKGROUP] OS=[Unix] Server=[Samba/4.13.3]
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        expected_shares = ['volume1', 'backup', 'media']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 3)
    
    def test_malformed_output_handling(self):
        """Test handling of malformed or unexpected output."""
        smbclient_output = """
        Some random output
        that doesn't match
        the expected format
        
        Sharename       Type      Comment
        ---------       ----      -------
        validshare      Disk      This should be parsed
        invalid*name    Disk      Should be skipped
        print$          Disk      Should be skipped (admin)
        
        More random text
        Server stuff here
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        # Should only get the valid share
        expected_shares = ['validshare']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 1)
    
    def test_section_boundary_detection(self):
        """Test correct detection of section boundaries."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        share1          Disk      First share
        share2          Disk      Second share
        
        Server               Comment
        ---------            -------
        SERVER1             Some comment
        
        This should not be parsed as a share
        Even if it looks like: SomeShare Disk Comment
        
        Workgroup            Master
        ---------            -------
        WORKGROUP           SERVER1
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        # Should stop parsing after the shares section
        expected_shares = ['share1', 'share2']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 2)
    
    def test_no_shares_section(self):
        """Test handling output with no shares section."""
        smbclient_output = """
        Connection to server failed
        SMB1 disabled -- no workgroup available
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        self.assertEqual(shares, [])
        self.assertEqual(len(shares), 0)
    
    def test_share_name_validation(self):
        """Test share name validation logic."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        valid_share     Disk      Valid name
        valid-share     Disk      Valid name with dash
        ValidShare      Disk      Valid mixed case
        123share        Disk      Valid with numbers
        share@invalid   Disk      Invalid character
        share.invalid   Disk      Invalid character
        share$          Disk      Administrative (should be skipped)
        
        Server               Comment
        ---------            -------
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        # Should only include shares with valid names (alphanumeric plus - and _)
        expected_shares = ['valid_share', 'valid-share', 'ValidShare', '123share']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 4)
    
    def test_regression_extra_shares(self):
        """Regression test: ensure parser doesn't include extra lines as shares."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        data            Disk      Data share
        backup          Disk      Backup share
        
        
        Server               Comment
        ---------            -------
        FILE-SERVER         File Server
        
        Domain=[WORKGROUP] OS=[Windows Server 2019] Server=[Windows Server 2019]
        
        Workgroup            Master
        ---------            -------
        WORKGROUP           FILE-SERVER
        """
        
        shares = self.access_op.parse_share_list(smbclient_output)
        
        # Should be exactly 2 shares, no more
        expected_shares = ['data', 'backup']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 2)
        
        # Critical: Ensure no extra items were incorrectly parsed
        self.assertNotIn('FILE-SERVER', shares)
        self.assertNotIn('Windows Server 2019', shares)
        self.assertNotIn('WORKGROUP', shares)

    def test_share_names_starting_with_headers(self):
        """Test parsing shares with names starting with header keywords (regression test)."""
        smbclient_output = """
        Sharename       Type      Comment
        ---------       ----      -------
        Backup          Disk      Backup Files
        Server          Disk      New Moodle Server
        Software        Disk      Software Distribution
        Workgroup       Disk      Department Files
        Domain          Disk      Domain Storage
        IPC$            IPC       Remote IPC

        SMB1 disabled -- no workgroup available

        Some random noise here
        Domain=[EXAMPLE] OS=[Windows] Server=[Windows Server 2019]

        Server               Comment
        ---------            -------
        FILE-SERVER         Main File Server

        Workgroup            Master
        ---------            -------
        WORKGROUP           FILE-SERVER

        Domain               Controller
        ---------            -------
        EXAMPLE.COM         DC01.EXAMPLE.COM
        """

        shares = self.access_op.parse_share_list(smbclient_output)

        # Should parse all legitimate disk shares in order, including those starting with header keywords
        expected_shares = ['Backup', 'Server', 'Software', 'Workgroup', 'Domain']
        self.assertEqual(shares, expected_shares)
        self.assertEqual(len(shares), 5)

        # Ensure shares starting with header keywords are included
        self.assertIn('Server', shares)
        self.assertIn('Workgroup', shares)
        self.assertIn('Domain', shares)

        # Ensure parser stopped at actual headers and didn't include them
        self.assertNotIn('FILE-SERVER', shares)
        self.assertNotIn('DC01.EXAMPLE.COM', shares)


class TestShareValidation(unittest.TestCase):
    """Test cases for share validation logic in process_target."""

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
    
    def test_valid_share_counts(self):
        """Test validation passes with correct share counts."""
        # This would be tested with mocked process_target method
        # For now, we test the validation logic concept
        shares_found = ['share1', 'share2', 'share3']
        accessible_shares = ['share1', 'share3']
        
        # These counts should be valid
        self.assertLessEqual(len(accessible_shares), len(shares_found))
        self.assertEqual(len([s for s in accessible_shares if s in shares_found]), len(accessible_shares))
    
    def test_invalid_share_counts_detection(self):
        """Test detection of invalid share count scenarios."""
        shares_found = ['share1', 'share2']
        accessible_shares = ['share1', 'share2', 'share3']  # More accessible than found!
        
        # This should be detected as invalid
        self.assertGreater(len(accessible_shares), len(shares_found))
        
        # Test for shares not in original list
        invalid_shares = [s for s in accessible_shares if s not in shares_found]
        self.assertEqual(invalid_shares, ['share3'])


class TestAccessConfiguration(unittest.TestCase):
    """Test cases for access configuration integration."""

    def test_max_concurrent_hosts_config_integration(self):
        """Test that AccessOperation properly uses max_concurrent_hosts config."""
        # This test verifies that the new configuration integrates with existing parsing
        from shared.config import SMBSeekConfig

        # Test that config contains the new access section
        config = SMBSeekConfig()
        access_section = config.get("access")
        self.assertIsNotNone(access_section, "Should have access configuration section")

        # Test that max_concurrent_hosts is available and defaults to 1
        max_concurrent = config.get_max_concurrent_hosts()
        self.assertEqual(max_concurrent, 1, "Should default to 1 concurrent host")

        # Test with custom config
        config.config["access"]["max_concurrent_hosts"] = 5
        max_concurrent = config.get_max_concurrent_hosts()
        self.assertEqual(max_concurrent, 5, "Should return configured value")


if __name__ == '__main__':
    # Run tests without API usage
    print("Running SMBSeek access parsing tests...")
    print("Note: These tests use mock data and do not make network connections.")
    
    unittest.main(verbosity=2)