#!/usr/bin/env python3
"""
SMBSeek Cautious Flag Testing Script

Tests the --cautious flag functionality and smbclient command builder
to ensure security options are correctly applied or omitted.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestCautiousFlag(unittest.TestCase):
    """Test cautious flag functionality and command building."""

    def setUp(self):
        """Set up test fixtures."""
        # Create mock config, output, database, and session_id
        self.mock_config = Mock()
        self.mock_output = Mock()
        self.mock_database = Mock()
        self.session_id = 1

    def test_access_operation_command_builder_cautious_mode(self):
        """Test that cautious mode includes security flags in smbclient commands."""
        # Patch smbclient availability check so constructor does not call subprocess
        with patch('commands.access.AccessOperation.check_smbclient_availability', return_value=True):
            from commands.access import AccessOperation

            # Create AccessOperation in cautious mode (cautious_mode=True)
            access_op = AccessOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=True
            )

            # Test enumerate command building
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "guest", "")

            # Should include security flags
            self.assertIn("--client-protection=sign", cmd)
            self.assertIn("--max-protocol=SMB3", cmd)
            self.assertIn("--option=client min protocol=SMB2", cmd)
            self.assertIn("--option=client smb encrypt=desired", cmd)

            # Should include credentials
            self.assertIn("--user", cmd)
            self.assertIn("guest%", cmd)

            # Should include target
            self.assertIn("-L", cmd)
            self.assertIn("//192.168.1.1", cmd)

    def test_access_operation_command_builder_legacy_mode(self):
        """Test that legacy mode (opt-in) omits security flags in smbclient commands."""
        # Patch smbclient availability check
        with patch('commands.access.AccessOperation.check_smbclient_availability', return_value=True):
            from commands.access import AccessOperation

            # Create AccessOperation in legacy mode (cautious_mode=False)
            access_op = AccessOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=False
            )

            # Test enumerate command building
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "guest", "")

            # Should NOT include security flags
            cmd_str = " ".join(cmd)
            self.assertNotIn("--client-protection", cmd_str)
            self.assertNotIn("--max-protocol", cmd_str)
            self.assertNotIn("client min protocol", cmd_str)
            self.assertNotIn("client smb encrypt", cmd_str)

            # Should still include credentials and target
            self.assertIn("--user", cmd)
            self.assertIn("guest%", cmd)
            self.assertIn("-L", cmd)
            self.assertIn("//192.168.1.1", cmd)

    def test_access_operation_command_builder_access_type(self):
        """Test command builder for share access operations."""
        with patch('commands.access.AccessOperation.check_smbclient_availability', return_value=True):
            from commands.access import AccessOperation

            access_op = AccessOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=True
            )

            # Test access command building
            cmd = access_op._build_smbclient_cmd("access", "192.168.1.1", "", "", share="testshare")

            # Should include share path
            self.assertIn("//192.168.1.1/testshare", cmd)

            # Should include security flags (cautious mode)
            self.assertIn("--client-protection=sign", cmd)

            # Should include anonymous auth
            self.assertIn("-N", cmd)

    def test_discover_operation_cautious_mode_parameter(self):
        """Test that DiscoverOperation accepts and stores cautious_mode parameter."""
        with patch('commands.discover.DiscoverOperation._check_smbclient_availability', return_value=True):
            from commands.discover import DiscoverOperation

            # Test legacy mode
            discover_op_legacy = DiscoverOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=False
            )
            self.assertFalse(discover_op_legacy.cautious_mode)

            # Test cautious mode
            discover_op_cautious = DiscoverOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=True
            )
            self.assertTrue(discover_op_cautious.cautious_mode)

    def test_credential_handling_in_command_builder(self):
        """Test various credential scenarios in command builder."""
        with patch('commands.access.AccessOperation.check_smbclient_availability', return_value=True):
            from commands.access import AccessOperation

            access_op = AccessOperation(
                self.mock_config,
                self.mock_output,
                self.mock_database,
                self.session_id,
                cautious_mode=False  # Use legacy mode to focus on credentials, not security flags
            )

            # Test anonymous
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "", "")
            self.assertIn("-N", cmd)

            # Test guest with blank password
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "guest", "")
            self.assertIn("guest%", cmd)

            # Test guest with password
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "guest", "guest")
            self.assertIn("guest%guest", cmd)

            # Test custom username/password
            cmd = access_op._build_smbclient_cmd("enumerate", "192.168.1.1", "testuser", "testpass")
            self.assertIn("testuser%testpass", cmd)


def main():
    """Run the test suite."""
    print("🧪 SMBSeek Cautious Flag Unit Tests")
    print("=" * 40)

    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCautiousFlag)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
