#!/usr/bin/env python3
"""
Dialect fallback tests for DiscoverOperation.

Ensures SMB1 blocking remains enabled even when smbprotocol lacks Dialect support.
"""

import unittest
from unittest.mock import Mock, patch

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DummyOutput:
    """Minimal output helper for DiscoverOperation unit tests."""

    def __init__(self):
        self.print_if_verbose = Mock()
        self.warning = Mock()
        self.error = Mock()
        self.info = Mock()
        self.success = Mock()
        self.subheader = Mock()
        self.header = Mock()


class TestDiscoverDialectFallback(unittest.TestCase):
    """Validate dialect fallback logic when smbprotocol lacks Dialect support."""

    def setUp(self):
        self.mock_config = Mock()
        self.mock_output = DummyOutput()
        self.mock_database = Mock()
        self.session_id = 123

        # Patch smbclient availability to skip subprocess invocation
        smbc_patch = patch('commands.discover.DiscoverOperation._check_smbclient_availability', return_value=True)
        self.addCleanup(smbc_patch.stop)
        smbc_patch.start()

        # Import after path/patch setup
        from commands.discover import DiscoverOperation
        self.DiscoverOperation = DiscoverOperation

        # Preserve original Dialect for restoration
        import commands.discover as discover_module
        self.discover_module = discover_module
        self.original_dialect = discover_module.Dialect

    def tearDown(self):
        # Restore Dialect reference for other tests
        self.discover_module.Dialect = self.original_dialect

    @patch('commands.discover.Session')
    @patch('commands.discover.Connection')
    def test_without_dialect_omits_argument(self, mock_connection, mock_session):
        """If Dialect is unavailable, DiscoverOperation should omit the dialects kwarg."""
        self.discover_module.Dialect = None

        discover_op = self.DiscoverOperation(
            self.mock_config,
            self.mock_output,
            self.mock_database,
            self.session_id,
            cautious_mode=False,
            allow_smb1=False
        )

        mock_conn_instance = Mock()
        mock_connection.return_value = mock_conn_instance

        mock_session_instance = Mock()
        mock_session.return_value = mock_session_instance

        result = discover_op._attempt_smb_connection("1.2.3.4", "", "", timeout=5)
        self.assertTrue(result)

        _, kwargs = mock_connection.call_args
        self.assertNotIn('dialects', kwargs)
        self.mock_output.print_if_verbose.assert_called()

    @patch('commands.discover.Session')
    @patch('commands.discover.Connection')
    def test_type_error_removes_dialect_argument(self, mock_connection, mock_session):
        """Older smbprotocol versions that reject dialects kwarg should retry without it."""
        class FakeDialect:
            SMB_2_0_2 = object()
            SMB_2_1 = object()
            SMB_3_0_2 = object()
            SMB_3_1_1 = object()

        self.discover_module.Dialect = FakeDialect

        def connection_side_effect(*args, **kwargs):
            if 'dialects' in kwargs:
                raise TypeError("unexpected keyword argument 'dialects'")
            conn = Mock()
            conn.connect.return_value = None
            return conn

        mock_connection.side_effect = connection_side_effect
        mock_session.return_value = Mock()

        discover_op = self.DiscoverOperation(
            self.mock_config,
            self.mock_output,
            self.mock_database,
            self.session_id,
            cautious_mode=False,
            allow_smb1=False
        )

        result = discover_op._attempt_smb_connection("5.6.7.8", "", "", timeout=5)
        self.assertTrue(result)

        # The verbose logger should note the fallback once
        logged_messages = [call.args[0] for call in self.mock_output.print_if_verbose.call_args_list]
        self.assertTrue(any("dialect restriction" in message.lower() for message in logged_messages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
