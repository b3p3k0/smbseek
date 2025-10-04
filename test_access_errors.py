#!/usr/bin/env python3
"""Tests for SMBSeek access error formatting and logging."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from commands.access import AccessOperation


class TestAccessErrorHandling(unittest.TestCase):
    """Validate friendly formatting of expected access-denied responses."""

    def setUp(self):
        # Patch smbclient availability check so constructor does not call subprocess
        patcher = patch('commands.access.AccessOperation.check_smbclient_availability', return_value=True)
        self.addCleanup(patcher.stop)
        patcher.start()

        self.mock_config = Mock()
        self.mock_output = Mock()
        for method in ['print_if_verbose', 'success', 'warning', 'error', 'info']:
            setattr(self.mock_output, method, Mock())

        self.mock_database = Mock()

        self.access_op = AccessOperation(
            config=self.mock_config,
            output=self.mock_output,
            database=self.mock_database,
            session_id=1
        )

    def test_format_access_denied_returns_friendly_message(self):
        """Formatter should return a clean message and no raw context."""
        result = SimpleNamespace(
            stderr='tree connect failed: NT_STATUS_ACCESS_DENIED\n',
            stdout='Anonymous login successful\n',
            returncode=1
        )

        friendly, raw = self.access_op._format_smbclient_error(result)

        self.assertIn('Access denied - share does not allow anonymous/guest browsing', friendly)
        self.assertIsNone(raw)

    @patch('subprocess.run')
    def test_access_denied_logs_warning(self, mock_run):
        """Expected access denials should emit warnings, not errors."""
        mock_run.return_value = SimpleNamespace(
            returncode=1,
            stdout='Anonymous login successful\n',
            stderr='tree connect failed: NT_STATUS_ACCESS_DENIED\n'
        )

        result = self.access_op.test_share_access('1.2.3.4', 'admin', '', '')

        self.mock_output.warning.assert_called()
        self.mock_output.error.assert_not_called()
        self.assertFalse(result['accessible'])
        self.assertIn('Access denied - share does not allow anonymous/guest browsing', result['error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
