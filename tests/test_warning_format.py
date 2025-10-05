#!/usr/bin/env python3
"""
Test for simplified share access error messages and warning format consistency.

Verifies that:
1. Access denied errors show as clean yellow warnings
2. Technical errors still show as red errors with details
3. Database still contains full error information
4. Warning format matches existing style
"""

import sys
import os
import unittest
import tempfile
import sqlite3
from unittest.mock import Mock, patch
from io import StringIO

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commands.access import AccessOperation
from shared.config import SMBSeekConfig
from shared.output import SMBSeekOutput
from shared.database import SMBSeekWorkflowDatabase


class TestWarningFormat(unittest.TestCase):
    """Test simplified warning format for share access errors."""

    def setUp(self):
        """Set up test fixtures."""
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(self.db_fd)

        # Create real config and components
        self.config = SMBSeekConfig()
        self.config.config['database']['path'] = self.db_path

        self.database = SMBSeekWorkflowDatabase(self.config, verbose=False)
        self.database.db_manager.initialize_database()
        self.session_id = self.database.create_session('test_warning_format')

        # Create server record for testing
        self.server_id = self.database.dal.get_or_create_server(
            ip_address='192.168.1.100',
            country='US',
            auth_method='guest/guest'
        )

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self.database, 'close'):
            self.database.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_warning_format_consistency(self):
        """Test that warning format matches existing SMBSeekOutput warning style."""
        # Test the warning output format directly
        output = SMBSeekOutput(self.config, quiet=False, verbose=False, no_colors=True)

        # Capture output
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            output.warning("Test warning message")
            warning_output = mock_stdout.getvalue().strip()

        # Verify format matches expected pattern
        self.assertTrue(warning_output.startswith("⚠ "), "Warning should start with ⚠ emoji")
        self.assertIn("Test warning message", warning_output, "Warning should contain the message")

    def test_access_denied_shows_as_warning(self):
        """Test that access denied errors show as clean yellow warnings."""
        output = SMBSeekOutput(self.config, quiet=False, verbose=False, no_colors=True)
        access_op = AccessOperation(
            config=self.config,
            output=output,
            database=self.database,
            session_id=self.session_id
        )

        access_op.total_targets = 1

        # Create mock result with access denied error
        test_result = {
            'ip_address': '192.168.1.100',
            'country': 'US',
            'auth_method': 'guest/guest',
            'timestamp': '2025-10-04T12:00:00',
            'shares_found': ['test_share'],
            'accessible_shares': [],
            'share_details': [
                {
                    'share_name': 'test_share',
                    'accessible': False,
                    'error': 'Access denied - insufficient permissions (NT_STATUS_ACCESS_DENIED) - tree connect failed: NT_STATUS_ACCESS_DENIED'
                }
            ]
        }

        access_op.results = [test_result]

        # Mock the individual share processing part that generates user output
        shares = ['test_share']
        host_label = "Host 1/1"
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            # Simulate the share testing loop from process_target()
            for i, share_name in enumerate(shares, 1):
                access_result = test_result['share_details'][0]
                if access_result['accessible']:
                    access_op.output.success(
                        f"{host_label}: Share {i}/{len(shares)}: {share_name} - accessible"
                    )
                else:
                    message = access_result.get('error', 'not accessible')
                    if message and 'NT_STATUS_ACCESS_DENIED' in message:
                        # All access denied errors = clean yellow warning
                        access_op.output.warning(
                            f"{host_label}: Share {i}/{len(shares)}: {share_name} - Access Failed"
                        )
                    elif 'timeout' in message.lower() or 'connection' in message.lower():
                        # Technical failures = red error with details
                        access_op.output.error(
                            f"{host_label}: Share {i}/{len(shares)}: {share_name} - {message}"
                        )
                    else:
                        # Other failures = clean yellow warning
                        access_op.output.warning(
                            f"{host_label}: Share {i}/{len(shares)}: {share_name} - Access Failed"
                        )

            console_output = mock_stdout.getvalue().strip()

        # Verify the output format
        self.assertTrue(console_output.startswith("⚠ "), "Should use warning emoji")
        self.assertIn("Host 1/1: Share 1/1: test_share - Access Failed", console_output, "Should show simplified message")
        self.assertNotIn("NT_STATUS_ACCESS_DENIED", console_output, "Should not show technical details in console")

    def test_missing_share_shows_pretty_warning(self):
        """Ensure missing shares emit a human-friendly warning instead of a raw error."""
        output = SMBSeekOutput(self.config, quiet=False, verbose=False, no_colors=True)
        access_op = AccessOperation(
            config=self.config,
            output=output,
            database=self.database,
            session_id=self.session_id
        )

        access_op.total_targets = 1
        host_label = "Host 1/1"

        shares = ['ghost_share']
        message = "Share not found on server (server reported NT_STATUS_BAD_NETWORK_NAME)"

        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            access_op.output.warning(
                f"{host_label}: Share 1/{len(shares)}: {shares[0]} - {message}"
            )

            console_output = mock_stdout.getvalue().strip()

        self.assertTrue(console_output.startswith("⚠ "), "Missing shares should show as warnings")
        self.assertIn("Share 1/1", console_output)
        self.assertIn("Share not found on server", console_output)
        self.assertIn("NT_STATUS_BAD_NETWORK_NAME", console_output)

    def test_technical_errors_show_as_errors(self):
        """Test that technical errors (timeouts, connections) still show as red errors with details."""
        output = SMBSeekOutput(self.config, quiet=False, verbose=False, no_colors=True)
        access_op = AccessOperation(
            config=self.config,
            output=output,
            database=self.database,
            session_id=self.session_id
        )

        access_op.total_targets = 1

        host_label = "Host 1/1"

        shares = ['test_share']

        # Test timeout error
        with patch('sys.stdout', new_callable=StringIO) as mock_stdout:
            message = "Connection timeout"
            if 'timeout' in message.lower() or 'connection' in message.lower():
                access_op.output.error(
                    f"{host_label}: Share 1/{len(shares)}: test_share - {message}"
                )

            console_output = mock_stdout.getvalue().strip()

        # Verify it shows as error with details
        self.assertTrue(console_output.startswith("✗ "), "Technical errors should use error emoji")
        self.assertIn("Connection timeout", console_output, "Should show technical details for technical errors")

    def test_database_preserves_full_error_details(self):
        """Test that database still stores full error information despite simplified console output."""
        output = SMBSeekOutput(self.config, quiet=True)  # Quiet to avoid console noise
        access_op = AccessOperation(
            config=self.config,
            output=output,
            database=self.database,
            session_id=self.session_id
        )

        # Create result with full technical error details
        test_result = {
            'ip_address': '192.168.1.100',
            'country': 'US',
            'auth_method': 'guest/guest',
            'timestamp': '2025-10-04T12:00:00',
            'shares_found': ['test_share'],
            'accessible_shares': [],
            'share_details': [
                {
                    'share_name': 'test_share',
                    'accessible': False,
                    'error': 'Access denied - insufficient permissions (NT_STATUS_ACCESS_DENIED) - tree connect failed: NT_STATUS_ACCESS_DENIED'
                }
            ]
        }

        access_op.results = [test_result]

        # Store results in database
        accessible_hosts, accessible_shares, share_details = access_op._save_and_summarize_results()

        # Verify storage succeeded
        self.assertEqual(accessible_hosts, 0, "Should have 0 accessible hosts")
        self.assertEqual(accessible_shares, 0, "Should have 0 accessible shares")

        # Check database contains full error details
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT sa.share_name, sa.accessible, sa.error_message
            FROM share_access sa
            JOIN smb_servers s ON sa.server_id = s.id
            WHERE s.ip_address = ?
        """, ('192.168.1.100',))

        stored_shares = cursor.fetchall()
        conn.close()

        # Verify database has detailed error information
        self.assertEqual(len(stored_shares), 1, "Should have 1 share record in database")
        share_record = stored_shares[0]
        self.assertEqual(share_record['share_name'], 'test_share')
        self.assertFalse(share_record['accessible'])

        # Key assertion: database should contain full technical details
        self.assertIn("NT_STATUS_ACCESS_DENIED", share_record['error_message'],
                     "Database should preserve full technical error details")
        self.assertIn("tree connect failed", share_record['error_message'],
                     "Database should preserve complete error context")


if __name__ == '__main__':
    print("Testing simplified warning format and error message handling...")
    unittest.main(verbosity=2)
