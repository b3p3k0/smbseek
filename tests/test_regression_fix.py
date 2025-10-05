#!/usr/bin/env python3
"""
Regression test for accessible shares database storage bug fix.

Tests that the fix for the workflow unification regression correctly
stores accessible shares in the database.
"""

import sys
import os
import unittest
import tempfile
import sqlite3
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from commands.access import AccessOperation
from shared.config import SMBSeekConfig
from shared.output import SMBSeekOutput
from shared.database import SMBSeekWorkflowDatabase


class TestRegressionFix(unittest.TestCase):
    """Test that the regression fix correctly stores accessible shares."""

    def setUp(self):
        """Set up test fixtures with real database."""
        # Create temporary database
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db')
        os.close(self.db_fd)

        # Create real config and components
        self.config = SMBSeekConfig()
        self.config.config['database']['path'] = self.db_path

        self.output = SMBSeekOutput(self.config, quiet=True)
        self.database = SMBSeekWorkflowDatabase(self.config, verbose=False)

        # Initialize the database schema
        self.database.db_manager.initialize_database()

        self.session_id = self.database.create_session('test_regression')

        # Create AccessOperation
        self.access_op = AccessOperation(
            config=self.config,
            output=self.output,
            database=self.database,
            session_id=self.session_id
        )

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self.database, 'close'):
            self.database.close()
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_accessible_shares_stored_correctly(self):
        """Test that accessible shares are correctly stored in database."""
        # Create a sample result that mimics successful share enumeration
        test_result = {
            'ip_address': '192.168.1.100',
            'country': 'US',
            'auth_method': 'guest/guest',
            'timestamp': '2025-10-04T12:00:00',
            'shares_found': ['public', 'shared', 'files'],
            'accessible_shares': ['public', 'shared'],
            'share_details': [
                {'share_name': 'public', 'accessible': True, 'error': None},
                {'share_name': 'shared', 'accessible': True, 'error': None},
                {'share_name': 'files', 'accessible': False, 'error': 'Access denied'}
            ]
        }

        # First need to create a server record in smb_servers table
        # Simulate this being created by discovery operation
        server_id = self.database.dal.get_or_create_server(
            ip_address='192.168.1.100',
            country='US',
            auth_method='guest/guest'
        )

        # Set up the results list as it would be after process_target()
        self.access_op.results = [test_result]

        # Call the fixed _save_and_summarize_results method
        accessible_hosts, accessible_shares, share_details = self.access_op._save_and_summarize_results()

        # Verify the method returns correct summary statistics
        self.assertEqual(accessible_hosts, 1, "Should report 1 accessible host")
        self.assertEqual(accessible_shares, 2, "Should report 2 accessible shares")
        self.assertEqual(len(share_details), 2, "Should return 2 share detail records")

        # Verify data was actually stored in database
        # Check that share_access table has the correct records
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Query share_access table
        cursor.execute("""
            SELECT sa.share_name, sa.accessible, s.ip_address
            FROM share_access sa
            JOIN smb_servers s ON sa.server_id = s.id
            WHERE s.ip_address = ?
            ORDER BY sa.share_name
        """, ('192.168.1.100',))

        stored_shares = cursor.fetchall()
        conn.close()

        # Verify correct data in database
        self.assertEqual(len(stored_shares), 3, "Should have 3 share records (all shares found)")

        # Check that accessible shares are marked correctly
        accessible_count = sum(1 for share in stored_shares if share['accessible'])
        self.assertEqual(accessible_count, 2, "Should have 2 accessible shares in database")

        # Check specific shares
        share_dict = {share['share_name']: share['accessible'] for share in stored_shares}
        self.assertTrue(share_dict.get('public'), "public share should be accessible")
        self.assertTrue(share_dict.get('shared'), "shared share should be accessible")
        self.assertFalse(share_dict.get('files'), "files share should not be accessible")

    def test_console_output_matches_database_storage(self):
        """Test that console output metrics match what gets stored in database."""
        # This is the core issue from the bug report - console shows accessible
        # shares but database shows 0

        test_result = {
            'ip_address': '138.201.8.183',
            'country': 'DE',
            'auth_method': 'guest/guest',
            'timestamp': '2025-10-04T12:00:00',
            'shares_found': ['public'],
            'accessible_shares': ['public'],
            'share_details': [
                {'share_name': 'public', 'accessible': True, 'error': None}
            ]
        }

        # Create server record
        server_id = self.database.dal.get_or_create_server(
            ip_address='138.201.8.183',
            country='DE',
            auth_method='guest/guest'
        )

        # Set up results
        self.access_op.results = [test_result]

        # Call storage method
        accessible_hosts, accessible_shares, share_details = self.access_op._save_and_summarize_results()

        # Verify console output metrics
        self.assertEqual(accessible_hosts, 1, "Console should show 1 accessible host")
        self.assertEqual(accessible_shares, 1, "Console should show 1 accessible share")

        # Verify database has matching data
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COUNT(*) as accessible_count
            FROM share_access sa
            JOIN smb_servers s ON sa.server_id = s.id
            WHERE s.ip_address = ? AND sa.accessible = 1
        """, ('138.201.8.183',))

        db_accessible_count = cursor.fetchone()['accessible_count']
        conn.close()

        # This is the key assertion - database should match console output
        self.assertEqual(db_accessible_count, 1,
                        "Database should show 1 accessible share (matching console output)")


if __name__ == '__main__':
    print("Testing regression fix for accessible shares database storage...")
    unittest.main(verbosity=2)