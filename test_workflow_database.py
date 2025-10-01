#!/usr/bin/env python3
"""
Unit tests for SMBSeek workflow database functions.

Tests the _get_recent_accessible_shares() and _get_recent_file_manifests()
functions to ensure they use the correct column names and return expected results.
"""

import sys
import os
import unittest
import sqlite3
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'commands'))

from commands.run import WorkflowOrchestrator


class TestWorkflowDatabase(unittest.TestCase):
    """Test cases for workflow database functions."""

    def setUp(self):
        """Set up test fixtures with in-memory database."""
        # Create mock args object
        self.mock_args = Mock()
        self.mock_args.config = 'conf/config.json'
        self.mock_args.quiet = False
        self.mock_args.verbose = True
        self.mock_args.no_colors = True
        self.mock_args.country = 'US'
        self.mock_args.pause_between_steps = False

        # Create in-memory database
        self.db_conn = sqlite3.connect(':memory:')
        self.db_conn.row_factory = sqlite3.Row

        # Create required tables with correct schema
        self.db_conn.execute('''
            CREATE TABLE smb_servers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                country VARCHAR(100),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.db_conn.execute('''
            CREATE TABLE share_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                share_name VARCHAR(255) NOT NULL,
                accessible BOOLEAN NOT NULL DEFAULT FALSE,
                test_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES smb_servers(id)
            )
        ''')

        self.db_conn.execute('''
            CREATE TABLE file_manifests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                session_id INTEGER NOT NULL,
                share_name VARCHAR(255) NOT NULL,
                file_path TEXT NOT NULL,
                discovery_timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES smb_servers(id)
            )
        ''')

        self.db_conn.commit()

        # Insert test data
        self._insert_test_data()

        # Mock external dependencies and create orchestrator
        with patch('commands.run.load_config'), \
             patch('commands.run.create_output_manager'), \
             patch('commands.run.create_workflow_database'), \
             patch('commands.run.create_reporter'):
            self.orchestrator = WorkflowOrchestrator(self.mock_args)

            # Mock the database manager to use our in-memory database
            mock_db_manager = Mock()
            mock_db_manager.execute_query = self._execute_query
            self.orchestrator.database = Mock()
            self.orchestrator.database.db_manager = mock_db_manager

    def _execute_query(self, query):
        """Execute query on our in-memory database."""
        cursor = self.db_conn.execute(query)
        return [dict(row) for row in cursor.fetchall()]

    def _insert_test_data(self):
        """Insert test data into the database."""
        # Insert test server
        cursor = self.db_conn.execute(
            "INSERT INTO smb_servers (ip_address, country) VALUES (?, ?)",
            ('192.168.1.100', 'US')
        )
        server_id = cursor.lastrowid

        # Insert recent accessible share (within last hour) - use SQLite datetime
        self.db_conn.execute(
            "INSERT INTO share_access (server_id, session_id, share_name, accessible, test_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-30 minutes'))",
            (server_id, 1, 'recent_share', 1)
        )

        # Insert old accessible share (more than 1 hour ago) - use SQLite datetime
        self.db_conn.execute(
            "INSERT INTO share_access (server_id, session_id, share_name, accessible, test_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-2 hours'))",
            (server_id, 1, 'old_share', 1)
        )

        # Insert inaccessible share (recent but not accessible) - use SQLite datetime
        self.db_conn.execute(
            "INSERT INTO share_access (server_id, session_id, share_name, accessible, test_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-30 minutes'))",
            (server_id, 1, 'inaccessible_share', 0)
        )

        # Insert recent file manifests - use SQLite datetime
        self.db_conn.execute(
            "INSERT INTO file_manifests (server_id, session_id, share_name, file_path, discovery_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-30 minutes'))",
            (server_id, 1, 'recent_share', '/path/to/file1.txt')
        )

        self.db_conn.execute(
            "INSERT INTO file_manifests (server_id, session_id, share_name, file_path, discovery_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-30 minutes'))",
            (server_id, 1, 'recent_share', '/path/to/file2.txt')
        )

        # Insert old file manifest - use SQLite datetime
        self.db_conn.execute(
            "INSERT INTO file_manifests (server_id, session_id, share_name, file_path, discovery_timestamp) VALUES (?, ?, ?, ?, datetime('now', 'localtime', '-2 hours'))",
            (server_id, 1, 'old_share', '/path/to/old_file.txt')
        )

        self.db_conn.commit()

    def test_get_recent_accessible_shares(self):
        """Test that _get_recent_accessible_shares returns recent accessible shares only."""
        shares = self.orchestrator._get_recent_accessible_shares()

        # Should return only the recent accessible share
        self.assertEqual(len(shares), 1)
        self.assertEqual(shares[0]['ip'], '192.168.1.100')
        self.assertEqual(shares[0]['share'], 'recent_share')

        # Should not include old shares or inaccessible shares
        share_names = [s['share'] for s in shares]
        self.assertNotIn('old_share', share_names)
        self.assertNotIn('inaccessible_share', share_names)

    def test_get_recent_file_manifests(self):
        """Test that _get_recent_file_manifests returns correct count of recent files."""
        file_count = self.orchestrator._get_recent_file_manifests()

        # Should return count of recent files (2 files within last hour)
        self.assertEqual(file_count, 2)

    def test_empty_database(self):
        """Test functions with empty database return empty results."""
        # Clear the database
        self.db_conn.execute("DELETE FROM file_manifests")
        self.db_conn.execute("DELETE FROM share_access")
        self.db_conn.execute("DELETE FROM smb_servers")
        self.db_conn.commit()

        shares = self.orchestrator._get_recent_accessible_shares()
        file_count = self.orchestrator._get_recent_file_manifests()

        self.assertEqual(shares, [])
        self.assertEqual(file_count, 0)

    def test_database_error_handling(self):
        """Test that database errors are handled gracefully."""
        # Mock a database error
        def error_query(query):
            raise sqlite3.Error("Database error")

        self.orchestrator.database.db_manager.execute_query = error_query

        shares = self.orchestrator._get_recent_accessible_shares()
        file_count = self.orchestrator._get_recent_file_manifests()

        # Should return empty results, not raise exceptions
        self.assertEqual(shares, [])
        self.assertEqual(file_count, 0)

    def tearDown(self):
        """Clean up test fixtures."""
        self.db_conn.close()


class TestColumnNameRegression(unittest.TestCase):
    """Regression tests specifically for the column name bug fix."""

    def test_accessible_shares_uses_test_timestamp(self):
        """Test that the query uses test_timestamp column."""
        # Create mock orchestrator to inspect the query
        mock_args = Mock()
        mock_args.config = 'conf/config.json'
        mock_args.quiet = True
        mock_args.verbose = False
        mock_args.no_colors = True
        mock_args.country = 'US'
        mock_args.pause_between_steps = False

        with patch('commands.run.load_config'), \
             patch('commands.run.create_output_manager'), \
             patch('commands.run.create_workflow_database'), \
             patch('commands.run.create_reporter'):
            orchestrator = WorkflowOrchestrator(mock_args)

            # Mock database manager to capture the query
            captured_query = None
            def capture_query(query):
                nonlocal captured_query
                captured_query = query
                return []

            mock_db_manager = Mock()
            mock_db_manager.execute_query = capture_query
            orchestrator.database = Mock()
            orchestrator.database.db_manager = mock_db_manager

            # Call the function
            orchestrator._get_recent_accessible_shares()

            # Verify the query uses test_timestamp, not timestamp
            self.assertIsNotNone(captured_query)
            self.assertIn('test_timestamp', captured_query)
            self.assertNotIn('sa.timestamp', captured_query)

    def test_file_manifests_uses_discovery_timestamp(self):
        """Test that the query uses discovery_timestamp column."""
        mock_args = Mock()
        mock_args.config = 'conf/config.json'
        mock_args.quiet = True
        mock_args.verbose = False
        mock_args.no_colors = True
        mock_args.country = 'US'
        mock_args.pause_between_steps = False

        with patch('commands.run.load_config'), \
             patch('commands.run.create_output_manager'), \
             patch('commands.run.create_workflow_database'), \
             patch('commands.run.create_reporter'):
            orchestrator = WorkflowOrchestrator(mock_args)

            # Mock database manager to capture the query
            captured_query = None
            def capture_query(query):
                nonlocal captured_query
                captured_query = query
                return [{'file_count': 0}]

            mock_db_manager = Mock()
            mock_db_manager.execute_query = capture_query
            orchestrator.database = Mock()
            orchestrator.database.db_manager = mock_db_manager

            # Call the function
            orchestrator._get_recent_file_manifests()

            # Verify the query uses discovery_timestamp, not timestamp
            self.assertIsNotNone(captured_query)
            self.assertIn('discovery_timestamp', captured_query)
            self.assertNotIn('WHERE timestamp', captured_query)


if __name__ == '__main__':
    print("Running SMBSeek workflow database tests...")
    print("Note: These tests use in-memory databases and do not make network connections.")

    unittest.main(verbosity=2)