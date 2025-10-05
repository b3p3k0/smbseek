#!/usr/bin/env python3
"""
Integration tests for SMBSeek access concurrency functionality.

Tests the real configuration loading and integration between components
to ensure concurrency works in practice.
"""

import sys
import os
import unittest
import tempfile
import json
from unittest.mock import Mock, patch

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import SMBSeekConfig
from shared.output import SMBSeekOutput


class TestConfigurationIntegration(unittest.TestCase):
    """Test real configuration loading with concurrency settings."""

    def test_default_config_includes_access_section(self):
        """Test that default configuration includes access section with max_concurrent_hosts."""
        config = SMBSeekConfig()

        # Verify access section exists
        access_config = config.get("access")
        self.assertIsNotNone(access_config, "Should have access configuration section")

        # Verify max_concurrent_hosts setting
        max_concurrent = access_config.get("max_concurrent_hosts")
        self.assertEqual(max_concurrent, 1, "Should default to 1 concurrent host")

        # Verify getter method works
        getter_result = config.get_max_concurrent_hosts()
        self.assertEqual(getter_result, 1, "Getter should return 1")

    def test_custom_config_override(self):
        """Test custom configuration overrides work correctly."""
        # Create a temporary config file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            custom_config = {
                "access": {
                    "max_concurrent_hosts": 5
                },
                "output": {
                    "colors_enabled": False
                }
            }
            json.dump(custom_config, f)
            temp_config_path = f.name

        try:
            # Load config with custom file
            config = SMBSeekConfig(temp_config_path)

            # Verify custom value is loaded
            max_concurrent = config.get_max_concurrent_hosts()
            self.assertEqual(max_concurrent, 5, "Should load custom value 5")

            # Verify other defaults are preserved
            timeout = config.get_connection_timeout()
            self.assertEqual(timeout, 30, "Should preserve default timeout")

        finally:
            # Clean up temp file
            os.unlink(temp_config_path)

    def test_invalid_config_values_fallback(self):
        """Test that invalid config values fall back to safe defaults."""
        # Create config with invalid values
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            invalid_config = {
                "access": {
                    "max_concurrent_hosts": -5  # Invalid negative value
                }
            }
            json.dump(invalid_config, f)
            temp_config_path = f.name

        try:
            config = SMBSeekConfig(temp_config_path)

            # Should fallback to 1 for invalid value
            max_concurrent = config.get_max_concurrent_hosts()
            self.assertEqual(max_concurrent, 1, "Should fallback to 1 for negative value")

        finally:
            os.unlink(temp_config_path)

    def test_config_json_snapshot_includes_access(self):
        """Test that config snapshot (for database storage) includes access settings."""
        config = SMBSeekConfig()

        # Get the full config dict
        full_config = config.config

        # Verify access section is present in the snapshot
        self.assertIn("access", full_config, "Config snapshot should include access section")
        self.assertIn("max_concurrent_hosts", full_config["access"], "Should include max_concurrent_hosts")
        self.assertEqual(full_config["access"]["max_concurrent_hosts"], 1, "Should show default value")


class TestThreadSafeOutputIntegration(unittest.TestCase):
    """Test thread-safe output with real configuration."""

    def test_output_manager_has_print_lock(self):
        """Test that output manager is created with thread lock."""
        config = SMBSeekConfig()
        output = SMBSeekOutput(config, quiet=False, verbose=True, no_colors=True)

        # Verify lock exists
        self.assertTrue(hasattr(output, '_print_lock'), "Should have _print_lock attribute")

        # Verify it's a threading.Lock
        import threading
        self.assertIsInstance(output._print_lock, threading.Lock, "Should be a threading.Lock")

    def test_output_methods_use_locking(self):
        """Test that output methods properly use the lock."""
        config = SMBSeekConfig()
        output = SMBSeekOutput(config, quiet=False, verbose=True, no_colors=True)

        # Mock the print function to capture calls and verify lock context
        with patch('builtins.print') as mock_print:
            # Test various output methods
            output.info("Test info message")
            output.success("Test success message")
            output.error("Test error message")
            output.warning("Test warning message")

            # Verify all methods called print (meaning they got through the lock)
            self.assertGreaterEqual(mock_print.call_count, 4, "Should call print for each message")

            # Verify the messages contain expected content
            call_args = [call[0][0] for call in mock_print.call_args_list]
            self.assertTrue(any("Test info message" in arg for arg in call_args), "Should contain info message")
            self.assertTrue(any("Test success message" in arg for arg in call_args), "Should contain success message")

    def test_quiet_mode_still_has_lock(self):
        """Test that lock exists even in quiet mode."""
        config = SMBSeekConfig()
        output = SMBSeekOutput(config, quiet=True, verbose=False, no_colors=True)

        # Verify lock exists even in quiet mode
        self.assertTrue(hasattr(output, '_print_lock'), "Should have _print_lock even in quiet mode")

        import threading
        self.assertIsInstance(output._print_lock, threading.Lock, "Should be a threading.Lock")


class TestEndToEndConfiguration(unittest.TestCase):
    """Test configuration works properly with all components together."""

    def test_config_validation_edge_cases(self):
        """Test various edge cases for configuration validation."""
        test_cases = [
            # (config_value, expected_result, description)
            (1, 1, "Normal positive value"),
            (10, 10, "Larger positive value"),
            (0, 1, "Zero should fallback to 1"),
            (-1, 1, "Negative should fallback to 1"),
            (-100, 1, "Large negative should fallback to 1"),
            ("invalid", 1, "String should fallback to 1"),
            (1.5, 1, "Float should fallback to 1"),
            (None, 1, "None should fallback to 1"),
            ([], 1, "List should fallback to 1"),
            ({}, 1, "Dict should fallback to 1"),
        ]

        for config_value, expected, description in test_cases:
            with self.subTest(config_value=config_value, description=description):
                # Create temporary config
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    test_config = {
                        "access": {
                            "max_concurrent_hosts": config_value
                        }
                    }
                    json.dump(test_config, f)
                    temp_config_path = f.name

                try:
                    config = SMBSeekConfig(temp_config_path)
                    result = config.get_max_concurrent_hosts()
                    self.assertEqual(result, expected, f"Failed for {description}")
                finally:
                    os.unlink(temp_config_path)


if __name__ == '__main__':
    print("Running SMBSeek integration tests for concurrency...")
    print("Note: These tests verify real configuration and component integration.")

    unittest.main(verbosity=2)