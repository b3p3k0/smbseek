"""
Basic functionality tests for SMBSeek GUI components.

Tests the core functionality of backend interface, database access,
and dashboard components using mock data.
"""

import unittest
import sys
import os
from pathlib import Path

# Add GUI modules to path
gui_dir = Path(__file__).parent.parent
sys.path.insert(0, str(gui_dir / "utils"))
sys.path.insert(0, str(gui_dir / "components"))

from database_access import DatabaseReader
from backend_interface import BackendInterface
from style import get_theme


class TestBackendInterface(unittest.TestCase):
    """Test backend interface functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.backend = BackendInterface("../backend")
        self.backend.enable_mock_mode()
    
    def test_mock_mode_scan(self):
        """Test scan operation in mock mode."""
        countries = ["US", "GB"]
        results = self.backend.run_scan(countries)
        
        self.assertTrue(results["success"])
        self.assertEqual(results["countries"], countries)
        self.assertGreater(results["successful_auth"], 0)
    
    def test_backend_availability_check(self):
        """Test backend availability checking."""
        # Should return True in mock mode
        self.assertTrue(self.backend.is_backend_available())
    
    def test_version_info(self):
        """Test version information retrieval."""
        version = self.backend.get_backend_version()
        self.assertIsNotNone(version)
        self.assertIn("mock", version.lower())


class TestDatabaseReader(unittest.TestCase):
    """Test database reader functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.db_reader = DatabaseReader("../test_data/test_database.db")
        self.db_reader.enable_mock_mode()
    
    def test_dashboard_summary(self):
        """Test dashboard summary data retrieval."""
        summary = self.db_reader.get_dashboard_summary()
        
        self.assertIn("total_servers", summary)
        self.assertIn("accessible_shares", summary)
        self.assertIn("high_risk_vulnerabilities", summary)
        self.assertIn("recent_discoveries", summary)
        
        # Verify data types
        self.assertIsInstance(summary["total_servers"], int)
        self.assertIsInstance(summary["accessible_shares"], int)
    
    def test_top_findings(self):
        """Test top findings retrieval."""
        findings = self.db_reader.get_top_findings(limit=3)
        
        self.assertLessEqual(len(findings), 3)
        
        if findings:
            finding = findings[0]
            self.assertIn("ip_address", finding)
            self.assertIn("country", finding)
            self.assertIn("summary", finding)
    
    def test_country_breakdown(self):
        """Test country breakdown data."""
        countries = self.db_reader.get_country_breakdown()
        
        self.assertIsInstance(countries, dict)
        
        # Should have at least some test countries
        if countries:
            self.assertIn("US", countries)
    
    def test_server_list_pagination(self):
        """Test server list with pagination."""
        servers, total = self.db_reader.get_server_list(limit=2, offset=0)
        
        self.assertLessEqual(len(servers), 2)
        self.assertIsInstance(total, int)
        
        if servers:
            server = servers[0]
            self.assertIn("ip_address", server)
            self.assertIn("country", server)


class TestStyling(unittest.TestCase):
    """Test styling and theme functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.theme = get_theme()
    
    def test_color_definitions(self):
        """Test color palette completeness."""
        required_colors = [
            "primary_bg", "secondary_bg", "text", "success", 
            "warning", "error", "info", "accent"
        ]
        
        for color in required_colors:
            self.assertIn(color, self.theme.colors)
            self.assertIsInstance(self.theme.colors[color], str)
            self.assertTrue(self.theme.colors[color].startswith("#"))
    
    def test_font_definitions(self):
        """Test font configuration."""
        required_fonts = ["title", "heading", "body", "small", "mono"]
        
        for font_type in required_fonts:
            self.assertIn(font_type, self.theme.fonts)
            font_config = self.theme.fonts[font_type]
            self.assertEqual(len(font_config), 3)  # family, size, weight
    
    def test_severity_colors(self):
        """Test severity color mapping."""
        severities = ["critical", "high", "medium", "low"]
        
        for severity in severities:
            color = self.theme.get_severity_color(severity)
            self.assertIsInstance(color, str)
            self.assertTrue(color.startswith("#"))
    
    def test_icon_symbols(self):
        """Test icon symbol availability."""
        icons = ["success", "error", "warning", "info", "scan"]
        
        for icon in icons:
            symbol = self.theme.get_icon_symbol(icon)
            self.assertIsInstance(symbol, str)
            self.assertGreater(len(symbol), 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for component interaction."""
    
    def setUp(self):
        """Set up test environment."""
        self.backend = BackendInterface("../backend")
        self.backend.enable_mock_mode()
        
        self.db_reader = DatabaseReader("../test_data/test_database.db")
        self.db_reader.enable_mock_mode()
    
    def test_mock_mode_consistency(self):
        """Test that mock mode provides consistent data."""
        # Backend should provide scan results
        scan_results = self.backend.run_scan(["US"])
        self.assertTrue(scan_results["success"])
        
        # Database should provide dashboard data
        summary = self.db_reader.get_dashboard_summary()
        self.assertGreater(summary["total_servers"], 0)
        
        # Both should be using mock data
        self.assertTrue(self.backend.mock_mode)
        self.assertTrue(self.db_reader.mock_mode)
    
    def test_error_handling(self):
        """Test error handling in mock mode."""
        # Disable mock mode temporarily to test error handling
        self.backend.disable_mock_mode()
        
        # Should handle backend unavailability gracefully
        available = self.backend.is_backend_available()
        # Result depends on actual backend presence, but should not crash
        self.assertIsInstance(available, bool)


if __name__ == "__main__":
    # Run tests
    unittest.main(verbosity=2)