"""Unit tests for probe indicator matching."""

import json
import tempfile
import unittest
from pathlib import Path

from gui.utils import probe_patterns


class TestProbePatterns(unittest.TestCase):
    def test_load_ransomware_indicators_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "config.json"
            config_path.write_text(json.dumps({
                "security": {
                    "ransomware_indicators": ["README-ID-*.txt", "HOW_TO_DECRYPT_FILES.txt"]
                }
            }), encoding="utf-8")
            indicators = probe_patterns.load_ransomware_indicators(str(config_path))
            self.assertIn("README-ID-*.txt", indicators)
            self.assertEqual(len(indicators), 2)

    def test_find_indicator_hits_flags_matches(self):
        indicators = ["README-ID-*.txt", "notes.txt"]
        patterns = probe_patterns.compile_indicator_patterns(indicators)
        snapshot = {
            "ip_address": "10.0.0.5",
            "shares": [
                {
                    "share": "C$",
                    "directories": [
                        {
                            "name": "Users",
                            "files": ["README-ID-12345.txt", "report.docx"]
                        }
                    ]
                }
            ]
        }
        analysis = probe_patterns.find_indicator_hits(snapshot, patterns)
        self.assertTrue(analysis["is_suspicious"])
        self.assertEqual(analysis["matches"][0]["indicator"], "README-ID-*.txt")

    def test_attach_indicator_analysis_adds_key(self):
        patterns = probe_patterns.compile_indicator_patterns(["+readme-warning+.txt"])
        snapshot = {
            "ip_address": "10.0.0.6",
            "shares": [
                {
                    "share": "Share",
                    "directories": [
                        {
                            "name": "Docs",
                            "files": ["manual.pdf"]
                        }
                    ]
                }
            ]
        }
        analysis = probe_patterns.attach_indicator_analysis(snapshot, patterns)
        self.assertIn("indicator_analysis", snapshot)
        self.assertFalse(analysis["is_suspicious"])


if __name__ == "__main__":
    unittest.main()
