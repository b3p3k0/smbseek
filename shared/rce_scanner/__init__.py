"""
RCE Scanner Package

RCE vulnerability detection and scoring for SMB enumeration.
Provides fact collection, scoring, and reporting capabilities
for defensive security analysis.

Main API:
    scan_rce_indicators(host_ctx) -> dict with score, level, matched_rules, evidence, status
"""

from .scanner import scan_rce_indicators, get_scanner_info, validate_scanner_setup
from .fact_collector import FactCollector
from .scorer import RCEScorer
from .reporter import RCEReporter

__version__ = "1.0.0"
__all__ = ["scan_rce_indicators", "get_scanner_info", "validate_scanner_setup", "FactCollector", "RCEScorer", "RCEReporter"]