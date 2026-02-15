"""
RCE Scanner Package

Lazy exports to avoid circular imports when only submodules (e.g., verdicts)
are needed. Public API remains unchanged.
"""

__version__ = "1.0.0"
__all__ = [
    "scan_rce_indicators",
    "get_scanner_info",
    "validate_scanner_setup",
    "FactCollector",
    "RCEScorer",
    "RCEReporter",
]


def __getattr__(name):
    if name in ("scan_rce_indicators", "get_scanner_info", "validate_scanner_setup"):
        from .scanner import scan_rce_indicators, get_scanner_info, validate_scanner_setup

        mapping = {
            "scan_rce_indicators": scan_rce_indicators,
            "get_scanner_info": get_scanner_info,
            "validate_scanner_setup": validate_scanner_setup,
        }
        return mapping[name]

    if name == "FactCollector":
        from .fact_collector import FactCollector
        return FactCollector

    if name == "RCEScorer":
        from .scorer import RCEScorer
        return RCEScorer

    if name == "RCEReporter":
        from .reporter import RCEReporter
        return RCEReporter

    raise AttributeError(f"module {__name__} has no attribute {name}")
