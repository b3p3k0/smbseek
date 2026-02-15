"""
RCE Verdict Taxonomy

Defines the verdict outcomes for RCE vulnerability assessment.
These verdicts represent the confidence level of vulnerability presence.
"""

from enum import Enum
from typing import Optional


class Verdict(str, Enum):
    """
    RCE assessment verdict taxonomy.

    Verdicts are ordered by severity for comparison purposes.
    The string inheritance allows direct serialization to JSON.
    """

    CONFIRMED = "confirmed"
    """Safe evidence proves vulnerability exists (e.g., FID0 STATUS_INSUFF_SERVER_RESOURCES)."""

    LIKELY = "likely"
    """Exposure is supported by passive signals but not provable via safe probes."""

    NOT_VULNERABLE = "not_vulnerable"
    """Signal truly excludes vulnerability (e.g., compression disabled for SMBGhost)."""

    NOT_ASSESSABLE = "not_assessable"
    """Assessment requires auth or intrusive probe that wasn't/can't be performed."""

    INSUFFICIENT_DATA = "insufficient_data"
    """Not enough telemetry to make any determination. Never report as 'clean'."""

    ERROR = "error"
    """Probe or analysis failed due to timeout, exception, or budget exhaustion."""

    @classmethod
    def from_string(cls, value: str) -> "Verdict":
        """
        Convert string to Verdict enum.

        Args:
            value: String representation of verdict

        Returns:
            Corresponding Verdict enum value

        Raises:
            ValueError: If string doesn't match any verdict
        """
        value_lower = value.lower().strip()
        for v in cls:
            if v.value == value_lower:
                return v
        raise ValueError(f"Unknown verdict: {value}")

    @property
    def severity_rank(self) -> int:
        """
        Get numeric severity rank for comparison.

        Higher rank = more severe/actionable finding.
        """
        ranks = {
            Verdict.CONFIRMED: 100,
            Verdict.LIKELY: 75,
            Verdict.NOT_ASSESSABLE: 50,
            Verdict.INSUFFICIENT_DATA: 25,
            Verdict.ERROR: 10,
            Verdict.NOT_VULNERABLE: 0,
        }
        return ranks.get(self, 0)

    def is_flagged(self) -> bool:
        """Check if this verdict should be flagged in UI (red indicator)."""
        return self in (Verdict.CONFIRMED, Verdict.LIKELY)

    def is_clean(self) -> bool:
        """Check if this verdict indicates no vulnerability found."""
        return self == Verdict.NOT_VULNERABLE

    def requires_attention(self) -> bool:
        """Check if this verdict requires user attention/follow-up."""
        return self in (Verdict.CONFIRMED, Verdict.LIKELY, Verdict.NOT_ASSESSABLE)


def verdict_to_rce_status(verdict: Verdict) -> str:
    """
    Convert Verdict to database rce_status value.

    Args:
        verdict: Verdict enum value

    Returns:
        Database status string: 'not_run' | 'clean' | 'flagged' | 'unknown' | 'error'
    """
    if verdict.is_flagged():
        return "flagged"
    elif verdict.is_clean():
        return "clean"
    elif verdict == Verdict.ERROR:
        return "error"
    elif verdict in (Verdict.NOT_ASSESSABLE, Verdict.INSUFFICIENT_DATA):
        return "unknown"
    else:
        return "not_run"


# Valid rce_status values for documentation/validation
VALID_RCE_STATUSES = {'not_run', 'clean', 'flagged', 'unknown', 'error'}


def compare_verdicts(v1: Verdict, v2: Verdict) -> int:
    """
    Compare two verdicts by severity.

    Args:
        v1: First verdict
        v2: Second verdict

    Returns:
        Negative if v1 < v2, zero if equal, positive if v1 > v2
    """
    return v1.severity_rank - v2.severity_rank


def highest_severity_verdict(verdicts: list) -> Optional[Verdict]:
    """
    Get the highest severity verdict from a list.

    Args:
        verdicts: List of Verdict enum values

    Returns:
        Highest severity verdict, or None if list is empty
    """
    if not verdicts:
        return None
    return max(verdicts, key=lambda v: v.severity_rank)


__all__ = [
    "Verdict",
    "verdict_to_rce_status",
    "compare_verdicts",
    "highest_severity_verdict",
    "VALID_RCE_STATUSES",
]
