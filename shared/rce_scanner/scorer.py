"""
RCE Scorer

Scoring logic for RCE vulnerability assessment.
Implements additive scoring model with confidence levels.
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScoringResult:
    """Results from RCE scoring analysis."""
    total_score: int           # Final score (0-100)
    confidence_level: str      # Always "low confidence" for this phase
    risk_assessment: str       # Risk level based on score
    score_breakdown: Dict[str, float]  # Component score contributions


class RCEScorer:
    """
    RCE vulnerability scoring engine.

    Implements additive scoring model with configurable thresholds
    and confidence assessment. Always assigns "low confidence" for
    initial implementation phase.
    """

    # Risk level thresholds (based on 0-100 score)
    RISK_THRESHOLDS = {
        "low": (0, 25),
        "medium": (25, 60),
        "high": (60, 85),
        "critical": (85, 100)
    }

    def __init__(self):
        """Initialize RCE scorer."""
        self.scoring_stats = {
            "total_scored": 0,
            "scores_by_risk": {"low": 0, "medium": 0, "high": 0, "critical": 0}
        }

    def calculate_score(self, rule_matches: List[Dict[str, Any]],
                       host_facts: Dict[str, Any]) -> ScoringResult:
        """
        Calculate final RCE score from rule matches and host facts.

        Args:
            rule_matches: List of matched rules with individual scores
            host_facts: Normalized host facts for context

        Returns:
            ScoringResult with total score and assessment
        """
        self.scoring_stats["total_scored"] += 1

        # Calculate base score from rule matches (additive model)
        rule_score = self._calculate_rule_score(rule_matches)

        # Apply contextual modifiers
        context_modifiers = self._calculate_context_modifiers(host_facts)

        # Combine scores
        raw_score = rule_score + context_modifiers.get("modifier_total", 0)

        # Cap at 100 and ensure non-negative
        final_score = max(0, min(100, int(raw_score)))

        # Assess risk level
        risk_level = self._assess_risk_level(final_score)
        self.scoring_stats["scores_by_risk"][risk_level] += 1

        # Build score breakdown
        score_breakdown = {
            "rule_matches": rule_score,
            "context_modifiers": context_modifiers.get("modifier_total", 0),
            "raw_total": raw_score,
            "final_capped": final_score
        }
        score_breakdown.update(context_modifiers)

        return ScoringResult(
            total_score=final_score,
            confidence_level="low confidence",  # Always low for this phase
            risk_assessment=risk_level,
            score_breakdown=score_breakdown
        )

    def _calculate_rule_score(self, rule_matches: List[Dict[str, Any]]) -> float:
        """Calculate total score from matched rules (additive)."""
        total_score = 0.0

        for match in rule_matches:
            # Each rule match contributes its calculated score
            rule_score = match.get("score", 0)
            if isinstance(rule_score, (int, float)):
                total_score += rule_score

        return total_score

    def _calculate_context_modifiers(self, host_facts: Dict[str, Any]) -> Dict[str, float]:
        """
        Calculate contextual score modifiers based on host facts.

        Args:
            host_facts: Normalized host facts

        Returns:
            Dictionary of modifier components and total
        """
        modifiers = {}

        # Administrative access modifier
        if host_facts.get("has_admin_access", False):
            modifiers["admin_access_bonus"] = 10.0
        else:
            modifiers["admin_access_bonus"] = 0.0

        # Anonymous access modifier (higher risk)
        if host_facts.get("anonymous_access", False):
            modifiers["anonymous_access_bonus"] = 8.0
        else:
            modifiers["anonymous_access_bonus"] = 0.0

        # Multiple accessible shares modifier
        accessible_count = len(host_facts.get("accessible_shares", []))
        if accessible_count > 3:
            modifiers["many_shares_bonus"] = 5.0
        elif accessible_count > 0:
            modifiers["some_shares_bonus"] = 2.0
        else:
            modifiers["no_shares_penalty"] = -5.0

        # Known vulnerabilities from Shodan
        known_vulns = len(host_facts.get("shodan_vulns", []))
        if known_vulns > 0:
            modifiers["known_vulns_bonus"] = min(15.0, known_vulns * 5)
        else:
            modifiers["known_vulns_bonus"] = 0.0

        # Legacy protocol penalty (higher risk for SMB1)
        if host_facts.get("supports_smb1", False):
            modifiers["smb1_risk_bonus"] = 12.0
        else:
            modifiers["smb1_risk_bonus"] = 0.0

        # Modern security features (lower risk)
        if host_facts.get("signing_required", False):
            modifiers["signing_penalty"] = -3.0
        else:
            modifiers["signing_penalty"] = 0.0

        if host_facts.get("encryption_supported", False):
            modifiers["encryption_penalty"] = -3.0
        else:
            modifiers["encryption_penalty"] = 0.0

        # Calculate total modifier
        modifier_total = sum(modifiers.values())
        modifiers["modifier_total"] = modifier_total

        return modifiers

    def _assess_risk_level(self, score: int) -> str:
        """
        Assess risk level based on final score.

        Args:
            score: Final calculated score (0-100)

        Returns:
            Risk level string (low, medium, high, critical)
        """
        for level, (min_score, max_score) in self.RISK_THRESHOLDS.items():
            if min_score <= score < max_score:
                return level

        # Handle edge case of exactly 100
        if score >= 85:
            return "critical"

        return "low"  # Fallback

    def get_risk_threshold_info(self) -> Dict[str, tuple]:
        """Get risk level threshold configuration."""
        return self.RISK_THRESHOLDS.copy()

    def get_scoring_stats(self) -> Dict[str, Any]:
        """Get statistics about scoring operations."""
        return self.scoring_stats.copy()

    def reset_stats(self) -> None:
        """Reset scoring statistics."""
        self.scoring_stats = {
            "total_scored": 0,
            "scores_by_risk": {"low": 0, "medium": 0, "high": 0, "critical": 0}
        }

    def validate_rule_matches(self, rule_matches: List[Dict[str, Any]]) -> bool:
        """
        Validate rule matches structure for scoring.

        Args:
            rule_matches: List of rule match dictionaries

        Returns:
            True if structure is valid for scoring
        """
        if not isinstance(rule_matches, list):
            return False

        for match in rule_matches:
            if not isinstance(match, dict):
                return False

            # Must have score field
            if "score" not in match:
                return False

            # Score must be numeric
            score = match["score"]
            if not isinstance(score, (int, float)):
                return False

        return True