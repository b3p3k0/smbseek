"""
RCE Rules Engine

Processing engine for evaluating RCE signatures against host context.
Implements scoring logic and evidence collection for vulnerability assessment.
"""

import logging
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from datetime import datetime

from .loader import Signature

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Represents a matched RCE signature with evidence."""
    signature: Signature
    score: float
    matched_conditions: List[Dict[str, Any]]
    applied_boosters: List[Dict[str, Any]]
    evidence: List[str]
    confidence: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "signature_name": self.signature.name,
            "cve_ids": self.signature.cve_ids,
            "score": self.score,
            "confidence": self.confidence,
            "matched_conditions": self.matched_conditions,
            "applied_boosters": self.applied_boosters,
            "evidence": self.evidence,
            "severity": self.signature.severity,
            "risk_band": self.signature.risk_band
        }


@dataclass
class RuleEngineResult:
    """Complete results from rule engine evaluation."""
    total_score: float
    confidence_level: str
    matched_rules: List[RuleMatch]
    evidence: List[str]
    status: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "score": min(100, max(0, int(self.total_score))),  # Ensure 0-100 range
            "level": self.confidence_level,
            "matched_rules": [rule.to_dict() for rule in self.matched_rules],
            "evidence": self.evidence,
            "status": self.status,
            "timestamp": self.timestamp
        }


class RuleEngine:
    """
    RCE signature evaluation engine.

    Processes loaded signatures against host context to identify
    potential RCE vulnerabilities with confidence scoring.
    """

    # Signal extractors for different data sources
    SIGNAL_EXTRACTORS = {
        "smb.negotiation.supports_smb1": lambda ctx: ctx.get("smb_dialects", []).count("SMB1") > 0,
        "smb.negotiation.supports_smb2": lambda ctx: any(d.startswith("SMB2") for d in ctx.get("smb_dialects", [])),
        "smb.negotiation.supports_smb3": lambda ctx: any(d.startswith("SMB3") for d in ctx.get("smb_dialects", [])),
        "host.os_detection": lambda ctx: ctx.get("os_hints", {}).get("detected_os", "").lower(),
        "host.shares_accessible": lambda ctx: len(ctx.get("accessible_shares", [])) > 0,
        "host.admin_shares_accessible": lambda ctx: any(
            share.lower() in ["admin$", "c$", "ipc$"] for share in ctx.get("accessible_shares", [])
        ),
        "host.anonymous_access": lambda ctx: ctx.get("auth_method", "") in ["anonymous", "guest", ""],
        "host.shodan_ports": lambda ctx: ctx.get("shodan_data", {}).get("ports", []),
        "host.shodan_vulns": lambda ctx: ctx.get("shodan_data", {}).get("vulns", []),
    }

    def __init__(self, signatures: List[Signature]):
        """
        Initialize rule engine with loaded signatures.

        Args:
            signatures: List of validated Signature instances
        """
        self.signatures = signatures
        self.evaluation_stats = {
            "total_evaluations": 0,
            "signatures_matched": 0,
            "conditions_evaluated": 0
        }

    def evaluate_host(self, host_context: Dict[str, Any]) -> RuleEngineResult:
        """
        Evaluate all signatures against a host context.

        Args:
            host_context: Dictionary containing host information from probe/access

        Returns:
            RuleEngineResult with scoring and evidence
        """
        self.evaluation_stats["total_evaluations"] += 1

        matched_rules = []
        all_evidence = []
        total_score = 0.0

        # Determine status based on available data
        status = self._determine_status(host_context)

        for signature in self.signatures:
            try:
                rule_match = self._evaluate_signature(signature, host_context)
                if rule_match:
                    matched_rules.append(rule_match)
                    total_score += rule_match.score
                    all_evidence.extend(rule_match.evidence)
                    self.evaluation_stats["signatures_matched"] += 1

            except Exception as e:
                logger.warning(f"Error evaluating signature {signature.name}: {str(e)}")

        # Cap total score at 100
        total_score = min(100.0, total_score)

        # Always assign "low confidence" for this phase
        confidence_level = "low confidence"

        # Remove duplicate evidence entries
        unique_evidence = list(dict.fromkeys(all_evidence))

        return RuleEngineResult(
            total_score=total_score,
            confidence_level=confidence_level,
            matched_rules=matched_rules,
            evidence=unique_evidence,
            status=status,
            timestamp=datetime.utcnow().isoformat() + "Z"
        )

    def _determine_status(self, host_context: Dict[str, Any]) -> str:
        """Determine analysis status based on available data."""
        # Check for key data sources
        has_smb_info = bool(host_context.get("smb_dialects"))
        has_share_info = bool(host_context.get("accessible_shares"))
        has_auth_info = bool(host_context.get("auth_method"))

        if not (has_smb_info or has_share_info or has_auth_info):
            return "insufficient-data"

        return "analyzed"

    def _evaluate_signature(self, signature: Signature, host_context: Dict[str, Any]) -> Optional[RuleMatch]:
        """
        Evaluate a single signature against host context.

        Args:
            signature: Signature to evaluate
            host_context: Host information dictionary

        Returns:
            RuleMatch if signature matches, None otherwise
        """
        matched_conditions = []
        evidence = []

        # Evaluate conditions
        for condition in signature.conditions:
            try:
                if self._evaluate_condition(condition, host_context):
                    matched_conditions.append(condition)
                    evidence.append(f"Condition met: {condition['rationale']}")
                    self.evaluation_stats["conditions_evaluated"] += 1
            except Exception as e:
                logger.debug(f"Error evaluating condition in {signature.name}: {str(e)}")

        # Check if minimum required signals are met
        if len(matched_conditions) < signature.required_signals:
            return None

        # Calculate base score
        score = signature.base_weight

        # Apply boosters
        applied_boosters = []
        for booster in signature.boosters:
            try:
                if self._evaluate_booster(booster, host_context):
                    applied_boosters.append(booster)
                    score += booster.get("weight", 0)
                    evidence.append(f"Booster applied: {booster['description']}")
            except Exception as e:
                logger.debug(f"Error evaluating booster in {signature.name}: {str(e)}")

        return RuleMatch(
            signature=signature,
            score=score,
            matched_conditions=matched_conditions,
            applied_boosters=applied_boosters,
            evidence=evidence,
            confidence="low"  # Always low confidence for this phase
        )

    def _evaluate_condition(self, condition: Dict[str, Any], host_context: Dict[str, Any]) -> bool:
        """
        Evaluate a single condition against host context.

        Args:
            condition: Condition dictionary from signature
            host_context: Host context data

        Returns:
            True if condition is satisfied
        """
        signal_name = condition.get("signal")
        expectation = condition.get("expectation")

        if not signal_name or expectation is None:
            return False

        # Extract signal value using appropriate extractor
        signal_value = self._extract_signal(signal_name, host_context)

        # Compare with expectation
        return self._compare_signal_value(signal_value, expectation)

    def _evaluate_booster(self, booster: Dict[str, Any], host_context: Dict[str, Any]) -> bool:
        """
        Evaluate a booster condition.
        For this initial implementation, boosters are not automatically evaluated.
        This is a placeholder for future enhancement.

        Args:
            booster: Booster dictionary from signature
            host_context: Host context data

        Returns:
            False (boosters not implemented yet)
        """
        # TODO: Implement booster evaluation logic
        # For now, boosters are descriptive only
        return False

    def _extract_signal(self, signal_name: str, host_context: Dict[str, Any]) -> Any:
        """
        Extract a signal value from host context.

        Args:
            signal_name: Name of the signal to extract
            host_context: Host context data

        Returns:
            Extracted signal value or None if not available
        """
        # Use registered extractor if available
        extractor = self.SIGNAL_EXTRACTORS.get(signal_name)
        if extractor:
            try:
                return extractor(host_context)
            except Exception as e:
                logger.debug(f"Error extracting signal {signal_name}: {str(e)}")
                return None

        # Fallback to direct key lookup with dot notation support
        keys = signal_name.split('.')
        value = host_context

        try:
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                else:
                    return None
        except Exception:
            return None

        return value

    def _compare_signal_value(self, signal_value: Any, expectation: Any) -> bool:
        """
        Compare extracted signal value with expected value.

        Args:
            signal_value: Extracted value from host context
            expectation: Expected value from signature condition

        Returns:
            True if values match according to comparison logic
        """
        # Handle None/missing values
        if signal_value is None:
            if isinstance(expectation, str) and expectation.lower() == "missing":
                return True
            return expectation is None

        # Direct equality comparison
        if signal_value == expectation:
            return True

        # String-based comparisons
        if isinstance(expectation, str):
            expectation_lower = expectation.lower()
            if expectation_lower == "missing" and not signal_value:
                return True
            if expectation_lower == "present" and bool(signal_value):
                return True
            if isinstance(signal_value, str) and expectation_lower in signal_value.lower():
                return True

        # Boolean comparisons
        if isinstance(expectation, bool):
            return bool(signal_value) == expectation

        return False

    def get_evaluation_stats(self) -> Dict[str, Any]:
        """Get statistics about rule engine usage."""
        return self.evaluation_stats.copy()

    def get_signature_names(self) -> List[str]:
        """Get list of loaded signature names."""
        return [sig.name for sig in self.signatures]

    def get_signature_count(self) -> int:
        """Get count of loaded signatures."""
        return len(self.signatures)
