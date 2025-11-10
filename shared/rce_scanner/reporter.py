"""
RCE Reporter

Reporting and formatting for RCE vulnerability assessment results.
Provides structured output compatible with existing probe and access workflows.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class RCEReporter:
    """
    RCE analysis results reporter.

    Formats RCE analysis results into structured output compatible
    with existing probe cache and display systems.
    """

    def __init__(self):
        """Initialize RCE reporter."""
        self.report_stats = {
            "reports_generated": 0,
            "by_confidence": {"low confidence": 0},
            "by_status": {"analyzed": 0, "insufficient-data": 0}
        }

    def generate_report(self, rule_engine_result: Dict[str, Any],
                       scoring_result: Dict[str, Any],
                       host_facts: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate structured RCE analysis report.

        Args:
            rule_engine_result: Results from rule engine evaluation
            scoring_result: Results from RCE scoring
            host_facts: Normalized host facts

        Returns:
            Structured report dictionary for probe cache storage
        """
        self.report_stats["reports_generated"] += 1

        # Extract key information
        total_score = scoring_result.get("total_score", 0)
        confidence_level = scoring_result.get("confidence_level", "low confidence")
        risk_assessment = scoring_result.get("risk_assessment", "low")
        status = rule_engine_result.get("status", "analyzed")

        # Update statistics
        self.report_stats["by_confidence"][confidence_level] = (
            self.report_stats["by_confidence"].get(confidence_level, 0) + 1
        )
        self.report_stats["by_status"][status] = (
            self.report_stats["by_status"].get(status, 0) + 1
        )

        # Build main report structure
        report = {
            "score": total_score,
            "level": f"{risk_assessment} ({confidence_level})",
            "matched_rules": self._format_matched_rules(rule_engine_result.get("matched_rules", [])),
            "evidence": self._format_evidence(rule_engine_result.get("evidence", [])),
            "status": status,
            "timestamp": rule_engine_result.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "analysis_metadata": {
                "confidence": confidence_level,
                "risk_level": risk_assessment,
                "score_breakdown": scoring_result.get("score_breakdown", {}),
                "facts_analyzed": self._get_facts_summary(host_facts)
            }
        }

        return report

    def _format_matched_rules(self, matched_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format matched rules for report output."""
        formatted_rules = []

        for rule in matched_rules:
            if not isinstance(rule, dict):
                continue

            formatted_rule = {
                "name": rule.get("signature_name", "Unknown"),
                "cve_ids": rule.get("cve_ids", []),
                "score": rule.get("score", 0),
                "severity": rule.get("severity", "unknown"),
                "conditions_met": len(rule.get("matched_conditions", [])),
                "boosters_applied": len(rule.get("applied_boosters", []))
            }

            # Include specific conditions that matched
            conditions = rule.get("matched_conditions", [])
            if conditions:
                formatted_rule["conditions"] = [
                    {
                        "signal": cond.get("signal", ""),
                        "rationale": cond.get("rationale", "")
                    }
                    for cond in conditions if isinstance(cond, dict)
                ]

            formatted_rules.append(formatted_rule)

        return formatted_rules

    def _format_evidence(self, evidence: List[str]) -> List[str]:
        """Format evidence list for report output."""
        if not isinstance(evidence, list):
            return []

        # Filter and clean evidence entries
        formatted_evidence = []
        seen_evidence = set()

        for item in evidence:
            if isinstance(item, str) and item.strip():
                clean_evidence = item.strip()
                if clean_evidence not in seen_evidence:
                    formatted_evidence.append(clean_evidence)
                    seen_evidence.add(clean_evidence)

        return formatted_evidence

    def _get_facts_summary(self, host_facts: Dict[str, Any]) -> Dict[str, Any]:
        """Create summary of facts used in analysis."""
        summary = {}

        # Key facts for transparency
        fact_keys = [
            "ip_address", "supports_smb1", "supports_smb2", "supports_smb3",
            "anonymous_access", "has_admin_access", "has_accessible_shares",
            "detected_os", "known_vulns_count"
        ]

        for key in fact_keys:
            if key in host_facts:
                summary[key] = host_facts[key]

        # Count-based summaries
        summary["accessible_shares_count"] = len(host_facts.get("accessible_shares", []))
        summary["admin_shares_count"] = len(host_facts.get("admin_shares_accessible", []))
        summary["shodan_ports_count"] = len(host_facts.get("shodan_ports", []))

        return summary

    def generate_summary_text(self, report: Dict[str, Any]) -> str:
        """
        Generate human-readable summary text for display.

        Args:
            report: RCE analysis report dictionary

        Returns:
            Formatted summary text
        """
        score = report.get("score", 0)
        level = report.get("level", "unknown")
        matched_count = len(report.get("matched_rules", []))
        status = report.get("status", "analyzed")

        if status == "insufficient-data":
            return f"RCE Analysis: {score}/100 ({level}) - Limited data available"

        if matched_count == 0:
            return f"RCE Analysis: {score}/100 ({level}) - No specific vulnerabilities detected"

        rule_names = [rule.get("name", "Unknown") for rule in report.get("matched_rules", [])]
        if len(rule_names) == 1:
            return f"RCE Analysis: {score}/100 ({level}) - Potential {rule_names[0]} vulnerability"
        else:
            return f"RCE Analysis: {score}/100 ({level}) - {matched_count} potential vulnerabilities detected"

    def generate_verbose_text(self, report: Dict[str, Any]) -> List[str]:
        """
        Generate verbose analysis text for detailed output.

        Args:
            report: RCE analysis report dictionary

        Returns:
            List of formatted text lines for verbose display
        """
        lines = []

        # Header
        score = report.get("score", 0)
        level = report.get("level", "unknown")
        lines.append(f"RCE Vulnerability Analysis: {score}/100 ({level})")

        # Status
        status = report.get("status", "analyzed")
        if status == "insufficient-data":
            lines.append("  Status: Analysis limited by insufficient telemetry data")
        else:
            lines.append(f"  Status: {status.title()}")

        # Matched rules
        matched_rules = report.get("matched_rules", [])
        if matched_rules:
            lines.append(f"  Matched Signatures: {len(matched_rules)}")
            for rule in matched_rules[:3]:  # Show first 3
                name = rule.get("name", "Unknown")
                rule_score = rule.get("score", 0)
                severity = rule.get("severity", "unknown")
                lines.append(f"    - {name}: {rule_score} points ({severity} severity)")

            if len(matched_rules) > 3:
                lines.append(f"    ... and {len(matched_rules) - 3} more")

        # Evidence (top few items)
        evidence = report.get("evidence", [])
        if evidence:
            lines.append(f"  Evidence: {len(evidence)} indicators")
            for item in evidence[:2]:  # Show first 2
                lines.append(f"    - {item}")

            if len(evidence) > 2:
                lines.append(f"    ... and {len(evidence) - 2} more indicators")

        # Facts summary
        facts = report.get("analysis_metadata", {}).get("facts_analyzed", {})
        if facts:
            key_facts = []
            if facts.get("supports_smb1"):
                key_facts.append("SMB1 enabled")
            if facts.get("anonymous_access"):
                key_facts.append("anonymous access")
            if facts.get("has_admin_access"):
                key_facts.append("admin shares accessible")

            if key_facts:
                lines.append(f"  Key Risk Factors: {', '.join(key_facts)}")

        return lines

    def get_report_stats(self) -> Dict[str, Any]:
        """Get statistics about generated reports."""
        return self.report_stats.copy()

    def reset_stats(self) -> None:
        """Reset reporting statistics."""
        self.report_stats = {
            "reports_generated": 0,
            "by_confidence": {"low confidence": 0},
            "by_status": {"analyzed": 0, "insufficient-data": 0}
        }

    def validate_report_structure(self, report: Dict[str, Any]) -> bool:
        """
        Validate report structure meets expected format.

        Args:
            report: Generated report dictionary

        Returns:
            True if report structure is valid
        """
        required_keys = ["score", "level", "matched_rules", "evidence", "status", "timestamp"]

        for key in required_keys:
            if key not in report:
                return False

        # Validate score is integer 0-100
        score = report.get("score")
        if not isinstance(score, int) or not (0 <= score <= 100):
            return False

        # Validate lists
        if not isinstance(report.get("matched_rules"), list):
            return False

        if not isinstance(report.get("evidence"), list):
            return False

        return True