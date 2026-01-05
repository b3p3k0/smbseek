"""Probe snapshot indicator matching utilities."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from shared.config import SMBSeekConfig
except Exception:
    SMBSeekConfig = None

IndicatorPattern = Tuple[str, re.Pattern]


def load_ransomware_indicators(config_path: Optional[str]) -> List[str]:
    """Return ransomware indicator filenames from SMBSeek config (with defaults)."""
    indicators: List[str] = []

    # Preferred path: use SMBSeekConfig to merge user config with defaults
    if SMBSeekConfig:
        try:
            cfg = SMBSeekConfig(config_path)
            indicators = cfg.get("security", "ransomware_indicators", []) or []
        except Exception:
            indicators = []

    # Fallback: read raw JSON if config helper unavailable
    if not indicators and config_path:
        try:
            config_data = json.loads(Path(config_path).read_text(encoding="utf-8"))
            indicators = config_data.get("security", {}).get("ransomware_indicators", []) or []
        except Exception:
            indicators = []

    # Normalize and deduplicate
    normalized: List[str] = []
    seen = set()
    for entry in indicators:
        if not isinstance(entry, str):
            continue
        cleaned = entry.strip()
        if not cleaned or cleaned.lower() in seen:
            continue
        seen.add(cleaned.lower())
        normalized.append(cleaned)
    return normalized


def compile_indicator_patterns(indicators: Sequence[str]) -> List[IndicatorPattern]:
    compiled: List[IndicatorPattern] = []
    for indicator in indicators:
        regex = _indicator_to_regex(indicator)
        if regex:
            compiled.append((indicator, regex))
    return compiled


def _indicator_to_regex(indicator: str) -> Optional[re.Pattern]:
    indicator = indicator.strip()
    if not indicator:
        return None
    escaped = re.escape(indicator)
    escaped = escaped.replace(r"\*", ".*")
    escaped = escaped.replace(r"\?", ".")
    escaped = re.sub(r"\\\[.*?\\\]", ".+", escaped)
    escaped = re.sub(r"\\\{.*?\\\}", ".+", escaped)
    try:
        return re.compile(escaped, re.IGNORECASE)
    except re.error:
        return None


def find_indicator_hits(snapshot: Dict[str, Any], indicator_patterns: Sequence[IndicatorPattern]) -> Dict[str, Any]:
    matches: List[Dict[str, str]] = []
    for target_type, path in _iter_snapshot_paths(snapshot):
        for indicator, pattern in indicator_patterns:
            if pattern.search(path):
                matches.append({
                    "indicator": indicator,
                    "path": path,
                    "target": target_type,
                })
    return {
        "is_suspicious": bool(matches),
        "matches": matches,
    }


def attach_indicator_analysis(snapshot: Optional[Dict[str, Any]], indicator_patterns: Sequence[IndicatorPattern]) -> Dict[str, Any]:
    """Compute and attach indicator analysis to the snapshot dict."""
    if not snapshot:
        return {"is_suspicious": False, "matches": []}
    analysis = find_indicator_hits(snapshot, indicator_patterns)
    snapshot["indicator_analysis"] = analysis
    return analysis


def _iter_snapshot_paths(snapshot: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    ip = snapshot.get("ip_address") or "host"
    shares = snapshot.get("shares") or []
    for share in shares:
        share_name = share.get("share") or "share"
        share_path = f"//{ip}/{share_name}"
        yield ("share", share_path)
        directories = share.get("directories") or []
        for directory in directories:
            dir_name = directory.get("name")
            if not dir_name:
                continue
            dir_path = f"{share_path}/{dir_name}"
            yield ("directory", dir_path)
            files = directory.get("files") or []
            for file_name in files:
                if not file_name:
                    continue
                yield ("file", f"{dir_path}/{file_name}")
