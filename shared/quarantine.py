"""Utility helpers for quarantining untrusted SMB artifacts."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional, Union

_DEFAULT_ROOT = Path.home() / ".smbseek" / "quarantine"


def _sanitize_label(value: str) -> str:
    cleaned = ''.join(c if c.isalnum() or c in {'-', '_', '.'} else '-' for c in value)
    cleaned = cleaned.strip('-_.')
    return cleaned or "host"


def _ensure_root(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    notice = root / "README.txt"
    if not notice.exists():
        notice.write_text(
            "This directory stores quarantined SMBSeek artifacts."
            " Inspect contents in an isolated environment before promoting them.",
            encoding='utf-8'
        )
    return root


def create_quarantine_dir(
    ip_address: Optional[str],
    *,
    purpose: str = "extract",
    base_path: Optional[Union[str, Path]] = None
) -> Path:
    """Create and return a quarantine subdirectory for the given host/purpose."""

    root = Path(base_path).expanduser() if base_path else _DEFAULT_ROOT
    root = _ensure_root(root)

    purpose_root = root / _sanitize_label(purpose or "extract")
    purpose_root.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    safe_ip = _sanitize_label(ip_address or "host")
    session_dir = purpose_root / f"{timestamp}_{safe_ip}"
    session_dir.mkdir(parents=True, exist_ok=True)

    return session_dir


__all__ = ["create_quarantine_dir"]
