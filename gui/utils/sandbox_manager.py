"""Sandbox helper for running SMB actions inside containers (Linux only)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


DEFAULT_IMAGE = os.environ.get("SMBSEEK_SANDBOX_IMAGE", "docker.io/library/alpine:latest")


@dataclass
class SandboxResult:
    command: List[str]
    stdout: str
    stderr: str
    returncode: int


class SandboxUnavailable(RuntimeError):
    """Raised when no supported sandbox runner is installed."""


class SandboxManager:
    """Manage sandboxed SMB helper invocations for GUI use."""

    def __init__(self, *, runner: Optional[str] = None, image: Optional[str] = None):
        self.runner = runner or self._detect_runner()
        self.image = image or DEFAULT_IMAGE

    @staticmethod
    def _detect_runner() -> Optional[str]:
        if platform.system() != "Linux":
            return None
        for candidate in ("podman", "docker"):
            if shutil.which(candidate):
                return candidate
        return None

    def is_available(self) -> bool:
        return self.runner is not None

    def require_available(self):
        if not self.is_available():
            raise SandboxUnavailable("Podman or Docker is required for sandboxed browsing on Linux.")

    def list_shares(self, ip_address: str, username: str, password: str, *, timeout: int = 60) -> SandboxResult:
        """Run smbclient -L inside the sandbox and return output."""

        self.require_available()
        command = self._build_command(ip_address, username, password)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return SandboxResult(command, result.stdout, result.stderr, result.returncode)

    def _build_command(self, ip_address: str, username: str, password: str) -> List[str]:
        script = self._build_script(ip_address, username)

        base = [self.runner, "run", "--rm", "--network", "host"]
        env_args = [
            "-e", f"SMB_USER={username}",
            "-e", f"SMB_PASS={password}",
            "-e", f"TARGET_IP={ip_address}",
        ]
        base.extend(env_args)
        base.append(self.image)
        base.extend(["sh", "-c", script])
        return base

    @staticmethod
    def _build_script(ip_address: str, username: str) -> str:
        install = "apk add --no-cache samba-client >/dev/null"
        auth_part = "-N" if not username else "-U \"$SMB_USER%$SMB_PASS\""
        smb_cmd = f"smbclient -L //{ip_address} {auth_part}"
        return f"{install} && {smb_cmd}"


_default_manager: Optional[SandboxManager] = None


def get_sandbox_manager() -> SandboxManager:
    global _default_manager
    if _default_manager is None:
        _default_manager = SandboxManager()
    return _default_manager


__all__ = [
    "SandboxManager",
    "SandboxUnavailable",
    "SandboxResult",
    "get_sandbox_manager",
]
