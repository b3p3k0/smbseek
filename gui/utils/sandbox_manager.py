"""Sandbox helper for running SMB actions inside containers (Linux only)."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional


DEFAULT_IMAGE = os.environ.get("SMBSEEK_SANDBOX_IMAGE", "docker.io/library/alpine:3.19")
DEFAULT_FILE_BROWSER = os.environ.get("SMBSEEK_SANDBOX_FILE_BROWSER", "pcmanfm")

logger = logging.getLogger(__name__)


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

    def launch_file_browser(
        self,
        ip_address: str,
        username: str,
        password: str,
        *,
        share: Optional[str] = None,
        timeout: int = 120
    ) -> SandboxResult:
        """Launch a sandboxed GUI file browser pointed at the target SMB server."""

        self.require_available()
        display_env = self._detect_display_env()
        if not display_env:
            raise SandboxUnavailable(
                "Sandboxed explorer requires an active X11 or Wayland display session."
            )

        browser_cmd = self._build_file_browser_command(ip_address, share)
        command = self._build_gui_command(username, password, display_env, browser_cmd)

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return SandboxResult(command, result.stdout, result.stderr, result.returncode)

    def launch_investigation_shell(self, host_ctx: Dict[str, Any], rce_score: Optional[int] = None) -> bool:
        """
        Launch an interactive investigation shell in a read-only container.

        Args:
            host_ctx: Host context dictionary with ip_address and other metadata
            rce_score: RCE vulnerability score for logging context

        Returns:
            True if shell was launched successfully, False otherwise
        """
        import json
        import os
        import pty
        import subprocess
        import threading
        import datetime
        from pathlib import Path

        self.require_available()

        ip_address = host_ctx.get('ip_address', 'unknown')

        # Setup logging directory
        log_dir = Path.home() / ".smbseek" / "logs" / "sandbox_sessions"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create session log file
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        session_log = log_dir / f"{ip_address.replace(':', '_')}-{timestamp}.json"

        # Initialize session metadata
        session_metadata = {
            "ip_address": ip_address,
            "rce_score": rce_score,
            "start_time": datetime.datetime.utcnow().isoformat() + "Z",
            "host_context": host_ctx,
            "commands": [],
            "status": "active"
        }

        try:
            # Build investigation container command
            container_cmd = self._build_investigation_command(ip_address)

            print(f"Starting investigation shell for {ip_address}")
            if rce_score is not None:
                print(f"RCE Risk Score: {rce_score}/100")
            print(f"Session log: {session_log}")
            print("Note: Container is read-only for security. Type 'exit' to close.")
            print()

            # Log session start
            self._log_command(session_metadata, "SESSION_START", f"Investigation shell started for {ip_address}")

            # Start container with PTY for interactive session
            master_fd, slave_fd = pty.openpty()

            proc = subprocess.Popen(
                container_cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )

            # Close slave fd in parent process
            os.close(slave_fd)

            # Setup command logging thread
            def log_thread():
                command_buffer = ""
                try:
                    while proc.poll() is None:
                        try:
                            data = os.read(master_fd, 1024).decode('utf-8', errors='ignore')
                            if data:
                                # Log actual commands (basic parsing)
                                for char in data:
                                    if char == '\n' or char == '\r':
                                        if command_buffer.strip():
                                            self._log_command(session_metadata, "COMMAND", command_buffer.strip())
                                            command_buffer = ""
                                    else:
                                        command_buffer += char
                        except OSError:
                            break
                except Exception as e:
                    self._log_command(session_metadata, "ERROR", f"Logging error: {str(e)}")

            # Start logging thread
            log_thread_handle = threading.Thread(target=log_thread)
            log_thread_handle.daemon = True
            log_thread_handle.start()

            # Interactive session - forward stdin/stdout
            try:
                while proc.poll() is None:
                    import select
                    # Check for data from container
                    ready, _, _ = select.select([master_fd, 0], [], [], 0.1)

                    if master_fd in ready:
                        try:
                            data = os.read(master_fd, 1024)
                            if data:
                                os.write(1, data)  # Write to stdout
                        except OSError:
                            break

                    if 0 in ready:  # stdin ready
                        try:
                            data = os.read(0, 1024)
                            if data:
                                os.write(master_fd, data)
                        except OSError:
                            break

            except KeyboardInterrupt:
                print("\nTerminating investigation shell...")

            # Wait for process to finish
            proc.wait()

            # Log session end
            session_metadata["end_time"] = datetime.datetime.utcnow().isoformat() + "Z"
            session_metadata["status"] = "completed"
            self._log_command(session_metadata, "SESSION_END", "Investigation shell completed")

            # Save final session log
            with open(session_log, 'w') as f:
                json.dump(session_metadata, f, indent=2)

            print(f"\nInvestigation session completed. Log saved to: {session_log}")
            return True

        except Exception as e:
            # Log error and save session metadata
            session_metadata["status"] = "failed"
            session_metadata["error"] = str(e)
            session_metadata["end_time"] = datetime.datetime.utcnow().isoformat() + "Z"

            try:
                with open(session_log, 'w') as f:
                    json.dump(session_metadata, f, indent=2)
            except:
                pass

            print(f"Failed to launch investigation shell: {str(e)}")
            return False

        finally:
            try:
                os.close(master_fd)
            except:
                pass

    def _build_investigation_command(self, ip_address: str) -> List[str]:
        """Build container command for investigation shell."""
        base_cmd = [
            self.runner, "run", "-it", "--rm",
            "--network", "host",
            "--read-only",  # Read-only container for security
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=100m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "-e", f"TARGET_IP={ip_address}",
            self.image,
            "sh", "-c",
            "apk add --no-cache samba-client nmap-ncat && exec sh"
        ]
        return base_cmd

    def _detect_display_env(self) -> Optional[Dict[str, str]]:
        """Determine whether X11 or Wayland display is available."""
        display = os.environ.get("DISPLAY")
        wayland = os.environ.get("WAYLAND_DISPLAY")
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR")

        if wayland and runtime_dir:
            wayland_path = os.path.join(runtime_dir, wayland)
            if os.path.exists(wayland_path):
                return {
                    "type": "wayland",
                    "display": wayland,
                    "runtime_dir": runtime_dir,
                    "socket": wayland_path
                }

        if display:
            x11_socket_dir = "/tmp/.X11-unix"
            if os.path.isdir(x11_socket_dir):
                return {
                    "type": "x11",
                    "display": display,
                    "socket": x11_socket_dir
                }

        return None

    def _build_file_browser_command(self, ip_address: str, share: Optional[str]) -> str:
        target = f"smb://{ip_address}/"
        if share:
            target = f"smb://{ip_address}/{share.strip('/')}"

        apk_packages = (
            "apk add --no-cache "
            "pcmanfm gvfs gvfs-smb gvfs-fuse gnome-keyring "
            "samba-client gtk+3.0 adwaita-icon-theme "
            "cairo libgcrypt libgpg-error gcr libfm gst-plugins-bad > /dev/null"
        )
        export_cmd = "export GVFS_DISABLE_FUSE=1"
        browser = DEFAULT_FILE_BROWSER
        return f"{apk_packages} && {export_cmd} && exec {browser} '{target}'"

    def _build_gui_command(
        self,
        username: str,
        password: str,
        display_env: Dict[str, str],
        browser_cmd: str
    ) -> List[str]:
        base = [self.runner, "run", "--rm", "--network", "host"]

        env_args = [
            "-e", f"SMB_USER={username}",
            "-e", f"SMB_PASS={password}",
        ]

        if display_env["type"] == "wayland":
            env_args.extend([
                "-e", f"WAYLAND_DISPLAY={display_env['display']}",
                "-e", f"XDG_RUNTIME_DIR={display_env['runtime_dir']}",
            ])
            base.extend([
                "-v", f"{display_env['runtime_dir']}:{display_env['runtime_dir']}:rw",
            ])
        else:
            env_args.extend(["-e", f"DISPLAY={display_env['display']}"])
            base.extend([
                "-v", "/tmp/.X11-unix:/tmp/.X11-unix:rw"
            ])

        base.extend(env_args)
        base.append(self.image)
        base.extend(["sh", "-c", browser_cmd])
        return base

    def _log_command(self, session_metadata: Dict[str, Any], event_type: str, command: str) -> None:
        """Log a command or event to the session metadata."""
        timestamp = datetime.datetime.utcnow().isoformat() + "Z"
        log_entry = {
            "timestamp": timestamp,
            "type": event_type,
            "command": command
        }
        session_metadata["commands"].append(log_entry)

    def cleanup_old_sessions(self, retention_days: int = 30) -> int:
        """
        Clean up sandbox session logs older than retention_days.

        Args:
            retention_days: Number of days to retain session logs

        Returns:
            Number of log files removed
        """
        import datetime
        from pathlib import Path

        log_dir = Path.home() / ".smbseek" / "logs" / "sandbox_sessions"
        if not log_dir.exists():
            return 0

        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
        removed_count = 0

        try:
            for log_file in log_dir.glob("*.json"):
                if log_file.stat().st_mtime < cutoff_date.timestamp():
                    log_file.unlink()
                    removed_count += 1
        except Exception as e:
            logger.error(f"Failed to cleanup old session logs: {str(e)}")

        return removed_count

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
