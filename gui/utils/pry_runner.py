"""
Pry password audit runner built on impacket.smbconnection.

Inspired by mmcbrute (BSD-3-Clause) as reference for SMB auth brute logic.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from threading import Event
from typing import Callable, Optional

try:  # pragma: no cover - runtime dependency
    from impacket.smbconnection import SMBConnection, SessionError  # type: ignore
except ImportError:  # pragma: no cover
    SMBConnection = None
    SessionError = None


class PryError(RuntimeError):
    """Raised when Pry cannot proceed."""


@dataclass
class PryResult:
    ip_address: str
    action: str
    status: str
    notes: str
    attempts: int
    found_password: Optional[str] = None


def run_pry(
    ip_address: str,
    username: str,
    wordlist_path: str,
    *,
    domain: str = "",
    user_as_pass: bool = True,
    stop_on_lockout: bool = True,
    verbose: bool = False,
    attempt_delay: float = 1.0,
    max_attempts: int = 0,
    cancel_event: Optional[Event] = None,
    progress_callback: Optional[Callable[[int, Optional[int]], None]] = None,
    socket_timeout: float = 6.0,
) -> PryResult:
    """
    Attempt SMB authentication against a single host with a single username.

    Args:
        ip_address: Target host/IP.
        username: Username (optionally DOMAIN\\user).
        wordlist_path: Plaintext password list (one per line).
        domain: Optional domain override (DOMAIN\\user is parsed automatically).
        user_as_pass: Try username as password first if True.
        stop_on_lockout: Halt on STATUS_ACCOUNT_LOCKED_OUT if True.
        verbose: Currently unused hook for future per-attempt logging.
        attempt_delay: Seconds to sleep between attempts (throttling).
        max_attempts: Maximum attempts (0 = unlimited).
        cancel_event: Threading Event to support cancellation.
        progress_callback: Callable receiving (attempts_done, total_attempts or None).
        socket_timeout: SMB socket timeout in seconds.
    """
    if SMBConnection is None:
        raise PryError(
            "impacket is not available. Install it in the GUI environment "
            "(e.g., pip install impacket) to enable Pry."
        )

    clean_username = (username or "").strip()
    if not clean_username:
        raise PryError("Username is required.")

    wl_path = wordlist_path.strip()
    if not wl_path:
        raise PryError("Password wordlist is required.")
    if wl_path.lower().endswith(".gz"):
        raise PryError("gzip wordlists are not supported yet—please decompress first.")
    if not os.path.isfile(wl_path):
        raise PryError("Password wordlist file not found.")
    if not os.access(wl_path, os.R_OK):
        raise PryError("Password wordlist is not readable.")

    parsed_domain, parsed_user = _split_domain(clean_username, domain)
    domain = parsed_domain
    username_only = parsed_user

    total_candidates = _count_candidates(wl_path, include_user_as_pass=user_as_pass)

    attempts_made = 0
    found_password: Optional[str] = None
    lockout_detected = False
    connection_error: Optional[str] = None

    last_progress = 0.0

    def _maybe_progress(force: bool = False) -> None:
        nonlocal last_progress
        if not progress_callback:
            return
        now = time.time()
        if force or attempts_made == 0 or attempts_made % 25 == 0 or (now - last_progress) >= 1.0:
            progress_callback(attempts_made, total_candidates if total_candidates > 0 else None)
            last_progress = now

    try:
        # Username-as-password attempt
        if user_as_pass and (max_attempts == 0 or attempts_made < max_attempts):
            _check_cancel(cancel_event)
            attempts_made += 1
            _maybe_progress()
            outcome = _attempt_login(
                ip_address,
                username_only,
                username_only,
                domain,
                socket_timeout,
            )
            if outcome == "lockout":
                lockout_detected = True
                if stop_on_lockout:
                    return PryResult(
                        ip_address=ip_address,
                        action="pry",
                        status="failed",
                        notes=f"Stopped due to account lockout after {attempts_made} attempts",
                        attempts=attempts_made,
                    )
            elif outcome == "success":
                found_password = username_only
                return PryResult(
                    ip_address=ip_address,
                    action="pry",
                    status="success",
                    notes=f"user {clean_username} authenticated with '{found_password}'",
                    attempts=attempts_made,
                    found_password=found_password,
                )
            # otherwise continue on failure
            if attempt_delay > 0:
                _sleep_with_cancel(attempt_delay, cancel_event)

        with open(wl_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if max_attempts and attempts_made >= max_attempts:
                    break
                password = line.rstrip("\r\n")
                if not password or len(password) > 256:
                    continue

                _check_cancel(cancel_event)
                attempts_made += 1
                _maybe_progress()

                outcome = _attempt_login(
                    ip_address,
                    username_only,
                    password,
                    domain,
                    socket_timeout,
                )

                if outcome == "success":
                    found_password = password
                    return PryResult(
                        ip_address=ip_address,
                        action="pry",
                        status="success",
                        notes=f"user {clean_username} authenticated with '{found_password}'",
                        attempts=attempts_made,
                        found_password=found_password,
                    )

                if outcome == "lockout":
                    lockout_detected = True
                    if stop_on_lockout:
                        return PryResult(
                            ip_address=ip_address,
                            action="pry",
                            status="failed",
                            notes=f"Stopped due to account lockout after {attempts_made} attempts",
                            attempts=attempts_made,
                        )

                if attempt_delay > 0:
                    _sleep_with_cancel(attempt_delay, cancel_event)

    except PryError:
        raise
    except Exception as exc:  # pragma: no cover - network/runtime errors
        connection_error = str(exc)

    _maybe_progress(force=True)

    if cancel_event and cancel_event.is_set():
        return PryResult(
            ip_address=ip_address,
            action="pry",
            status="cancelled",
            notes=f"Cancelled after {attempts_made} attempts",
            attempts=attempts_made,
        )

    if connection_error:
        return PryResult(
            ip_address=ip_address,
            action="pry",
            status="failed",
            notes=f"Connection failed: {connection_error}",
            attempts=attempts_made,
        )

    if lockout_detected and stop_on_lockout:
        return PryResult(
            ip_address=ip_address,
            action="pry",
            status="failed",
            notes=f"Stopped due to account lockout after {attempts_made} attempts",
            attempts=attempts_made,
        )

    if lockout_detected and not stop_on_lockout:
        return PryResult(
            ip_address=ip_address,
            action="pry",
            status="success",
            notes=f"user {clean_username} not authenticated; lockout observed but continued (honey badger mode)",
            attempts=attempts_made,
        )

    return PryResult(
        ip_address=ip_address,
        action="pry",
        status="success",
        notes=f"user {clean_username} not authenticated with provided wordlist",
        attempts=attempts_made,
    )


def _attempt_login(
    ip_address: str,
    username: str,
    password: str,
    domain: str,
    timeout: float,
) -> str:
    """
    Attempt a single SMB login. Returns: "success", "failure", "lockout".
    Raises PryError for connection-level failures.
    """
    conn = None
    try:
        conn = SMBConnection(
            remoteName=ip_address,
            remoteHost=ip_address,
            sess_port=445,
            timeout=timeout,
        )
        conn.login(username, password, domain)
        return "success"
    except SessionError as exc:  # pragma: no cover - status parsing
        message = str(exc).upper()
        if "STATUS_ACCOUNT_LOCKED_OUT" in message or "ACCOUNT_LOCKED_OUT" in message or "ACCOUNT_RESTRICTION" in message:
            return "lockout"
        if "STATUS_PASSWORD_EXPIRED" in message:
            return "failure"
        return "failure"
    except Exception as exc:  # pragma: no cover
        raise PryError(str(exc))
    finally:
        try:
            if conn:
                conn.logoff()
                conn.close()
        except Exception:
            pass


def _count_candidates(path: str, include_user_as_pass: bool) -> int:
    """Return total candidate count without loading into memory."""
    total = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            candidate = line.rstrip("\r\n")
            if not candidate or len(candidate) > 256:
                continue
            total += 1
    if include_user_as_pass:
        total += 1
    return total


def _split_domain(username: str, domain: str) -> tuple[str, str]:
    """Split DOMAIN\\user if present; fall back to provided domain arg."""
    if "\\" in username:
        dom, user = username.split("\\", 1)
        return dom, user
    return domain, username


def _check_cancel(cancel_event: Optional[Event]) -> None:
    if cancel_event and cancel_event.is_set():
        raise PryError("Cancelled")


def _sleep_with_cancel(delay: float, cancel_event: Optional[Event]) -> None:
    """Sleep in small slices so cancellation can abort promptly."""
    end_time = time.time() + delay
    while time.time() < end_time:
        if cancel_event and cancel_event.is_set():
            raise PryError("Cancelled")
        time.sleep(0.05)


__all__ = ["run_pry", "PryError", "PryResult"]
