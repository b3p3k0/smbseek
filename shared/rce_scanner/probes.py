"""
Safe Probe Runner for RCE Analysis

Implements bounded, safe-active probes for RCE vulnerability assessment.
Enforces budget limits, timeouts, and jitter between probes.

IMPORTANT: Only safe probes are implemented here. Intrusive probes are
blocked by config guard and not implemented.

Budget Policy:
- SafeProbeRunner is created once per scan using the caller's config/database
- Call reset_for_host(ip) before analyzing each host
- Each probe attempt (including retries) counts toward max_requests
- When budget is exhausted, probes return an ERROR verdict and skip remaining work

Example with max_requests=2 and retry_count=1:
- First negotiate attempt times out → budget=1
- Retry succeeds → budget=2 (exhausted)
- Subsequent MS17-010 probe is skipped because budget is exhausted
"""

import logging
import random
import socket
import struct
import time
import re
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from .verdicts import Verdict

if TYPE_CHECKING:
    from shared.config import SMBSeekConfig

logger = logging.getLogger(__name__)

# SMB Status codes for MS17-010 detection
STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INSUFF_SERVER_RESOURCES = 0xC0000205  # Indicates unpatched MS17-010


class SafeProbeRunner:
    """
    Runs safe-active probes for RCE vulnerability assessment.

    Enforces:
    - Budget limits (max requests per host)
    - Timeouts per probe
    - Jitter between probes
    - Legacy mode gating for SMB1 probes
    """

    def __init__(self, config: "SMBSeekConfig", legacy_mode: bool = False):
        """
        Initialize probe runner with config and mode.

        Args:
            config: SMBSeekConfig instance for budget settings
            legacy_mode: If True, SMB1 probes are allowed (--legacy flag)
        """
        self.config = config
        self.legacy_mode = legacy_mode

        # Load budget settings
        budget = config.get_rce_safe_budget()
        self.max_requests = budget.get("max_requests", 2)
        self.timeout = budget.get("per_host_timeout_seconds", 5)
        self.retry_count = budget.get("retry_count", 0)
        self.jitter_ms = budget.get("jitter_ms", 250)

        # Per-host state
        self._request_count = 0
        self._current_ip = None

    def reset_for_host(self, ip: str) -> None:
        """Reset budget counter for a new host."""
        self._request_count = 0
        self._current_ip = ip

    def _budget_check(self) -> bool:
        """Check if budget allows another request."""
        return self._request_count < self.max_requests

    def _apply_jitter(self) -> None:
        """Apply random jitter delay between probes."""
        if self.jitter_ms > 0:
            delay = random.uniform(0, self.jitter_ms / 1000.0)
            time.sleep(delay)

    def _check_intrusive_allowed(self) -> bool:
        """
        Check if intrusive mode is enabled.

        This is a safety guard - always returns False unless
        explicitly enabled in config (which it never should be).
        """
        if not self.config.is_intrusive_mode_enabled():
            logger.warning("Intrusive probe blocked - mode not enabled in config")
            return False
        return True

    def run_negotiate_probe(self, ip: str, port: int = 445) -> Dict[str, Any]:
        """
        Run SMB2/3 negotiate probe to gather protocol information.

        Always runs SMB2/3 negotiate. SMB1 negotiate only if legacy_mode=True.

        Retries count toward budget. If budget is exhausted, the probe returns
        an ERROR verdict without attempting network activity.
        """
        last_result: Optional[Dict[str, Any]] = None

        for attempt in range(1 + self.retry_count):
            if not self._budget_check():
                logger.warning(f"Budget exceeded for {ip}, skipping negotiate probe")
                return {"error": "budget_exceeded", "verdict": Verdict.ERROR}

            self._request_count += 1
            self._apply_jitter()

            result = self._negotiate_smb2_once(ip, port)

            # Successful or non-transient outcome
            error = result.get("error")
            if error is None or (error not in ("timeout", "socket_error") and not str(error).startswith("socket_error")):
                return result

            last_result = result
            if attempt < self.retry_count:
                time.sleep(0.5 * (attempt + 1))  # simple backoff

        return last_result or {"error": "all_retries_failed", "verdict": Verdict.ERROR}

    def _negotiate_smb2_once(self, ip: str, port: int) -> Dict[str, Any]:
        """Single SMB2 negotiate attempt factored for retry handling."""
        result = {
            "smb_dialect": None,
            "signing_required": False,
            "compression_algos": [],
            "smb1_possible": self.legacy_mode,
            "error": None,
        }

        try:
            smb2_result = self._negotiate_smb2(ip, port)
            if smb2_result:
                result.update(smb2_result)

            # If legacy mode, also probe SMB1
            if self.legacy_mode:
                smb1_result = self._probe_smb1_support(ip, port)
                if smb1_result.get("smb1_supported"):
                    result["smb1_possible"] = True

        except socket.timeout:
            result["error"] = "timeout"
            logger.debug(f"Negotiate probe timeout for {ip}")
        except socket.error as e:
            result["error"] = f"socket_error: {e}"
            logger.debug(f"Negotiate probe socket error for {ip}: {e}")
        except Exception as e:
            result["error"] = f"exception: {e}"
            logger.warning(f"Negotiate probe failed for {ip}: {e}")

        return result

    def _negotiate_smb2(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """
        Send SMB2 NEGOTIATE request and parse response.

        Returns dialect, signing requirements, and compression capabilities.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Build SMB2 NEGOTIATE request
            negotiate_req = self._build_smb2_negotiate_request()
            sock.sendall(negotiate_req)

            # Receive response
            response = self._recv_smb_response(sock)
            if not response:
                return None

            # Parse response
            return self._parse_smb2_negotiate_response(response)

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _build_smb2_negotiate_request(self) -> bytes:
        """Build SMB2 NEGOTIATE request packet."""
        # NetBIOS header placeholder (will be filled later)
        # SMB2 Header
        smb2_header = b"\xfeSMB"  # Protocol ID
        smb2_header += struct.pack("<H", 64)  # Header length
        smb2_header += struct.pack("<H", 0)  # Credit charge
        smb2_header += struct.pack("<I", 0)  # Status
        smb2_header += struct.pack("<H", 0)  # Command (NEGOTIATE = 0)
        smb2_header += struct.pack("<H", 31)  # Credits requested
        smb2_header += struct.pack("<I", 0)  # Flags
        smb2_header += struct.pack("<I", 0)  # Next command
        smb2_header += struct.pack("<Q", 1)  # Message ID
        smb2_header += struct.pack("<I", 0)  # Reserved
        smb2_header += struct.pack("<I", 0)  # Tree ID
        smb2_header += struct.pack("<Q", 0)  # Session ID
        smb2_header += b"\x00" * 16  # Signature

        # SMB2 NEGOTIATE request body
        # Dialects: 0x0202, 0x0210, 0x0300, 0x0302, 0x0311
        dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
        negotiate_body = struct.pack("<H", 36)  # Structure size
        negotiate_body += struct.pack("<H", len(dialects))  # Dialect count
        negotiate_body += struct.pack("<H", 1)  # Security mode (signing enabled)
        negotiate_body += struct.pack("<H", 0)  # Reserved
        negotiate_body += struct.pack("<I", 0x7F)  # Capabilities
        negotiate_body += b"\x00" * 16  # Client GUID
        negotiate_body += struct.pack("<I", 0)  # Negotiate context offset
        negotiate_body += struct.pack("<H", 0)  # Negotiate context count
        negotiate_body += struct.pack("<H", 0)  # Reserved

        # Add dialects
        for dialect in dialects:
            negotiate_body += struct.pack("<H", dialect)

        # Combine and add NetBIOS header
        smb_packet = smb2_header + negotiate_body
        netbios_header = struct.pack(">I", len(smb_packet))

        return netbios_header + smb_packet

    def _recv_smb_response(self, sock: socket.socket, max_size: int = 4096) -> Optional[bytes]:
        """Receive SMB response from socket."""
        try:
            # Read NetBIOS header (4 bytes)
            nb_header = sock.recv(4)
            if len(nb_header) < 4:
                return None

            # Parse length (big-endian 4 bytes, high bit is type)
            length = struct.unpack(">I", nb_header)[0] & 0x00FFFFFF

            # Read SMB packet
            if length > max_size:
                length = max_size

            data = b""
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 4096))
                if not chunk:
                    break
                data += chunk

            return data

        except Exception as e:
            logger.debug(f"Error receiving SMB response: {e}")
            return None

    def _parse_smb2_negotiate_response(self, data: bytes) -> Dict[str, Any]:
        """Parse SMB2 NEGOTIATE response."""
        result = {
            "smb_dialect": None,
            "signing_required": False,
            "compression_algos": [],
        }

        if len(data) < 65:  # Minimum SMB2 header + negotiate response
            return result

        # Check SMB2 signature
        if data[0:4] != b"\xfeSMB":
            return result

        # Parse header
        header_length = struct.unpack("<H", data[4:6])[0]
        status = struct.unpack("<I", data[8:12])[0]

        if status != STATUS_SUCCESS:
            return result

        # Parse negotiate response (starts at offset 64)
        if len(data) < 64 + 65:  # Header + minimum response
            return result

        offset = 64
        # Structure size at offset
        struct_size = struct.unpack("<H", data[offset:offset + 2])[0]

        # Security mode at offset + 2
        security_mode = struct.unpack("<H", data[offset + 2:offset + 4])[0]
        result["signing_required"] = bool(security_mode & 0x02)  # SIGNING_REQUIRED

        # Dialect revision at offset + 4
        dialect = struct.unpack("<H", data[offset + 4:offset + 6])[0]
        result["smb_dialect"] = dialect

        # For SMB 3.1.1, parse negotiate contexts for compression
        if dialect == 0x0311 and len(data) > offset + 68:
            try:
                context_offset = struct.unpack("<I", data[offset + 60:offset + 64])[0]
                context_count = struct.unpack("<H", data[offset + 64:offset + 66])[0]

                if context_offset > 0 and context_count > 0:
                    result["compression_algos"] = self._parse_compression_context(
                        data, context_offset, context_count
                    )
            except Exception as e:
                logger.debug(f"Error parsing negotiate contexts: {e}")

        return result

    def _parse_compression_context(
        self, data: bytes, offset: int, count: int
    ) -> List[int]:
        """
        Parse SMB2_COMPRESSION_CAPABILITIES context for algorithm IDs.

        Args:
            data: Full response data
            offset: Offset to negotiate contexts
            count: Number of contexts

        Returns:
            List of compression algorithm IDs
        """
        compression_algos = []

        try:
            pos = offset
            for _ in range(count):
                if pos + 8 > len(data):
                    break

                context_type = struct.unpack("<H", data[pos:pos + 2])[0]
                context_length = struct.unpack("<H", data[pos + 2:pos + 4])[0]

                # SMB2_COMPRESSION_CAPABILITIES = 0x0003
                if context_type == 0x0003 and context_length >= 4:
                    algo_count = struct.unpack("<H", data[pos + 8:pos + 10])[0]
                    for i in range(algo_count):
                        algo_offset = pos + 12 + (i * 2)
                        if algo_offset + 2 <= len(data):
                            algo = struct.unpack("<H", data[algo_offset:algo_offset + 2])[0]
                            compression_algos.append(algo)

                # Move to next context (8-byte aligned)
                pos += 8 + context_length
                pos = (pos + 7) & ~7  # Align to 8 bytes

        except Exception as e:
            logger.debug(f"Error parsing compression context: {e}")

        return compression_algos

    def _probe_smb1_support(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Probe for SMB1 support (only if legacy_mode is True).

        This is a minimal check to see if the server accepts SMB1.
        """
        result = {"smb1_supported": False}

        if not self.legacy_mode:
            return result

        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send minimal SMB1 negotiate request
            smb1_negotiate = self._build_smb1_negotiate_request()
            sock.sendall(smb1_negotiate)

            # Receive response
            response = self._recv_smb_response(sock)
            if response and len(response) >= 4:
                # Check for SMB1 signature
                if response[0:4] == b"\xffSMB":
                    result["smb1_supported"] = True

        except Exception as e:
            logger.debug(f"SMB1 probe failed for {ip}: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

        return result

    def _build_smb1_negotiate_request(self) -> bytes:
        """Build minimal SMB1 NEGOTIATE request."""
        # SMB1 Header
        smb1_header = b"\xffSMB"  # Protocol ID
        smb1_header += b"\x72"  # Command (NEGOTIATE)
        smb1_header += b"\x00\x00\x00\x00"  # Status
        smb1_header += b"\x18"  # Flags
        smb1_header += b"\x53\xc0"  # Flags2
        smb1_header += b"\x00" * 12  # Extra
        smb1_header += b"\x00" * 2  # TID
        smb1_header += b"\x00" * 2  # PID
        smb1_header += b"\x00" * 2  # UID
        smb1_header += b"\x00" * 2  # MID

        # NEGOTIATE request body
        dialects = b"\x02NT LM 0.12\x00"  # NT LAN Manager dialect
        word_count = struct.pack("B", 0)  # Word count
        byte_count = struct.pack("<H", len(dialects))  # Byte count

        body = word_count + byte_count + dialects

        # Combine and add NetBIOS header
        smb_packet = smb1_header + body
        netbios_header = struct.pack(">I", len(smb_packet))

        return netbios_header + smb_packet

    def run_ms17_010_probe(self, ip: str, port: int = 445) -> Dict[str, Any]:
        """
        Run safe MS17-010 (EternalBlue) vulnerability check.

        This is the safe FID0 status check that detects unpatched systems
        by examining the SMB response to a specific transaction.

        ONLY runs if legacy_mode=True (--legacy flag).

        Args:
            ip: Target IP address
            port: SMB port (default 445)

        Returns:
            Dict with status code, verdict, and reason
        """
        if not self.legacy_mode:
            return {
                "verdict": Verdict.NOT_ASSESSABLE,
                "reason": "SMB1 not enabled/allowed (requires --legacy)",
                "status": None,
            }

        if not self._budget_check():
            return {
                "verdict": Verdict.ERROR,
                "reason": "budget_exceeded",
                "status": None,
            }

        # Check if MS17-010 probe is enabled
        if not self.config.is_ms17_010_enabled():
            return {
                "verdict": Verdict.NOT_ASSESSABLE,
                "reason": "MS17-010 probe disabled in config",
                "status": None,
            }

        self._request_count += 1
        self._apply_jitter()

        try:
            status_code = self._perform_ms17_010_check(ip, port)
            return self._classify_ms17_010_status(status_code)

        except socket.timeout:
            return {
                "verdict": Verdict.ERROR,
                "reason": "probe_timeout",
                "status": None,
            }
        except socket.error as e:
            return {
                "verdict": Verdict.ERROR,
                "reason": f"socket_error: {e}",
                "status": None,
            }
        except Exception as e:
            logger.warning(f"MS17-010 probe failed for {ip}: {e}")
            return {
                "verdict": Verdict.ERROR,
                "reason": f"exception: {e}",
                "status": None,
            }

    def _perform_ms17_010_check(self, ip: str, port: int) -> Optional[int]:
        """
        Perform the safe FID0 MS17-010 check.

        Protocol:
        1) SMB1 negotiate (NT LM 0.12)
        2) Anonymous session setup
        3) Tree connect to IPC$
        4) Send FID0 transaction against \\PIPE\\BROWSER

        Returns NT status code or None if unavailable (treated as INSUFFICIENT_DATA).
        """
        try:
            from impacket.smbconnection import SMBConnection
            from impacket import smb
        except ImportError:
            logger.debug("impacket not available for MS17-010 check")
            return None

        conn = None
        try:
            conn = SMBConnection(ip, ip, sess_port=port, timeout=self.timeout)

            # Force SMB1 negotiation
            conn.negotiateSession(preferredDialect=smb.SMB_DIALECT)

            # Anonymous login
            conn.login('', '')

            tree_id = conn.connectTree('IPC$')

            # Use low-level server to send FID0 transaction
            smb_server = conn.getSMBServer()
            status = self._send_fid0_trans(smb_server, tree_id)

            try:
                conn.disconnectTree(tree_id)
            except Exception:
                pass
            try:
                conn.logoff()
            except Exception:
                pass
            return status

        except socket.timeout:
            logger.debug(f"MS17-010 check timeout for {ip}")
            return None
        except socket.error as e:
            logger.debug(f"MS17-010 check socket error for {ip}: {e}")
            return None
        except Exception as e:
            status = self._extract_status_from_exception(e)
            if status is not None:
                return status
            logger.debug(f"MS17-010 check failed for {ip}: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _send_fid0_trans(self, smb_server, tree_id: int) -> Optional[int]:
        """
        Send a safe SMB1 TRANS request with FID=0 to trigger MS17-010 status.

        Returns NT status code from response, or None on failure.
        """
        try:
            # Attempt to open \BROWSER using FID 0 semantics. If the server
            # is unpatched, this path yields STATUS_INSUFF_SERVER_RESOURCES.
            fid = smb_server.open_file(
                tree_id,
                '\\BROWSER',
                desiredAccess=0x0012019F,  # FILE_READ_DATA | READ_ATTRIBUTES | READ_EA
                creationOption=0x00000040,  # FILE_NON_DIRECTORY_FILE
                fileAttributes=0,
                shareMode=0x00000001  # FILE_SHARE_READ
            )
            smb_server.close_file(tree_id, fid)
            return STATUS_ACCESS_DENIED
        except Exception as e:
            status = self._extract_status_from_exception(e)
            if status is not None:
                return status
            return None

    def _extract_status_from_exception(self, e: Exception) -> Optional[int]:
        """Extract NT status code from impacket SMB exception."""
        error_str = str(e)
        match = re.search(r"STATUS_[A-Z_]+|0x[0-9a-fA-F]{8}", error_str)
        if not match:
            return None

        status_str = match.group()
        if status_str.startswith('0x'):
            try:
                return int(status_str, 16)
            except ValueError:
                return None

        status_map = {
            'STATUS_INSUFF_SERVER_RESOURCES': STATUS_INSUFF_SERVER_RESOURCES,
            'STATUS_ACCESS_DENIED': STATUS_ACCESS_DENIED,
            'STATUS_INVALID_HANDLE': STATUS_INVALID_HANDLE,
        }
        return status_map.get(status_str)

    def _classify_ms17_010_status(self, status_code: Optional[int]) -> Dict[str, Any]:
        """
        Classify MS17-010 probe result based on status code.

        Args:
            status_code: NT status code from probe, or None if failed

        Returns:
            Dict with verdict and reason
        """
        if status_code is None:
            return {
                "verdict": Verdict.INSUFFICIENT_DATA,
                "reason": "Could not determine patch status",
                "status": None,
            }

        if status_code == STATUS_INSUFF_SERVER_RESOURCES:
            # This status indicates the system is UNPATCHED
            return {
                "verdict": Verdict.CONFIRMED,
                "reason": "STATUS_INSUFF_SERVER_RESOURCES indicates unpatched MS17-010",
                "status": hex(status_code),
            }
        elif status_code in (STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE):
            # These statuses indicate the system is PATCHED or protected
            return {
                "verdict": Verdict.NOT_VULNERABLE,
                "reason": f"Status {hex(status_code)} indicates patched/protected",
                "status": hex(status_code),
            }
        else:
            # Unexpected status code
            return {
                "verdict": Verdict.INSUFFICIENT_DATA,
                "reason": f"Unexpected status code: {hex(status_code)}",
                "status": hex(status_code),
            }

    def get_probe_stats(self) -> Dict[str, Any]:
        """Get statistics about probes run."""
        return {
            "current_ip": self._current_ip,
            "request_count": self._request_count,
            "max_requests": self.max_requests,
            "budget_remaining": self.max_requests - self._request_count,
        }


__all__ = ["SafeProbeRunner"]
