import re
import subprocess
from typing import Optional

from .share_enumerator import build_smbclient_cmd, execute_with_fallback

# Map common NT_STATUS codes to user-friendly descriptions
SMB_STATUS_HINTS = {
    'NT_STATUS_ACCESS_DENIED': 'Access denied - insufficient permissions',
    'NT_STATUS_BAD_NETWORK_NAME': 'Share not found or unavailable',
    'NT_STATUS_LOGON_FAILURE': 'Authentication failed',
    'NT_STATUS_ACCOUNT_DISABLED': 'User account is disabled',
    'NT_STATUS_ACCOUNT_LOCKED_OUT': 'User account is locked out',
    'NT_STATUS_PASSWORD_EXPIRED': 'Password has expired',
    'NT_STATUS_CONNECTION_REFUSED': 'Connection refused by server',
    'NT_STATUS_HOST_UNREACHABLE': 'Host is unreachable',
    'NT_STATUS_NETWORK_UNREACHABLE': 'Network is unreachable',
    'NT_STATUS_IO_TIMEOUT': 'Connection timed out',
    'NT_STATUS_PIPE_NOT_AVAILABLE': 'Named pipe not available',
    'NT_STATUS_PIPE_BROKEN': 'Named pipe broken',
    'NT_STATUS_OBJECT_NAME_NOT_FOUND': 'Object or path not found',
    'NT_STATUS_SHARING_VIOLATION': 'File is in use by another process',
    'NT_STATUS_INSUFFICIENT_RESOURCES': 'Insufficient server resources'
}


def test_share_access(op, ip, share_name, username, password):
    """Test read access to a specific SMB share using smbclient."""
    access_result = {
        'share_name': share_name,
        'accessible': False,
        'error': None,
        'auth_status': None
    }

    try:
        cmd = build_smbclient_cmd(op, "access", ip, username, password, share=share_name)
        cmd.extend(["-c", "ls"])

        op.output.print_if_verbose(f"Testing access: {' '.join(cmd)}")

        result = execute_with_fallback(
            op,
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            stdin=subprocess.DEVNULL
        )

        if result.returncode == 0:
            if "NT_STATUS" not in result.stderr and len(result.stdout.strip()) > 0:
                access_result['accessible'] = True
                access_result['auth_status'] = "OK"
                op.output.print_if_verbose(f"Share '{share_name}' is accessible")
            else:
                access_result['error'] = "Access denied or empty share"
                access_result['auth_status'] = _extract_nt_status(result.stderr) or "ACCESS_DENIED"
                op.output.print_if_verbose(f"Share '{share_name}' - no readable content")
        else:
            friendly_msg, raw_context = _format_smbclient_error(result)
            share_missing = 'NT_STATUS_BAD_NETWORK_NAME' in friendly_msg

            if share_missing:
                access_result['error'] = "Share not found on server (server reported NT_STATUS_BAD_NETWORK_NAME)"
                access_result['auth_status'] = "NT_STATUS_BAD_NETWORK_NAME"
            else:
                access_result['error'] = friendly_msg
                access_result['auth_status'] = _extract_nt_status(friendly_msg) or "ERROR"

            if op.cautious_mode and "NT_STATUS" in friendly_msg:
                if "ACCESS_DENIED" in friendly_msg or "LOGON_FAILURE" in friendly_msg:
                    op.output.print_if_verbose(f"Share '{share_name}' access denied - security restrictions in cautious mode")

            is_expected_denial = 'NT_STATUS_ACCESS_DENIED' in friendly_msg
            if is_expected_denial or share_missing:
                pass
            else:
                if raw_context and raw_context != friendly_msg:
                    op.output.error(f"Share '{share_name}' - {friendly_msg} [{raw_context}]")
                else:
                    op.output.error(f"Share '{share_name}' - {friendly_msg}")

    except subprocess.TimeoutExpired:
        access_result['error'] = "Connection timeout (smbclient)"
        access_result['auth_status'] = "TIMEOUT"
        op.output.warning(
            f"Share '{share_name}' - timeout (consider increasing share access timeout if this is frequent)"
        )
    except Exception as e:
        access_result['error'] = f"Test error: {str(e)}"
        access_result['auth_status'] = "ERROR"
        op.output.warning(f"Share '{share_name}' - test error: {str(e)}")

    return access_result


def _format_smbclient_error(result):
    """
    Format smbclient error messages with NT_STATUS codes and context.
    """
    def _clean(stream: Optional[str]) -> str:
        if not stream:
            return ""
        return stream.strip().rstrip("~").strip()

    stderr_trimmed = _clean(result.stderr)
    stdout_trimmed = _clean(result.stdout)

    if stderr_trimmed and stdout_trimmed:
        combined_output = f"{stderr_trimmed} | {stdout_trimmed}"
    elif stderr_trimmed:
        combined_output = stderr_trimmed
    elif stdout_trimmed:
        combined_output = stdout_trimmed
    else:
        combined_output = ""

    if not combined_output:
        return (f"smbclient exited with code {result.returncode} and produced no output", "")

    nt_status_match = re.search(r'(NT_STATUS_[A-Z_]+)', combined_output)

    if nt_status_match and nt_status_match.group(1) == 'NT_STATUS_ACCESS_DENIED':
        combined_lower = combined_output.lower()
        if 'tree connect failed' in combined_lower and 'anonymous login successful' in combined_lower:
            friendly_msg = 'Access denied - share does not allow anonymous/guest browsing (NT_STATUS_ACCESS_DENIED)'
            return (friendly_msg, None)

    if nt_status_match and nt_status_match.group(1) == 'NT_STATUS_LOGON_FAILURE':
        combined_lower = combined_output.lower()
        if 'tree connect failed' in combined_lower:
            friendly_msg = 'Authentication failed for this share'
            return (friendly_msg, None)

    if nt_status_match:
        status_code = nt_status_match.group(1)
        hint = SMB_STATUS_HINTS.get(status_code, "SMB protocol error")

        if status_code in ('NT_STATUS_IO_TIMEOUT', 'NT_STATUS_CONNECTION_REFUSED',
                           'NT_STATUS_HOST_UNREACHABLE', 'NT_STATUS_NETWORK_UNREACHABLE'):
            ip_match = re.search(r"Connection to\s+([^\s)]+)", combined_output)
            target = ip_match.group(1) if ip_match else "target host"
            friendly_msg = f"{hint} while reaching {target}"
            return (friendly_msg, None)

        if status_code == 'NT_STATUS_BAD_NETWORK_NAME':
            friendly_msg = "Share not found on server"
            return (friendly_msg, None)

        start_pos = max(0, nt_status_match.start() - 80)
        end_pos = min(len(combined_output), nt_status_match.end() + 80)
        context = combined_output[start_pos:end_pos]

        if len(context) > 160:
            context = context[:157] + "..."

        friendly_msg = f"{hint} ({status_code}) - {context}"
        raw_ctx = combined_output if combined_output != friendly_msg else None
        return (friendly_msg, raw_ctx)
    else:
        trimmed_output = combined_output[:160] + "..." if len(combined_output) > 160 else combined_output
        return (f"smbclient error: {trimmed_output}", combined_output)


def _extract_nt_status(message: str) -> Optional[str]:
    """Return first NT_STATUS_* token in the provided message, if present."""
    if not message:
        return None
    marker = "NT_STATUS_"
    upper = message.upper()
    if marker not in upper:
        return None
    match = re.search(r"(NT_STATUS_[A-Z0-9_]+)", upper)
    if match:
        return match.group(1)
    return None
