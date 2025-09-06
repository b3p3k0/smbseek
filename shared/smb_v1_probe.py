"""
SMBSeek SMB1 Discovery Mode

Secure SMB1 discovery functionality implementing the audit requirements.
Provides anonymous-only, discovery-only SMB1 enumeration with strict security controls.

IMPORTANT: This module implements SMB1 discovery with the following constraints:
- Anonymous authentication only (no credentials accepted)
- Share discovery only (no file operations)
- Strict timeouts and output limits
- Impacket preferred, smbclient fallback
- One-run mode only (no persistent enablement)
"""

import re
import socket
import struct
from typing import List, Dict, Optional, Any, Tuple
from contextlib import closing

from .proc import run_smbclient_safe, ProcessExecutionError, ProcessTimeoutError
from .safety import (
    strip_control, validate_share_name, sanitize_hostname, 
    SecurityLimits, enforce_string_limits
)

# Try to import Impacket for preferred SMB1 implementation
IMPACKET_AVAILABLE = False
try:
    from impacket.smb import SMB, SMBError
    from impacket.smbconnection import SMBConnection
    from impacket import smb
    import impacket.dcerpc.v5.transport as transport
    from impacket.dcerpc.v5 import srvsvc
    from impacket.dcerpc.v5.dtypes import NULL
    IMPACKET_AVAILABLE = True
except ImportError:
    pass


class SMB1ProbeError(Exception):
    """Base exception for SMB1 probing errors."""
    pass


class SMB1SecurityError(SMB1ProbeError):
    """Raised when SMB1 probe violates security constraints."""
    pass


class SMB1TimeoutError(SMB1ProbeError):
    """Raised when SMB1 probe exceeds timeout limits."""
    pass


def scan_host_smb1(host: str, limits: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Perform SMB1 discovery scan on a host with strict security controls.
    
    This function implements the audit-required SMB1 Discovery Mode:
    - Anonymous authentication only
    - Share enumeration only (no file operations)
    - Strict caps and timeouts
    - Impacket preferred, smbclient fallback
    - No DFS referrals or redirections
    
    Args:
        host: Target hostname or IP address
        limits: Dictionary with security limits from config
        
    Returns:
        List of dictionaries with share information:
        [{"name": str, "type": str, "protocol": "SMB1"}, ...]
        
    Raises:
        SMB1ProbeError: General probe failure
        SMB1SecurityError: Security constraint violation
        SMB1TimeoutError: Operation timeout
    """
    # Validate and sanitize input
    clean_host = sanitize_hostname(host)
    if not clean_host:
        raise SMB1SecurityError(f"Invalid hostname: {host}")
    
    # Extract security limits with safe defaults
    timeout_per_host = limits.get('timeout_per_host_seconds', 30)
    max_pdu_bytes = limits.get('max_pdu_bytes', SecurityLimits.MAX_PDU_SIZE)
    max_stdout_bytes = limits.get('max_stdout_bytes', 10000)
    max_shares = limits.get('max_shares', SecurityLimits.MAX_SHARES_PER_HOST)
    max_share_name_len = limits.get('max_share_name_len', SecurityLimits.MAX_SHARE_NAME_LENGTH)
    
    # Validate limits
    if timeout_per_host <= 0 or timeout_per_host > 300:  # Max 5 minutes for SMB1
        raise SMB1SecurityError("Invalid timeout_per_host_seconds")
    
    if max_shares <= 0 or max_shares > SecurityLimits.MAX_SHARES_PER_HOST:
        raise SMB1SecurityError("Invalid max_shares limit")
    
    # Try Impacket path first (preferred)
    if IMPACKET_AVAILABLE:
        try:
            return _scan_with_impacket(
                clean_host, timeout_per_host, max_pdu_bytes, 
                max_shares, max_share_name_len
            )
        except Exception as e:
            # Log the Impacket failure but continue to fallback
            print(f"Impacket SMB1 probe failed for {clean_host}: {e}")
    
    # Fallback to hardened smbclient
    return _scan_with_smbclient_fallback(
        clean_host, timeout_per_host, max_stdout_bytes,
        max_shares, max_share_name_len
    )


def _scan_with_impacket(
    host: str,
    timeout: int,
    max_pdu_bytes: int,
    max_shares: int,
    max_share_name_len: int
) -> List[Dict[str, str]]:
    """
    Scan SMB1 shares using Impacket with security controls.
    
    Implements the audit-required Impacket SMB1 flow:
    1. Negotiate SMB1 (NT1)
    2. Anonymous SessionSetup
    3. TreeConnect to IPC$
    4. Bind SRVSVC
    5. Call NetShareEnumAll
    6. Enforce caps and clean disconnect
    """
    shares = []
    conn = None
    
    try:
        # Create SMB connection with SMB1 (NT1) dialect only
        conn = SMBConnection(
            remoteName=host,
            remoteHost=host,
            timeout=timeout,
            preferredDialect=smb.SMB_DIALECT
        )
        
        # Anonymous login - refuse any credentials
        conn.login('', '', domain='')
        
        # Verify we're using SMB1/NT1
        if conn.getDialect() != smb.SMB_DIALECT:
            raise SMB1SecurityError(f"Expected SMB1/NT1, got dialect: {conn.getDialect()}")
        
        # Connect to SRVSVC via IPC$ share
        conn.connectTree('IPC$')
        
        # Set up SRVSVC RPC interface
        dce = conn.connectDCE('\\PIPE\\srvsvc')
        
        # Bind to SRVSVC interface (UUID from audit spec)
        srvsvc.hNetrShareEnum(dce, NULL, 1)
        
        # Get shares via NetShareEnumAll (level 1)
        resp = srvsvc.hNetrShareEnum(dce, host, 1)
        
        # Parse response with security controls
        if resp['InfoStruct']['ShareInfo']['Level'] != 1:
            raise SMB1SecurityError("Unexpected NetShareEnum response level")
        
        share_info = resp['InfoStruct']['ShareInfo']['ShareInfo1']
        
        if share_info['EntriesRead'] > max_shares:
            raise SMB1SecurityError(f"Too many shares: {share_info['EntriesRead']} > {max_shares}")
        
        # Process each share with validation
        for i in range(share_info['EntriesRead']):
            try:
                share_entry = share_info['Buffer'][i]
                
                # Extract and validate share name
                share_name = str(share_entry['shi1_netname']).strip()
                share_name = strip_control(share_name)
                
                if not validate_share_name(share_name, max_share_name_len):
                    continue  # Skip invalid share names
                
                # Extract share type
                share_type_num = share_entry['shi1_type']
                share_type = _map_share_type(share_type_num)
                
                # Only allow whitelisted share types
                if share_type not in ['Disk', 'IPC', 'Printer']:
                    continue
                
                shares.append({
                    'name': share_name,
                    'type': share_type,
                    'protocol': 'SMB1'
                })
                
            except Exception as e:
                # Skip malformed share entries
                continue
        
        return shares
        
    except SMBError as e:
        raise SMB1ProbeError(f"SMB error: {e}")
    except Exception as e:
        raise SMB1ProbeError(f"Impacket probe failed: {e}")
    finally:
        # Clean disconnect
        if conn:
            try:
                conn.close()
            except:
                pass


def _scan_with_smbclient_fallback(
    host: str,
    timeout: int,
    max_stdout_bytes: int,
    max_shares: int,
    max_share_name_len: int
) -> List[Dict[str, str]]:
    """
    Fallback SMB1 scanning using hardened smbclient.
    
    Implements the audit-required smbclient fallback with:
    - NT1 protocol pinning
    - Anonymous authentication
    - Strict output parsing with caps
    """
    # SMB1-specific options (override defaults)
    smb1_options = [
        "--option=client min protocol=NT1",
        "--option=client max protocol=NT1",
        "--option=client signing=required"
    ]
    
    try:
        result = run_smbclient_safe(
            host=host,
            list_shares=True,
            additional_options=smb1_options,
            timeout=timeout,
            max_output_bytes=max_stdout_bytes
        )
        
        if result.timeout_exceeded:
            raise SMB1TimeoutError(f"smbclient timeout exceeded for {host}")
        
        if result.output_truncated:
            raise SMB1SecurityError(f"Output truncated for {host} - possible attack")
        
        # Parse smbclient output with security controls
        return _parse_smbclient_output(
            result.stdout, max_shares, max_share_name_len
        )
        
    except (ProcessExecutionError, ProcessTimeoutError) as e:
        raise SMB1ProbeError(f"smbclient execution failed: {e}")


def _parse_smbclient_output(
    output: str,
    max_shares: int,
    max_share_name_len: int
) -> List[Dict[str, str]]:
    """
    Parse smbclient output with strict security controls.
    
    Implements fail-closed parsing with:
    - Control character stripping
    - Share count limits
    - Share name validation
    - Type whitelisting
    """
    shares = []
    
    # Strip control characters from entire output
    clean_output = strip_control(output)
    
    # Split into lines and enforce line limits
    lines = clean_output.split('\n')
    if len(lines) > 1000:  # Reasonable line limit
        raise SMB1SecurityError("Too many output lines - possible attack")
    
    # State machine for parsing
    in_shares_section = False
    share_count = 0
    
    for line in lines:
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # Detect start of shares section
        if re.match(r'^\s*Sharename\s+Type\s+Comment', line, re.IGNORECASE):
            in_shares_section = True
            continue
        
        # Detect end of shares section
        if in_shares_section and (
            line.startswith('Server') or 
            line.startswith('Workgroup') or
            line.startswith('Domain') or
            '---' in line
        ):
            break
        
        # Parse share line if in shares section
        if in_shares_section:
            share_info = _parse_share_line(line, max_share_name_len)
            if share_info:
                share_count += 1
                if share_count > max_shares:
                    raise SMB1SecurityError(f"Too many shares: {share_count} > {max_shares}")
                
                shares.append({
                    'name': share_info['name'],
                    'type': share_info['type'], 
                    'protocol': 'SMB1'
                })
    
    return shares


def _parse_share_line(line: str, max_share_name_len: int) -> Optional[Dict[str, str]]:
    """
    Parse individual share line with validation.
    
    Expected format: "ShareName    Type    Comment"
    """
    # Skip separator lines
    if re.match(r'^[-\s]*$', line):
        return None
    
    # Parse with regex to handle variable spacing
    match = re.match(r'^(\S+)\s+(Disk|IPC|Printer)\s*(.*)?$', line, re.IGNORECASE)
    if not match:
        return None  # Skip unparseable lines (fail-closed)
    
    share_name = match.group(1).strip()
    share_type = match.group(2).strip()
    
    # Validate share name
    if not validate_share_name(share_name, max_share_name_len):
        return None
    
    # Normalize share type
    share_type_normalized = share_type.capitalize()
    
    # Only allow whitelisted types
    if share_type_normalized not in ['Disk', 'IPC', 'Printer']:
        return None
    
    return {
        'name': share_name,
        'type': share_type_normalized
    }


def _map_share_type(type_num: int) -> str:
    """
    Map Windows share type number to string.
    
    Args:
        type_num: Windows SHARE_TYPE value
        
    Returns:
        Share type string or 'Unknown'
    """
    type_map = {
        0: 'Disk',      # STYPE_DISKTREE
        1: 'Printer',   # STYPE_PRINTQ
        2: 'Device',    # STYPE_DEVICE  
        3: 'IPC',       # STYPE_IPC
        0x80000000: 'Hidden'  # STYPE_SPECIAL (administrative)
    }
    
    # Mask off temporary and hidden flags for base type
    base_type = type_num & 0x7FFFFFFF
    return type_map.get(base_type, 'Unknown')


def test_smb1_availability(host: str, timeout: int = 10) -> bool:
    """
    Test if a host supports SMB1 protocol.
    
    Performs minimal SMB1 dialect negotiation test without authentication.
    Used for pre-flight checks before full SMB1 discovery.
    
    Args:
        host: Target hostname or IP
        timeout: Connection timeout
        
    Returns:
        True if SMB1/NT1 is supported
    """
    clean_host = sanitize_hostname(host)
    if not clean_host:
        return False
    
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout)
            sock.connect((clean_host, 445))
            
            # SMB1 negotiate request for NT1 dialect
            negotiate_req = (
                b'\x00'  # NetBIOS message type
                b'\x00\x00\x54'  # Message length (84 bytes)
                b'\xFF\x53\x4D\x42'  # SMB signature
                b'\x72'  # SMB command (negotiate)
                b'\x00\x00\x00\x00'  # NT status
                b'\x18'  # Flags
                b'\x01\x28'  # Flags2
                b'\x00\x00'  # Process ID high
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Signature
                b'\x00\x00'  # Reserved
                b'\x00\x00'  # Tree ID
                b'\x2F\x4B'  # Process ID
                b'\x00\x00'  # User ID
                b'\xC5\x5E'  # Multiplex ID
                b'\x00'  # Word count
                b'\x31\x00'  # Byte count (49 bytes)
                b'\x02NT LM 0.12\x00'  # NT1 dialect
            )
            
            sock.send(negotiate_req)
            
            # Read response with timeout
            sock.settimeout(5)
            response = sock.recv(1024)
            
            # Check for valid SMB response with NT1 dialect
            if len(response) >= 4 and response[:4] == b'\x00\x00\x00':
                # Extract NetBIOS length
                nb_len = struct.unpack('>I', b'\x00' + response[1:4])[0]
                if len(response) >= nb_len + 4:
                    # Look for SMB signature and successful negotiate
                    smb_data = response[4:4+nb_len]
                    if (len(smb_data) >= 4 and 
                        smb_data[:4] == b'\xFF\x53\x4D\x42'):
                        return True
            
            return False
            
    except Exception:
        return False


def validate_smb1_mode_constraints(
    enable_smb1: bool,
    yes_i_know: bool,
    username: Optional[str] = None,
    password: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Validate SMB1 mode security constraints from audit requirements.
    
    Args:
        enable_smb1: Whether SMB1 mode is enabled
        yes_i_know: Whether user acknowledged risks
        username: Username (must be empty for SMB1)
        password: Password (must be empty for SMB1)
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not enable_smb1:
        return True, ""
    
    # SMB1 mode requires explicit acknowledgment
    if not yes_i_know:
        return False, (
            "SMB1 Discovery Mode requires explicit acknowledgment. "
            "Use --yes-i-know to acknowledge security risks."
        )
    
    # SMB1 mode must be anonymous only
    if username or password:
        return False, (
            "SMB1 Discovery Mode only supports anonymous authentication. "
            "Remove username/password for SMB1 mode."
        )
    
    return True, ""


def print_smb1_banner_start():
    """Print SMB1 mode start banner as required by audit."""
    print("⚠ WARNING: SMB1 Discovery Mode Active")
    print("⚠ Protocol: NT1 (SMB1) | Auth: Anonymous | Mode: Discovery-only")
    print("⚠ This mode has security risks and should only be used for discovery")


def print_smb1_banner_end():
    """Print SMB1 mode end banner as required by audit."""
    print("✓ SMB1 Discovery Mode ended; SMB1 remains disabled")
    print("✓ Returning to safe SMB2/3 default mode")