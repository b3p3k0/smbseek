"""
SMBSeek Access Operations

Share access verification functionality for the unified workflow.
Tests access to SMB shares on authenticated servers.
"""

import subprocess
import csv
import json
import re
import time
import sys
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO
from dataclasses import dataclass
from typing import Set, List, Dict, Optional, Any

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import load_config, get_standard_timestamp
from shared.database import create_workflow_database
from shared.output import create_output_manager

# Check if SMB libraries are available
SMB_AVAILABLE = False
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open, CreateDisposition, ImpersonationLevel, FileAttributes, ShareAccess
    from smbprotocol.exceptions import SMBException
    import uuid
    SMB_AVAILABLE = True
except ImportError:
    pass


@dataclass
class AccessResult:
    """Results from share access verification operation"""
    accessible_hosts: int        # Count of hosts with any accessible shares
    accessible_shares: int       # Total count of accessible share entries
    share_details: List[Dict]    # Detailed share information


class AccessOperation:
    """
    SMB share access verification operation.

    Tests access to SMB shares on previously authenticated servers.
    """

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

    def __init__(self, config, output, database, session_id, cautious_mode=False, check_rce=False):
        """
        Initialize access operation.

        Args:
            config: SMBSeekConfig instance
            output: SMBSeekOutput instance
            database: SMBSeekWorkflowDatabase instance
            session_id: Database session ID for this operation
            cautious_mode: Enable modern security hardening if True
            check_rce: Enable RCE vulnerability analysis if True
        """
        self.config = config
        self.output = output
        self.database = database
        self.session_id = session_id
        self.cautious_mode = cautious_mode
        self.check_rce = check_rce
        
        # Check smbclient availability for share enumeration
        self.smbclient_available = self.check_smbclient_availability()
        if not self.smbclient_available:
            self.output.print_if_verbose("smbclient unavailable; share enumeration will be limited.")

        self.results = []
        self.total_targets = 0
    
    def check_smbclient_availability(self):
        """Check if smbclient command is available on the system."""
        try:
            result = subprocess.run(['smbclient', '--help'],
                                  capture_output=True,
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def _build_smbclient_cmd(self, operation_type, target, username="", password="", **kwargs):
        """
        Build complete smbclient command with security options and credentials.

        Args:
            operation_type: Type of operation ("enumerate" or "access")
            target: Target IP address
            username: Username for authentication
            password: Password for authentication
            **kwargs: Additional parameters (e.g., share for access operations)

        Returns:
            List containing complete smbclient command
        """
        cmd = ["smbclient"]

        if self.cautious_mode:
            # Cautious mode: Apply security hardening flags
            cmd.extend([
                "--client-protection=sign",  # Require signing (Samba 4.11+)
                "--max-protocol=SMB3",       # Allow SMB2/3, block SMB1
                "--option=client min protocol=SMB2",
                "--option=client smb encrypt=desired"  # Prefer but don't require encryption
            ])

        # Add operation-specific parts
        if operation_type == "enumerate":
            cmd.extend(["-L", f"//{target}"])
        elif operation_type == "access":
            share = kwargs.get('share')
            cmd.extend([f"//{target}/{share}"])

        # Add credentials (after security options)
        if username == "" and password == "":
            cmd.append("-N")  # Anonymous
        elif username == "guest":
            if password == "":
                cmd.extend(["--user", "guest%"])
            else:
                cmd.extend(["--user", f"guest%{password}"])
        else:
            cmd.extend(["--user", f"{username}%{password}"])

        return cmd

    def _execute_with_fallback(self, cmd, **kwargs):
        """
        Execute smbclient command with fallback for unsupported security flags.

        Args:
            cmd: smbclient command list
            **kwargs: Additional arguments for subprocess.run

        Returns:
            subprocess.CompletedProcess result
        """
        try:
            result = subprocess.run(cmd, **kwargs)
            return result
        except subprocess.CalledProcessError as e:
            if self.cautious_mode and "Unknown option" in (e.stderr or ""):
                # Fallback: remove modern security flags and retry with older syntax
                fallback_cmd = [arg for arg in cmd if not arg.startswith("--client-protection")]

                # Add older signing syntax if the modern flag was removed
                if "--client-protection=sign" in cmd:
                    # Insert after 'smbclient' but before target/operation flags
                    insert_pos = 1
                    fallback_cmd.insert(insert_pos, "--option=client signing=required")

                self.output.print_if_verbose("Falling back to older smbclient syntax for security options")
                return subprocess.run(fallback_cmd, **kwargs)
            raise
    
    def execute(self, target_ips: Set[str], recent_hours=None) -> AccessResult:
        """
        Execute the access verification operation.

        Args:
            target_ips: Set of IP addresses to test for share access
            recent_hours: Filter for hosts discovered in recent hours (optional)

        Returns:
            AccessResult with share enumeration statistics

        Raises:
            RuntimeError: If SMB libraries unavailable
        """
        if not SMB_AVAILABLE:
            raise RuntimeError("SMB libraries not available. Install with: pip install smbprotocol pyspnego")

        self.output.print_if_verbose("Starting share access verification...")

        # Convert target IPs to list for database queries
        target_ip_list = list(target_ips)

        # Get authenticated host information from database
        authenticated_hosts = self.database.get_authenticated_hosts(
            ip_filter=target_ip_list,
            recent_hours=recent_hours
        )

        if not authenticated_hosts:
            self.output.warning("No authenticated hosts available for share testing")
            return AccessResult(
                accessible_hosts=0,
                accessible_shares=0,
                share_details=[]
            )

        self.total_targets = len(authenticated_hosts)
        self.output.info(f"Testing share access on {self.total_targets} authenticated hosts")

        # Get concurrency setting and clamp pool size
        max_concurrent = self.config.get_max_concurrent_hosts()
        max_workers = min(max_concurrent, len(authenticated_hosts) or 1)

        # Preallocate results array for deterministic ordering
        results_by_index = [None] * len(authenticated_hosts)

        # Process hosts with controlled concurrency
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks with index and host position tracking
            future_to_metadata = {}
            for index, host in enumerate(authenticated_hosts):
                host_position = index + 1
                future = executor.submit(self.process_target, host, host_position)
                future_to_metadata[future] = (index, host_position)

            # Collect results in deterministic order
            for future in future_to_metadata:
                index, _host_position = future_to_metadata[future]
                try:
                    result = future.result()
                    results_by_index[index] = result
                except Exception as e:
                    # Create error result with same structure as process_target
                    host = authenticated_hosts[index]
                    error_result = {
                        'ip_address': host.get('ip_address', 'unknown'),
                        'country': host.get('country', 'unknown'),
                        'auth_method': host.get('auth_method', 'unknown'),
                        'timestamp': get_standard_timestamp(),
                        'error': f"Processing failed: {str(e)}",
                        'shares_found': [],
                        'accessible_shares': [],
                        'share_details': []
                    }
                    results_by_index[index] = error_result
                    self.output.error(f"Failed to process {host.get('ip_address', 'unknown')}: {str(e)}")

        # Store results maintaining original order
        self.results = results_by_index

        # Save results to database using session_id and compute summary
        accessible_hosts, accessible_shares, share_details = self._save_and_summarize_results()

        self.output.print_if_verbose(f"Access verification completed: {accessible_hosts} hosts, {accessible_shares} shares")

        return AccessResult(
            accessible_hosts=accessible_hosts,
            accessible_shares=accessible_shares,
            share_details=share_details
        )
    
    def parse_auth_method(self, auth_method_str):
        """Parse authentication method string to extract credentials."""
        # Handle different auth method formats from database
        auth_lower = auth_method_str.lower()
        
        if 'anonymous' in auth_lower:
            return "", ""
        elif 'guest/blank' in auth_lower or 'guest/' in auth_lower:
            return "guest", ""
        elif 'guest/guest' in auth_lower:
            return "guest", "guest"
        else:
            # Default fallback
            self.output.print_if_verbose(f"Unknown auth method '{auth_method_str}', defaulting to guest/guest")
            return "guest", "guest"
    
    def enumerate_shares(self, ip, username, password):
        """Enumerate available SMB shares on the target server."""
        if not self.smbclient_available:
            return []

        try:
            # Build smbclient command with security options
            cmd = self._build_smbclient_cmd("enumerate", ip, username, password)

            self.output.print_if_verbose(f"Enumerating shares: {' '.join(cmd)}")

            # Run command with timeout and fallback handling, prevent password prompts
            result = self._execute_with_fallback(cmd, capture_output=True, text=True,
                                               timeout=15, stdin=subprocess.DEVNULL)

            # Parse shares from output
            if result.returncode == 0 or "Sharename" in result.stdout:
                shares = self.parse_share_list(result.stdout)
                self.output.print_if_verbose(f"Found {len(shares)} non-admin shares")
                return shares
            elif self.cautious_mode and result.returncode != 0:
                # In cautious mode, provide informational message for failures
                if "NT_STATUS" in result.stderr:
                    self.output.print_if_verbose(f"Share enumeration failed on {ip}: rejected in cautious mode")

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.output.print_if_verbose(f"Share enumeration failed: {str(e)}")

        return []
    
    def _is_section_header(self, line):
        """Check if line is an actual smbclient section header, not a share name."""
        line_lower = line.strip().lower()

        # Check for actual section headers with required keywords
        if line_lower.startswith("server") and "comment" in line_lower:
            return True
        elif line_lower.startswith("workgroup") and "master" in line_lower:
            return True
        elif line_lower.startswith("domain") and "controller" in line_lower:
            return True
        elif line_lower.startswith("session request"):
            return True

        return False

    def parse_share_list(self, smbclient_output):
        """Parse smbclient -L output to extract non-administrative share names."""
        shares = []
        lines = smbclient_output.split('\n')
        in_share_section = False
        share_section_ended = False

        self.output.print_if_verbose("Parsing smbclient share list output")
        
        for line_num, line in enumerate(lines):
            line = line.strip()
            
            # Skip if we've already finished parsing the shares section
            if share_section_ended:
                break
            
            # Look for the start of the shares section
            if not in_share_section and "Sharename" in line and "Type" in line:
                in_share_section = True
                if True:  # verbose check handled by output methods
                    self.output.print_if_verbose(f"Found shares section header at line {line_num + 1}")
                continue
            
            # Skip header separator lines (dashes)
            if in_share_section and line.startswith("-"):
                continue
            
            # Detect end of shares section - more robust logic
            if in_share_section:
                # Empty line followed by section header indicates end
                if line == "":
                    # Check if next non-empty line is a section header
                    for next_line in lines[line_num + 1:line_num + 3]:  # Check next 2 lines
                        next_line = next_line.strip()
                        if next_line:  # Skip empty lines when scanning ahead
                            if self._is_section_header(next_line):
                                share_section_ended = True
                                if True:  # verbose check handled by output methods
                                    self.output.print_if_verbose(f"Detected end of shares section at line {line_num + 1}")
                                break
                            break  # Stop at first non-empty line
                    continue

                # Direct detection of section end markers
                elif self._is_section_header(line):
                    share_section_ended = True
                    if True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Found section end marker at line {line_num + 1}: {line[:30]}...")
                    break
            
            # Parse share lines - only when in shares section and not ended
            if in_share_section and not share_section_ended and line:
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    
                    # Validate share name format (basic sanity check)
                    if not share_name.replace('_', '').replace('-', '').isalnum():
                        if True:  # verbose check handled by output methods
                            self.output.print_if_verbose(f"Skipping invalid share name format: {share_name}")
                        continue
                    
                    # Only include non-administrative Disk shares
                    if not share_name.endswith('$') and share_type == "Disk":
                        shares.append(share_name)
                        if True:  # verbose check handled by output methods
                            self.output.print_if_verbose(f"Added share: {share_name}")
                    elif share_name.endswith('$'):
                        self.output.print_if_verbose(f"Skipped administrative share: {share_name}")
                    elif True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Skipped non-disk share: {share_name} ({share_type})")
        
        self.output.print_if_verbose(f"Parsed {len(shares)} valid shares from smbclient output")
        
        return shares
    
    def test_share_access(self, ip, share_name, username, password):
        """Test read access to a specific SMB share using smbclient."""
        access_result = {
            'share_name': share_name,
            'accessible': False,
            'error': None,
            'auth_status': None
        }

        try:
            # Build smbclient command with security options
            cmd = self._build_smbclient_cmd("access", ip, username, password, share=share_name)

            # Add command to list directory (test read access)
            cmd.extend(["-c", "ls"])

            if True:  # verbose check handled by output methods
                self.output.print_if_verbose(f"Testing access: {' '.join(cmd)}")

            # Run command with timeout and fallback handling
            result = self._execute_with_fallback(cmd, capture_output=True, text=True,
                                               timeout=15, stdin=subprocess.DEVNULL)

            # Check if listing was successful
            if result.returncode == 0:
                # Additional check: ensure we got actual file listing output
                if "NT_STATUS" not in result.stderr and len(result.stdout.strip()) > 0:
                    access_result['accessible'] = True
                    access_result['auth_status'] = "OK"
                    if True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Share '{share_name}' is accessible")
                else:
                    access_result['error'] = f"Access denied or empty share"
                    access_result['auth_status'] = self._extract_nt_status(result.stderr) or "ACCESS_DENIED"
                    if True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Share '{share_name}' - no readable content")
            else:
                # Format error using new helper
                friendly_msg, raw_context = self._format_smbclient_error(result)
                share_missing = 'NT_STATUS_BAD_NETWORK_NAME' in friendly_msg

                if share_missing:
                    access_result['error'] = "Share not found on server (server reported NT_STATUS_BAD_NETWORK_NAME)"
                    access_result['auth_status'] = "NT_STATUS_BAD_NETWORK_NAME"
                else:
                    access_result['error'] = friendly_msg
                    access_result['auth_status'] = self._extract_nt_status(friendly_msg) or "ERROR"

                # In cautious mode, provide informational message for security-related failures
                if self.cautious_mode and "NT_STATUS" in friendly_msg:
                    if "ACCESS_DENIED" in friendly_msg or "LOGON_FAILURE" in friendly_msg:
                        self.output.print_if_verbose(f"Share '{share_name}' access denied - security restrictions in cautious mode")

                if True:  # verbose check handled by output methods
                    # Consider ACCESS_DENIED and missing shares as expected outcomes
                    is_expected_denial = 'NT_STATUS_ACCESS_DENIED' in friendly_msg

                    if is_expected_denial or share_missing:
                        # Suppress detailed output for expected access denials/missing shares
                        # Let the summary processing handle all user-facing output
                        pass
                    else:
                        # Show detailed red errors only for genuine technical failures
                        if raw_context and raw_context != friendly_msg:
                            self.output.error(f"Share '{share_name}' - {friendly_msg} [{raw_context}]")
                        else:
                            self.output.error(f"Share '{share_name}' - {friendly_msg}")

        except subprocess.TimeoutExpired:
            access_result['error'] = "Connection timeout (smbclient)"
            access_result['auth_status'] = "TIMEOUT"
            if True:  # verbose check handled by output methods
                self.output.warning(
                    f"Share '{share_name}' - timeout (consider increasing share access timeout if this is frequent)"
                )
        except Exception as e:
            access_result['error'] = f"Test error: {str(e)}"
            access_result['auth_status'] = "ERROR"
            if True:  # verbose check handled by output methods
                self.output.warning(f"Share '{share_name}' - test error: {str(e)}")

        return access_result

    def _format_smbclient_error(self, result):
        """
        Format smbclient error messages with NT_STATUS codes and context.

        Args:
            result: subprocess.CompletedProcess with stdout, stderr, returncode

        Returns:
            tuple: (friendly_message, raw_combined_context)
        """
        # Combine and trim stdout/stderr
        def _clean(stream: Optional[str]) -> str:
            if not stream:
                return ""
            # Strip whitespace and trailing tildes some smbclient builds append
            return stream.strip().rstrip("~").strip()

        stderr_trimmed = _clean(result.stderr)
        stdout_trimmed = _clean(result.stdout)

        # Combine both streams with separator when both exist
        if stderr_trimmed and stdout_trimmed:
            combined_output = f"{stderr_trimmed} | {stdout_trimmed}"
        elif stderr_trimmed:
            combined_output = stderr_trimmed
        elif stdout_trimmed:
            combined_output = stdout_trimmed
        else:
            combined_output = ""

        # If no output at all, provide exit code info
        if not combined_output:
            return (f"smbclient exited with code {result.returncode} and produced no output", "")

        # Look for NT_STATUS codes using regex
        nt_status_match = re.search(r'(NT_STATUS_[A-Z_]+)', combined_output)

        # Friendly formatting for expected anonymous/guest access denials
        if nt_status_match and nt_status_match.group(1) == 'NT_STATUS_ACCESS_DENIED':
            combined_lower = combined_output.lower()
            if 'tree connect failed' in combined_lower and 'anonymous login successful' in combined_lower:
                friendly_msg = 'Access denied - share does not allow anonymous/guest browsing (NT_STATUS_ACCESS_DENIED)'
                return (friendly_msg, None)

        # Friendly formatting for logon failures that spam tree connect failed
        if nt_status_match and nt_status_match.group(1) == 'NT_STATUS_LOGON_FAILURE':
            combined_lower = combined_output.lower()
            if 'tree connect failed' in combined_lower:
                friendly_msg = 'Authentication failed for this share (NT_STATUS_LOGON_FAILURE)'
                return (friendly_msg, None)

        if nt_status_match:
            status_code = nt_status_match.group(1)
            hint = self.SMB_STATUS_HINTS.get(status_code, "SMB protocol error")

            # Special-case: missing share should be concise and friendly
            if status_code == 'NT_STATUS_BAD_NETWORK_NAME':
                friendly_msg = "Share not found on server (NT_STATUS_BAD_NETWORK_NAME)"
                return (friendly_msg, None)

            # Find context around the status code (up to 80 chars before/after)
            start_pos = max(0, nt_status_match.start() - 80)
            end_pos = min(len(combined_output), nt_status_match.end() + 80)
            context = combined_output[start_pos:end_pos]

            # Trim to ~160 chars total if needed
            if len(context) > 160:
                context = context[:157] + "..."

            friendly_msg = f"{hint} ({status_code}) - {context}"

            # Avoid duplicating context in caller; only return raw context if it adds value
            raw_ctx = combined_output if combined_output != friendly_msg else None
            return (friendly_msg, raw_ctx)
        else:
            # No NT_STATUS found, provide generic error with trimmed output
            trimmed_output = combined_output[:160] + "..." if len(combined_output) > 160 else combined_output
            return (f"smbclient error: {trimmed_output}", combined_output)


    @staticmethod
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

    def process_target(self, host_record, host_position):
        """Process a single host target for share access testing."""
        ip = host_record['ip_address']
        country = host_record.get('country', 'Unknown')
        auth_method = host_record['auth_method']

        host_label = f"Host {host_position}/{self.total_targets}"
        self.output.info(f"[{host_position}/{self.total_targets}] Testing {ip} ({country})...")

        username, password = self.parse_auth_method(auth_method)
        if True:
            self.output.info(f"Using auth: {username}/{password if password else '[blank]'}")

        target_result = {
            'ip_address': ip,
            'country': country,
            'auth_method': auth_method,
            'timestamp': get_standard_timestamp(),
            'shares_found': [],
            'accessible_shares': [],
            'share_details': []
        }

        try:
            port_timeout = self.config.get_connection_timeout()
            if not self.check_port(ip, 445, port_timeout):
                self.output.error(f"Port 445 not accessible on {ip}")
                target_result['error'] = 'Port 445 not accessible'
                return target_result

            shares = self.enumerate_shares(ip, username, password)
            target_result['shares_found'] = shares

            if not shares:
                self.output.warning(f"No non-administrative shares found on {ip}")
                if self.check_rce:
                    self._analyze_rce_vulnerabilities(target_result)
                return target_result

            self.output.success(f"Found {len(shares)} shares to test on {ip}")

            for i, share_name in enumerate(shares, 1):
                access_result = self.test_share_access(ip, share_name, username, password)
                target_result['share_details'].append(access_result)

                if access_result['accessible']:
                    target_result['accessible_shares'].append(share_name)
                    self.output.success(f"{host_label}: Share {i}/{len(shares)}: {share_name} - accessible")
                else:
                    message = access_result.get('error', 'not accessible') or ''
                    status = access_result.get('auth_status') or ''
                    if 'ACCESS_DENIED' in status:
                        self.output.warning(f"{host_label}: Share {i}/{len(shares)}: {share_name} - Access denied")
                    elif 'BAD_NETWORK_NAME' in status or 'share not found' in message.lower():
                        self.output.warning(f"{host_label}: Share {i}/{len(shares)}: {share_name} - {message}")
                    elif 'TIMEOUT' in status or 'timeout' in message.lower() or 'connection' in message.lower():
                        self.output.error(f"{host_label}: Share {i}/{len(shares)}: {share_name} - {message}")
                    else:
                        self.output.warning(f"{host_label}: Share {i}/{len(shares)}: {share_name} - Access failed")

                if share_name != shares[-1]:
                    delay = self.config.get_share_access_delay()
                    time.sleep(delay)

            accessible_count = len(target_result['accessible_shares'])
            total_count = len(shares)

            if accessible_count > total_count:
                self.output.error(f"VALIDATION ERROR: {accessible_count} accessible > {total_count} total shares on {ip}")
                target_result['validation_error'] = f"Accessible count ({accessible_count}) exceeds total count ({total_count})"

            if len(set(target_result['accessible_shares'])) != len(target_result['accessible_shares']):
                duplicates = [x for x in target_result['accessible_shares'] if target_result['accessible_shares'].count(x) > 1]
                self.output.warning(f"VALIDATION WARNING: Duplicate shares in accessible list: {set(duplicates)}")
                target_result['validation_warning'] = f"Duplicate accessible shares: {set(duplicates)}"

            invalid_shares = [share for share in target_result['accessible_shares'] if share not in shares]
            if invalid_shares:
                self.output.error(f"VALIDATION ERROR: Accessible shares not in original list: {invalid_shares}")
                target_result['validation_error'] = f"Invalid accessible shares: {invalid_shares}"

            if accessible_count > 0:
                self.output.success(f"{accessible_count}/{total_count} shares accessible on {ip}: {', '.join(target_result['accessible_shares'])}")
            else:
                self.output.warning(f"0/{total_count} shares accessible on {ip}")

            if self.check_rce:
                self._analyze_rce_vulnerabilities(target_result)

        except Exception as e:
            self.output.error(f"Error testing target {ip}: {str(e)[:50]}")
            target_result['error'] = str(e)

        return target_result

    def _analyze_rce_vulnerabilities(self, target_result: Dict[str, Any]) -> None:
        """
        Perform RCE vulnerability analysis on target host.

        Args:
            target_result: Target result dictionary to update with RCE analysis
        """
        try:
            from shared.rce_scanner import scan_rce_indicators

            ip = target_result.get('ip_address', 'unknown')
            self.output.print_if_verbose(f"Performing RCE analysis for {ip}")

            # Build host context from target result
            host_context = {
                'ip_address': ip,
                'country': target_result.get('country', 'unknown'),
                'auth_method': target_result.get('auth_method', ''),
                'shares_found': target_result.get('shares_found', []),
                'accessible_shares': target_result.get('accessible_shares', []),
                'share_details': target_result.get('share_details', []),
                'timestamp': target_result.get('timestamp', '')
            }

            # Add any additional context from configuration or environment
            # (SMB dialects, OS hints, etc. would come from connection attempts)

            # Perform RCE analysis
            rce_result = scan_rce_indicators(host_context)

            # Store RCE results in target_result
            target_result['rce_analysis'] = rce_result

            # Output summary based on verbosity
            score = rce_result.get('score', 0)
            level = rce_result.get('level', 'unknown')
            status = rce_result.get('status', 'analyzed')

            if status == 'insufficient-data':
                self.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - Limited data available")
            elif self.output.verbose:
                # Verbose output with details
                matched_count = len(rce_result.get('matched_rules', []))
                if matched_count > 0:
                    self.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - {matched_count} potential vulnerabilities detected")
                    for rule in rce_result.get('matched_rules', [])[:2]:  # Show first 2
                        rule_name = rule.get('name', 'Unknown')
                        rule_score = rule.get('score', 0)
                        self.output.print_if_verbose(f"  - {rule_name}: {rule_score} points")
                else:
                    self.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - No specific vulnerabilities detected")
            else:
                # Quiet output - just the summary
                self.output.info(f"RCE Analysis: {score}/100 ({level})")

        except ImportError:
            self.output.error("RCE scanner not available - missing dependencies")
            target_result['rce_analysis'] = {
                'score': 0,
                'level': 'error',
                'status': 'scanner-unavailable',
                'error': 'RCE scanner dependencies not found'
            }
        except Exception as e:
            self.output.error(f"RCE analysis failed for {ip}: {str(e)}")
            target_result['rce_analysis'] = {
                'score': 0,
                'level': 'error',
                'status': 'analysis-failed',
                'error': str(e)
            }

    def _save_and_summarize_results(self):
        """
        Save results to database using session_id and compute summary statistics.

        Uses the proven working storage logic from save_results() method to avoid
        the regression introduced during workflow unification.

        Returns:
            Tuple of (accessible_hosts, accessible_shares, share_details)
        """
        try:
            # Store results using the proven working logic from save_results()
            # Save to database - exclude results with errors or validation issues
            stored_count = 0
            validation_errors = 0

            for result in self.results:
                # Skip results with errors or validation problems
                if 'error' in result or 'validation_error' in result:
                    if 'validation_error' in result:
                        validation_errors += 1
                        self.output.print_if_verbose(f"Skipping storage of {result.get('ip_address', 'unknown')} due to validation error")
                    continue

                # Use the complete result structure (not individual shares) - this is the key fix
                if self.database.store_share_access_result(self.session_id, result):
                    stored_count += 1
                else:
                    self.output.print_if_verbose(f"Failed to store results for {result.get('ip_address', 'unknown')}")

            # Compute summary statistics from the stored results
            accessible_hosts = set()
            total_accessible_shares = 0
            share_details = []

            for result in self.results:
                # Skip results with errors
                if 'error' in result or 'validation_error' in result:
                    continue

                ip_address = result.get('ip_address')
                accessible_shares = result.get('accessible_shares', [])

                if accessible_shares:
                    accessible_hosts.add(ip_address)
                    total_accessible_shares += len(accessible_shares)

                    # Add to details list for workflow summary
                    for share_name in accessible_shares:
                        share_details.append({
                            'ip_address': ip_address,
                            'share_name': share_name,
                            'accessible': True
                        })

            valid_results_count = len([r for r in self.results if 'error' not in r and 'validation_error' not in r])
            self.output.print_if_verbose(f"Stored {stored_count}/{valid_results_count} valid results to database")

            if validation_errors > 0:
                self.output.warning(f"Excluded {validation_errors} results due to validation errors")

            return len(accessible_hosts), total_accessible_shares, share_details

        except Exception as e:
            self.output.error(f"Failed to save results to database: {e}")
            return 0, 0, []

    def check_port(self, ip, port, timeout):
        """Check if a specific port is open on the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def save_results(self):
        """Save results to database and JSON file."""
        try:
            # Save to database - exclude results with errors or validation issues
            session_id = self.database.create_session('access')
            stored_count = 0
            validation_errors = 0
            
            for result in self.results:
                # Skip results with errors or validation problems
                if 'error' in result or 'validation_error' in result:
                    if 'validation_error' in result:
                        validation_errors += 1
                        if True:  # verbose check handled by output methods
                            self.output.print_if_verbose(f"Skipping storage of {result.get('ip_address', 'unknown')} due to validation error")
                    continue
                    
                if self.database.store_share_access_result(session_id, result):
                    stored_count += 1
                else:
                    if True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Failed to store results for {result.get('ip_address', 'unknown')}")
            
            valid_results_count = len([r for r in self.results if 'error' not in r and 'validation_error' not in r])
            if True:  # verbose check handled by output methods
                self.output.print_if_verbose(f"Stored {stored_count}/{valid_results_count} valid results to database")
                if validation_errors > 0:
                    self.output.warning(f"Excluded {validation_errors} results due to validation errors")
            
            # Also save to JSON file
            output_file = f"share_access_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            output_data = {
                'metadata': {
                    'tool': 'smbseek_access',
                    'version': '1.0',
                    'scan_date': get_standard_timestamp(),
                    'total_targets': self.total_targets,
                    'config': {
                        'share_access_delay': self.config.get_share_access_delay(),
                        'timeout': self.config.get_connection_timeout()
                    }
                },
                'results': self.results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.output.success(f"Results saved to {output_file}")
            
        except Exception as e:
            self.output.error(f"Failed to save results: {e}")
    
    def print_summary(self):
        """Print analysis summary."""
        if not self.results:
            return
        
        total_targets = len(self.results)
        targets_with_shares = len([r for r in self.results if r.get('shares_found')])
        targets_with_access = len([r for r in self.results if r.get('accessible_shares')])
        
        total_shares_found = sum(len(r.get('shares_found', [])) for r in self.results)
        total_accessible_shares = sum(len(r.get('accessible_shares', [])) for r in self.results)
        
        self.output.header("=== SUMMARY ===")
        self.output.info(f"Total targets processed: {total_targets}")
        self.output.info(f"Targets with shares: {targets_with_shares}")
        self.output.info(f"Targets with accessible shares: {targets_with_access}")
        self.output.info(f"Total shares found: {total_shares_found}")
        self.output.info(f"Total accessible shares: {total_accessible_shares}")
        
        if total_shares_found > 0:
            access_rate = (total_accessible_shares / total_shares_found) * 100
            self.output.info(f"Share access rate: {access_rate:.1f}%")


# Compatibility layer for old AccessCommand interface
class AccessCommand:
    """
    DEPRECATED: Legacy compatibility wrapper for AccessOperation.
    Use workflow.UnifiedWorkflow or AccessOperation directly.
    """

    def __init__(self, args):
        """
        Initialize legacy access command.

        Args:
            args: Parsed command line arguments
        """
        import warnings
        warnings.warn("AccessCommand is deprecated, use AccessOperation or UnifiedWorkflow",
                      DeprecationWarning, stacklevel=2)

        self.args = args

        # Load configuration and components for compatibility
        from shared.config import load_config
        from shared.database import create_workflow_database
        from shared.output import create_output_manager

        self.config = load_config(args.config)
        self.output = create_output_manager(
            self.config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )
        self.database = create_workflow_database(self.config, args.verbose)

    def execute(self) -> int:
        """
        Execute the legacy access command.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Create a session for backward compatibility
            session_data = {
                'tool_name': 'smbseek-access-legacy',
                'config_snapshot': '{}',
                'status': 'running'
            }
            session_id = self.database.dal.create_session(session_data)

            # Get target IPs based on legacy arguments
            if hasattr(self.args, 'servers') and self.args.servers:
                target_ips = set(ip.strip() for ip in self.args.servers.split(','))
            else:
                # Get all authenticated hosts from database
                authenticated_hosts = self.database.get_authenticated_hosts(
                    recent_hours=getattr(self.args, 'recent', None)
                )
                target_ips = set(host['ip_address'] for host in authenticated_hosts)

            if not target_ips:
                self.output.warning("No authenticated hosts found in database")
                self.output.info("Run discovery first")
                return 0

            # Create and execute the operation
            operation = AccessOperation(
                self.config,
                self.output,
                self.database,
                session_id
            )

            result = operation.execute(
                target_ips=target_ips,
                recent_hours=getattr(self.args, 'recent', None)
            )

            # Update session
            self.database.dal.update_session(session_id, {
                'status': 'completed',
                'total_targets': len(target_ips),
                'successful_targets': result.accessible_hosts
            })

            # Display legacy-style results
            self.output.subheader("Access Verification Results")
            self.output.print_if_not_quiet(f"Hosts Tested: {len(target_ips)}")
            self.output.print_if_not_quiet(f"Accessible Hosts: {result.accessible_hosts}")
            self.output.print_if_not_quiet(f"Accessible Shares: {result.accessible_shares}")

            if result.accessible_shares > 0:
                self.output.success(f"Found {result.accessible_shares} accessible shares on {result.accessible_hosts} hosts")
            else:
                self.output.warning("No accessible shares found")

            return 0

        except Exception as e:
            self.output.error(f"Access verification failed: {e}")
            if getattr(self.args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1

        finally:
            if hasattr(self.database, 'close'):
                self.database.close()
