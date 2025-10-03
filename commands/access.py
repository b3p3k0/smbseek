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
from datetime import datetime
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO
from dataclasses import dataclass
from typing import Set, List, Dict, Optional

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

    def __init__(self, config, output, database, session_id):
        """
        Initialize access operation.

        Args:
            config: SMBSeekConfig instance
            output: SMBSeekOutput instance
            database: SMBSeekWorkflowDatabase instance
            session_id: Database session ID for this operation
        """
        self.config = config
        self.output = output
        self.database = database
        self.session_id = session_id
        
        # Check smbclient availability for share enumeration
        self.smbclient_available = self.check_smbclient_availability()
        if not self.smbclient_available:
            self.output.print_if_verbose("smbclient unavailable; share enumeration will be limited.")

        self.results = []
        self.total_targets = 0
        self.current_target = 0
    
    def check_smbclient_availability(self):
        """Check if smbclient command is available on the system."""
        try:
            result = subprocess.run(['smbclient', '--help'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
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

        # Process each authenticated host
        for host in authenticated_hosts:
            target_result = self.process_target(host)
            self.results.append(target_result)

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
            # Use smbclient command to list shares
            cmd = ["smbclient", "-L", f"//{ip}"]
            
            # Add authentication based on credentials
            if username == "" and password == "":
                cmd.append("-N")  # No password (anonymous)
            elif username == "guest":
                if password == "":
                    cmd.extend(["--user", "guest%"])
                else:
                    cmd.extend(["--user", f"guest%{password}"])
            else:
                cmd.extend(["--user", f"{username}%{password}"])
            
            self.output.print_if_verbose(f"Enumerating shares: {' '.join(cmd)}")

            # Run command with timeout, prevent password prompts
            result = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=15, stdin=subprocess.DEVNULL)

            # Parse shares from output
            if result.returncode == 0 or "Sharename" in result.stdout:
                shares = self.parse_share_list(result.stdout)
                self.output.print_if_verbose(f"Found {len(shares)} non-admin shares")
                return shares

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.output.print_if_verbose(f"Share enumeration failed: {str(e)}")
        
        return []
    
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
                # Empty line followed by non-share content indicates end
                if line == "":
                    # Check if next non-empty line looks like end of shares
                    for next_line in lines[line_num + 1:line_num + 3]:  # Check next 2 lines
                        next_line = next_line.strip()
                        if next_line and (next_line.startswith("Server") or 
                                        next_line.startswith("Workgroup") or
                                        next_line.startswith("Domain")):
                            share_section_ended = True
                            if True:  # verbose check handled by output methods
                                self.output.print_if_verbose(f"Detected end of shares section at line {line_num + 1}")
                            break
                    continue
                
                # Direct detection of section end markers
                elif (line.startswith("Server") or line.startswith("Workgroup") or 
                      line.startswith("Domain") or line.startswith("session request")):
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
                    elif self.args.verbose and share_name.endswith('$'):
                        self.output.print_if_verbose(f"Skipped administrative share: {share_name}")
                    elif True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Skipped non-disk share: {share_name} ({share_type})")
        
        if True:  # verbose check handled by output methods
            self.output.info(f"Parsed {len(shares)} valid shares from smbclient output")
        
        return shares
    
    def test_share_access(self, ip, share_name, username, password):
        """Test read access to a specific SMB share using smbclient."""
        access_result = {
            'share_name': share_name,
            'accessible': False,
            'error': None
        }
        
        try:
            # Use smbclient to test if we can list the share contents
            cmd = ["smbclient", f"//{ip}/{share_name}"]
            
            # Add authentication based on credentials
            if username == "" and password == "":
                cmd.append("-N")  # No password (anonymous)
            elif username == "guest":
                if password == "":
                    cmd.extend(["--user", "guest%"])
                else:
                    cmd.extend(["--user", f"guest%{password}"])
            else:
                cmd.extend(["--user", f"{username}%{password}"])
            
            # Add command to list directory (test read access)
            cmd.extend(["-c", "ls"])
            
            if True:  # verbose check handled by output methods
                self.output.print_if_verbose(f"Testing access: {' '.join(cmd)}")
            
            # Run command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Check if listing was successful
            if result.returncode == 0:
                # Additional check: ensure we got actual file listing output
                if "NT_STATUS" not in result.stderr and len(result.stdout.strip()) > 0:
                    access_result['accessible'] = True
                    if True:  # verbose check handled by output methods
                        self.output.success(f"Share '{share_name}' is accessible")
                else:
                    access_result['error'] = f"Access denied or empty share"
                    if True:  # verbose check handled by output methods
                        self.output.print_if_verbose(f"Share '{share_name}' - no readable content")
            else:
                # Format error using new helper
                friendly_msg, raw_context = self._format_smbclient_error(result)
                access_result['error'] = friendly_msg

                if True:  # verbose check handled by output methods
                    # Include raw context in brackets if it differs from the friendly message
                    if raw_context and raw_context != friendly_msg:
                        self.output.error(f"Share '{share_name}' - {friendly_msg} [{raw_context}]")
                    else:
                        self.output.error(f"Share '{share_name}' - {friendly_msg}")
                
        except subprocess.TimeoutExpired:
            access_result['error'] = "Connection timeout"
            if True:  # verbose check handled by output methods
                self.output.error(f"Share '{share_name}' - timeout")
        except Exception as e:
            access_result['error'] = f"Test error: {str(e)}"
            if True:  # verbose check handled by output methods
                self.output.error(f"Share '{share_name}' - test error")
        
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
        stderr_trimmed = result.stderr.strip() if result.stderr else ""
        stdout_trimmed = result.stdout.strip() if result.stdout else ""

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

        if nt_status_match:
            status_code = nt_status_match.group(1)
            hint = self.SMB_STATUS_HINTS.get(status_code, "SMB protocol error")

            # Find context around the status code (up to 80 chars before/after)
            start_pos = max(0, nt_status_match.start() - 80)
            end_pos = min(len(combined_output), nt_status_match.end() + 80)
            context = combined_output[start_pos:end_pos]

            # Trim to ~160 chars total if needed
            if len(context) > 160:
                context = context[:157] + "..."

            friendly_msg = f"{hint} ({status_code}) - {context}"
            return (friendly_msg, combined_output)
        else:
            # No NT_STATUS found, provide generic error with trimmed output
            trimmed_output = combined_output[:160] + "..." if len(combined_output) > 160 else combined_output
            return (f"smbclient error: {trimmed_output}", combined_output)

    def process_target(self, host_record):
        """Process a single host target for share access testing."""
        ip = host_record['ip_address']
        country = host_record.get('country', 'Unknown')
        auth_method = host_record['auth_method']
        
        self.current_target += 1
        self.output.info(f"[{self.current_target}/{self.total_targets}] Testing {ip} ({country})...")
        
        # Parse authentication method
        username, password = self.parse_auth_method(auth_method)
        if True:  # verbose check handled by output methods
            self.output.info(f"Using auth: {username}/{password if password else '[blank]'}")
        
        # Create result structure
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
            # First check if port 445 is still open
            port_timeout = self.config.get_connection_timeout()
            if not self.check_port(ip, 445, port_timeout):
                self.output.error(f"Port 445 not accessible on {ip}")
                target_result['error'] = 'Port 445 not accessible'
                return target_result
            
            # Enumerate shares fresh
            shares = self.enumerate_shares(ip, username, password)
            target_result['shares_found'] = shares
            
            if not shares:
                self.output.warning(f"No non-administrative shares found on {ip}")
                return target_result
            
            self.output.success(f"Found {len(shares)} shares to test on {ip}")
            
            # Test access to each share
            for i, share_name in enumerate(shares, 1):
                access_result = self.test_share_access(ip, share_name, username, password)
                target_result['share_details'].append(access_result)
                
                if access_result['accessible']:
                    target_result['accessible_shares'].append(share_name)
                    self.output.success(f"Share {i}/{len(shares)}: {share_name} - accessible")
                else:
                    self.output.error(f"Share {i}/{len(shares)}: {share_name} - {access_result.get('error', 'not accessible')}")
                
                # Rate limiting between share tests
                if share_name != shares[-1]:  # Don't delay after the last share
                    delay = self.config.get_share_access_delay()
                    time.sleep(delay)
            
            # Validate results before summary output
            accessible_count = len(target_result['accessible_shares'])
            total_count = len(shares)
            
            # Critical validation: accessible shares should never exceed total shares
            if accessible_count > total_count:
                self.output.error(f"VALIDATION ERROR: {accessible_count} accessible > {total_count} total shares on {ip}")
                self.output.error(f"Found shares: {shares}")
                self.output.error(f"Accessible shares: {target_result['accessible_shares']}")
                # Flag this result as having an error to prevent database storage
                target_result['validation_error'] = f"Accessible count ({accessible_count}) exceeds total count ({total_count})"
            
            # Check for duplicate shares in accessible list
            if len(set(target_result['accessible_shares'])) != len(target_result['accessible_shares']):
                duplicates = [x for x in target_result['accessible_shares'] if target_result['accessible_shares'].count(x) > 1]
                self.output.warning(f"VALIDATION WARNING: Duplicate shares in accessible list: {set(duplicates)}")
                target_result['validation_warning'] = f"Duplicate accessible shares: {set(duplicates)}"
            
            # Verify all accessible shares are in the original shares list
            invalid_shares = [share for share in target_result['accessible_shares'] if share not in shares]
            if invalid_shares:
                self.output.error(f"VALIDATION ERROR: Accessible shares not in original list: {invalid_shares}")
                target_result['validation_error'] = f"Invalid accessible shares: {invalid_shares}"
            
            # Summary output
            if accessible_count > 0:
                self.output.success(f"{accessible_count}/{total_count} shares accessible on {ip}: {', '.join(target_result['accessible_shares'])}")
            else:
                self.output.warning(f"0/{total_count} shares accessible on {ip}")
                
        except Exception as e:
            self.output.error(f"Error testing target {ip}: {str(e)[:50]}")
            target_result['error'] = str(e)
        
        return target_result

    def _save_and_summarize_results(self):
        """
        Save results to database using session_id and compute summary statistics.

        Returns:
            Tuple of (accessible_hosts, accessible_shares, share_details)
        """
        try:
            # Save results to database using the workflow's session_id
            from db_manager import SMBSeekDataAccessLayer
            dal = SMBSeekDataAccessLayer(self.database.db_manager)

            stored_count = 0
            accessible_hosts = set()
            total_accessible_shares = 0
            share_details = []

            for result in self.results:
                # Skip results with errors
                if 'error' in result or 'validation_error' in result:
                    continue

                ip_address = result.get('ip_address')
                if not ip_address:
                    continue

                # Store share access results using the session_id
                accessible_shares = result.get('accessible_shares', [])
                if accessible_shares:
                    accessible_hosts.add(ip_address)
                    total_accessible_shares += len(accessible_shares)

                    # Store each accessible share in database
                    for share_name in accessible_shares:
                        share_record = {
                            'ip_address': ip_address,
                            'share_name': share_name,
                            'accessible': True,
                            'session_id': self.session_id
                        }
                        # Store in database
                        if self.database.store_share_access_result(self.session_id, share_record):
                            stored_count += 1

                        # Add to details list
                        share_details.append({
                            'ip_address': ip_address,
                            'share_name': share_name,
                            'accessible': True
                        })

            self.output.print_if_verbose(f"Stored {stored_count} share access results to database")

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