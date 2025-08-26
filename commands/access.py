"""
SMBSeek Access Command

Share access verification functionality adapted for the unified CLI.
Tests access to SMB shares on authenticated servers.
"""

import subprocess
import csv
import json
import time
import sys
import os
import socket
from datetime import datetime
from pathlib import Path
from contextlib import redirect_stderr
from io import StringIO

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


class AccessCommand:
    """
    SMB share access verification command.
    
    Tests access to SMB shares on previously authenticated servers.
    """
    
    def __init__(self, args):
        """
        Initialize access command.
        
        Args:
            args: Parsed command line arguments
        """
        self.args = args
        
        # Load configuration and components
        self.config = load_config(args.config)
        self.output = create_output_manager(
            self.config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )
        self.database = create_workflow_database(self.config, args.verbose)
        
        # Check smbclient availability for share enumeration
        self.smbclient_available = self.check_smbclient_availability()
        if not self.smbclient_available and not args.quiet:
            self.output.warning("smbclient unavailable; share enumeration will be limited.")
        
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
    
    def execute(self) -> int:
        """
        Execute the access command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            self.output.header("SMB Share Access Verification")
            
            if not SMB_AVAILABLE:
                self.output.error("SMB libraries not available. Install with: pip install smbprotocol pyspnego")
                return 1
            
            # Get authenticated hosts from database
            authenticated_hosts = self.database.get_authenticated_hosts()
            if not authenticated_hosts:
                self.output.warning("No authenticated hosts found in database")
                self.output.info("Run discovery first: smbseek discover --country US")
                return 0
            
            self.total_targets = len(authenticated_hosts)
            self.output.info(f"Testing share access on {self.total_targets} authenticated hosts")
            
            # Process each authenticated host
            for host in authenticated_hosts:
                target_result = self.process_target(host)
                self.results.append(target_result)
            
            # Save results and show summary
            self.save_results()
            self.print_summary()
            
            return 0
        
        except Exception as e:
            self.output.error(f"Access verification failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()
    
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
            if self.args.verbose:
                self.output.warning(f"Unknown auth method '{auth_method_str}', defaulting to guest/guest")
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
            
            if self.args.verbose:
                self.output.info(f"Enumerating shares: {' '.join(cmd)}")
            
            # Run command with timeout, prevent password prompts
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Parse shares from output
            if result.returncode == 0 or "Sharename" in result.stdout:
                shares = self.parse_share_list(result.stdout)
                if self.args.verbose:
                    self.output.info(f"Found {len(shares)} non-admin shares")
                return shares
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            if self.args.verbose:
                self.output.warning(f"Share enumeration failed: {str(e)}")
        
        return []
    
    def parse_share_list(self, smbclient_output):
        """Parse smbclient -L output to extract non-administrative share names."""
        shares = []
        lines = smbclient_output.split('\n')
        in_share_section = False
        
        for line in lines:
            line = line.strip()
            
            # Look for the start of the shares section
            if "Sharename" in line and "Type" in line:
                in_share_section = True
                continue
            
            # Stop when we hit the end of shares section
            if in_share_section and (line.startswith("Server") or line.startswith("Workgroup") or line == ""):
                if not line or line.startswith("-"):
                    continue
                if line.startswith("Server") or line.startswith("Workgroup"):
                    break
            
            # Parse share lines
            if in_share_section and line and not line.startswith("-"):
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    
                    # Only include non-administrative Disk shares
                    if not share_name.endswith('$') and share_type == "Disk":
                        shares.append(share_name)
        
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
            
            if self.args.verbose:
                self.output.info(f"Testing access: {' '.join(cmd)}")
            
            # Run command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Check if listing was successful
            if result.returncode == 0:
                # Additional check: ensure we got actual file listing output
                if "NT_STATUS" not in result.stderr and len(result.stdout.strip()) > 0:
                    access_result['accessible'] = True
                    if self.args.verbose:
                        self.output.success(f"Share '{share_name}' is accessible")
                else:
                    access_result['error'] = f"Access denied or empty share"
                    if self.args.verbose:
                        self.output.warning(f"Share '{share_name}' - no readable content")
            else:
                # Parse error from stderr
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                if "NT_STATUS_ACCESS_DENIED" in error_msg:
                    access_result['error'] = "Access denied"
                elif "NT_STATUS_BAD_NETWORK_NAME" in error_msg:
                    access_result['error'] = "Share not found"
                else:
                    access_result['error'] = f"smbclient error: {error_msg[:50]}"
                
                if self.args.verbose:
                    self.output.error(f"Share '{share_name}' - {access_result['error']}")
                
        except subprocess.TimeoutExpired:
            access_result['error'] = "Connection timeout"
            if self.args.verbose:
                self.output.error(f"Share '{share_name}' - timeout")
        except Exception as e:
            access_result['error'] = f"Test error: {str(e)}"
            if self.args.verbose:
                self.output.error(f"Share '{share_name}' - test error")
        
        return access_result
    
    def process_target(self, host_record):
        """Process a single host target for share access testing."""
        ip = host_record['ip_address']
        country = host_record.get('country', 'Unknown')
        auth_method = host_record['auth_method']
        
        self.current_target += 1
        self.output.info(f"[{self.current_target}/{self.total_targets}] Testing {ip} ({country})...")
        
        # Parse authentication method
        username, password = self.parse_auth_method(auth_method)
        if self.args.verbose:
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
            
            # Summary output
            accessible_count = len(target_result['accessible_shares'])
            total_count = len(shares)
            
            if accessible_count > 0:
                self.output.success(f"{accessible_count}/{total_count} shares accessible on {ip}: {', '.join(target_result['accessible_shares'])}")
            else:
                self.output.warning(f"0/{total_count} shares accessible on {ip}")
                
        except Exception as e:
            self.output.error(f"Error testing target {ip}: {str(e)[:50]}")
            target_result['error'] = str(e)
        
        return target_result
    
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
            # Save to database
            session_id = self.database.create_session('access')
            stored_count = 0
            for result in self.results:
                if 'error' not in result:
                    if self.database.store_share_access_result(session_id, result):
                        stored_count += 1
                    else:
                        if self.args.verbose:
                            self.output.warning(f"Failed to store results for {result.get('ip_address', 'unknown')}")
            
            if self.args.verbose:
                self.output.info(f"Stored {stored_count}/{len([r for r in self.results if 'error' not in r])} results to database")
            
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