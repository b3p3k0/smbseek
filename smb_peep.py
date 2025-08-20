#!/usr/bin/env python3
"""
SMB Peep - Share Access Verification Tool
Tests read accessibility of SMB shares from successfully authenticated servers
"""

import csv
import json
import time
import sys
import argparse
import uuid
import os
import subprocess
from datetime import datetime
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateDisposition, ImpersonationLevel, FileAttributes, ShareAccess
from smbprotocol.exceptions import SMBException
import socket
from contextlib import redirect_stderr
from io import StringIO

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

def load_configuration(config_file="config.json"):
    """Load configuration from JSON file with fallback to defaults."""
    default_config = {
        "shodan": {
            "api_key": "YOUR_API_KEY_HERE"
        },
        "connection": {
            "timeout": 30,
            "port_check_timeout": 10,
            "rate_limit_delay": 3,
            "share_access_delay": 7
        },
        "files": {
            "default_exclusion_file": "exclusion_list.txt"
        },
        "countries": {
            "US": "United States",
            "GB": "United Kingdom", 
            "CA": "Canada",
            "IE": "Ireland",
            "AU": "Australia",
            "NZ": "New Zealand",
            "ZA": "South Africa"
        }
    }
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validate required sections exist
        required_sections = ["shodan", "connection", "files", "countries"]
        for section in required_sections:
            if section not in config:
                print(f"✗ Warning: Missing '{section}' section in {config_file}, using defaults")
                config[section] = default_config[section]
        
        # Ensure share_access_delay exists
        if "share_access_delay" not in config["connection"]:
            config["connection"]["share_access_delay"] = 7
                
        return config
        
    except FileNotFoundError:
        print(f"✗ Configuration file {config_file} not found, using defaults")
        return default_config
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON in {config_file}: {e}")
        print("✗ Using default configuration")
        return default_config
    except Exception as e:
        print(f"✗ Error loading configuration: {e}")
        print("✗ Using default configuration")  
        return default_config

class SMBPeep:
    def __init__(self, config, quiet=False, verbose=False, output_file=None, no_colors=False):
        """Initialize the SMB Peep tool."""
        self.config = config
        self.quiet = quiet
        self.verbose = verbose
        self.no_colors = no_colors
        self.output_file = output_file or f"share_access_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Set up colors based on no_colors flag
        if self.no_colors:
            self.GREEN = ''
            self.RED = ''
            self.YELLOW = ''
            self.CYAN = ''
            self.RESET = ''
        else:
            self.GREEN = GREEN
            self.RED = RED
            self.YELLOW = YELLOW
            self.CYAN = CYAN
            self.RESET = RESET

        # Check smbclient availability for share enumeration
        self.smbclient_available = self.check_smbclient_availability()
        if not self.smbclient_available and not self.quiet:
            print(f"{self.YELLOW}⚠ smbclient unavailable; share enumeration will be limited.{self.RESET}")
        
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

    def print_if_not_quiet(self, message):
        """Print message only if not in quiet mode."""
        if not self.quiet:
            print(message)
    
    def print_if_verbose(self, message):
        """Print message only if in verbose mode and not quiet."""
        if self.verbose and not self.quiet:
            print(message)

    def load_ip_records(self, csv_file):
        """Load successful IP records from CSV file."""
        ip_records = []
        try:
            with open(csv_file, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    ip_records.append({
                        'ip_address': row.get('ip_address'),
                        'country': row.get('country', 'Unknown'),
                        'auth_method': row.get('auth_method', 'Unknown'),
                        'shares': row.get('shares', ''),
                        'timestamp': row.get('timestamp', '')
                    })
        except Exception as e:
            print(f"✗ Error reading CSV file: {e}")
            raise
        return ip_records

    def parse_auth_method(self, auth_method_str):
        """Parse authentication method string to extract credentials."""
        # Handle different auth method formats from smb_scan.py
        auth_lower = auth_method_str.lower()
        
        if 'anonymous' in auth_lower:
            return "", ""
        elif 'guest/blank' in auth_lower:
            return "guest", ""
        elif 'guest/guest' in auth_lower:
            return "guest", "guest"
        else:
            # Default fallback
            self.print_if_verbose(f"  {self.YELLOW}Unknown auth method '{auth_method_str}', defaulting to guest/guest{self.RESET}")
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
            
            self.print_if_verbose(f"    {self.CYAN}Enumerating shares: {' '.join(cmd)}{self.RESET}")
            
            # Run command with timeout, prevent password prompts
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Parse shares from output
            if result.returncode == 0 or "Sharename" in result.stdout:
                shares = self.parse_share_list(result.stdout)
                self.print_if_verbose(f"    {self.CYAN}Found {len(shares)} non-admin shares{self.RESET}")
                return shares
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.print_if_verbose(f"    {self.YELLOW}Share enumeration failed: {str(e)}{self.RESET}")
        
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
            
            self.print_if_verbose(f"      {self.CYAN}Testing access: {' '.join(cmd)}{self.RESET}")
            
            # Run command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Check if listing was successful
            if result.returncode == 0:
                # Additional check: ensure we got actual file listing output
                if "NT_STATUS" not in result.stderr and len(result.stdout.strip()) > 0:
                    access_result['accessible'] = True
                    self.print_if_verbose(f"      {self.GREEN}✓ Share '{share_name}' is accessible{self.RESET}")
                else:
                    access_result['error'] = f"Access denied or empty share"
                    self.print_if_verbose(f"      {self.YELLOW}⚠ Share '{share_name}' - no readable content{self.RESET}")
            else:
                # Parse error from stderr
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                if "NT_STATUS_ACCESS_DENIED" in error_msg:
                    access_result['error'] = "Access denied"
                elif "NT_STATUS_BAD_NETWORK_NAME" in error_msg:
                    access_result['error'] = "Share not found"
                else:
                    access_result['error'] = f"smbclient error: {error_msg[:50]}"
                
                self.print_if_verbose(f"      {self.RED}✗ Share '{share_name}' - {access_result['error']}{self.RESET}")
                
        except subprocess.TimeoutExpired:
            access_result['error'] = "Connection timeout"
            self.print_if_verbose(f"      {self.RED}✗ Share '{share_name}' - timeout{self.RESET}")
        except Exception as e:
            access_result['error'] = f"Test error: {str(e)}"
            self.print_if_verbose(f"      {self.RED}✗ Share '{share_name}' - test error{self.RESET}")
        
        return access_result

    def process_target(self, ip_record):
        """Process a single IP target for share access testing."""
        ip = ip_record['ip_address']
        country = ip_record['country']
        auth_method = ip_record['auth_method']
        
        self.current_target += 1
        self.print_if_not_quiet(f"[{self.current_target}/{self.total_targets}] Testing {self.YELLOW}{ip}{self.RESET} ({country})...")
        
        # Parse authentication method
        username, password = self.parse_auth_method(auth_method)
        self.print_if_verbose(f"  {self.CYAN}Using auth: {username}/{password if password else '[blank]'}{self.RESET}")
        
        # Create result structure
        target_result = {
            'ip_address': ip,
            'country': country,
            'auth_method': auth_method,
            'timestamp': datetime.now().isoformat(),
            'shares_found': [],
            'accessible_shares': [],
            'share_details': []
        }
        
        try:
            # First check if port 445 is still open
            self.print_if_not_quiet(f"  ⏳ Checking port 445...", end='', flush=True)
            if not self.check_port(ip, 445, self.config["connection"]["port_check_timeout"]):
                print(f"\r  {self.RED}✗ Port 445 not accessible{self.RESET}")
                target_result['error'] = 'Port 445 not accessible'
                return target_result
            print(f"\r  {self.GREEN}✓ Port 445 open{self.RESET}")
            
            # Enumerate shares fresh
            self.print_if_not_quiet(f"  ⏳ Enumerating shares...", end='', flush=True)
            shares = self.enumerate_shares(ip, username, password)
            target_result['shares_found'] = shares
            
            if not shares:
                print(f"\r  {self.YELLOW}⚠ No non-administrative shares found{self.RESET}")
                return target_result
            
            print(f"\r  {self.GREEN}✓ Found {len(shares)} shares to test{self.RESET}")
            
            # Test access to each share
            for i, share_name in enumerate(shares, 1):
                self.print_if_not_quiet(f"  ⏳ Testing share {i}/{len(shares)}: {share_name}...", end='', flush=True)
                
                access_result = self.test_share_access(ip, share_name, username, password)
                target_result['share_details'].append(access_result)
                
                if access_result['accessible']:
                    target_result['accessible_shares'].append(share_name)
                    print(f"\r  {self.GREEN}✓ Share {i}/{len(shares)}: {share_name} - accessible{self.RESET}")
                else:
                    print(f"\r  {self.RED}✗ Share {i}/{len(shares)}: {share_name} - {access_result.get('error', 'not accessible')}{self.RESET}")
                
                # Rate limiting between share tests
                if share_name != shares[-1]:  # Don't delay after the last share
                    time.sleep(self.config["connection"]["share_access_delay"])
            
            # Summary output
            accessible_count = len(target_result['accessible_shares'])
            total_count = len(shares)
            
            if accessible_count > 0:
                self.print_if_not_quiet(f"  {self.GREEN}✓ {accessible_count}/{total_count} shares accessible: {', '.join(target_result['accessible_shares'])}{self.RESET}")
            else:
                self.print_if_not_quiet(f"  {self.RED}✗ 0/{total_count} shares accessible{self.RESET}")
                
        except Exception as e:
            self.print_if_not_quiet(f"  {self.RED}✗ Error testing target: {str(e)[:50]}{self.RESET}")
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

    def run_analysis(self, csv_file):
        """Main analysis function - processes IP records from CSV."""
        self.print_if_not_quiet("SMB Peep - Share Access Verification Tool")
        self.print_if_not_quiet("=" * 50)
        
        # Load IP records
        ip_records = self.load_ip_records(csv_file)
        self.total_targets = len(ip_records)
        
        if not ip_records:
            self.print_if_not_quiet("No IP records found in CSV file.")
            return
        
        self.print_if_not_quiet(f"Loaded {self.total_targets} IP records for share access testing\n")
        
        # Process each IP record
        for ip_record in ip_records:
            target_result = self.process_target(ip_record)
            self.results.append(target_result)
        
        # Save results
        self.save_results()
        
        # Summary
        self.print_summary()

    def save_results(self):
        """Save results to JSON file."""
        try:
            output_data = {
                'metadata': {
                    'tool': 'smb_peep',
                    'version': '1.0',
                    'scan_date': datetime.now().isoformat(),
                    'total_targets': self.total_targets,
                    'config': {
                        'share_access_delay': self.config["connection"]["share_access_delay"],
                        'timeout': self.config["connection"]["timeout"]
                    }
                },
                'results': self.results
            }
            
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.print_if_not_quiet(f"\n{self.GREEN}✓{self.RESET} Results saved to {self.output_file}")
            
        except Exception as e:
            print(f"✗ Failed to save results: {e}")

    def print_summary(self):
        """Print analysis summary."""
        if not self.results:
            return
        
        total_targets = len(self.results)
        targets_with_shares = len([r for r in self.results if r.get('shares_found')])
        targets_with_access = len([r for r in self.results if r.get('accessible_shares')])
        
        total_shares_found = sum(len(r.get('shares_found', [])) for r in self.results)
        total_accessible_shares = sum(len(r.get('accessible_shares', [])) for r in self.results)
        
        self.print_if_not_quiet(f"\n{self.CYAN}=== SUMMARY ==={self.RESET}")
        self.print_if_not_quiet(f"Total targets processed: {total_targets}")
        self.print_if_not_quiet(f"Targets with shares: {targets_with_shares}")
        self.print_if_not_quiet(f"Targets with accessible shares: {targets_with_access}")
        self.print_if_not_quiet(f"Total shares found: {total_shares_found}")
        self.print_if_not_quiet(f"Total accessible shares: {total_accessible_shares}")
        
        if total_shares_found > 0:
            access_rate = (total_accessible_shares / total_shares_found) * 100
            self.print_if_not_quiet(f"Share access rate: {access_rate:.1f}%")

def print_help():
    """Print comprehensive help information."""
    help_text = """
SMB Peep - Share Access Verification Tool

DESCRIPTION:
    Tests read accessibility of SMB shares from servers with successful authentication.
    Enumerates shares fresh and validates which shares allow read access using the
    original authentication method that succeeded during initial scanning.

USAGE:
    python3 smb_peep.py [ip_record.csv]
    python3 smb_peep.py --help | -h

ARGUMENTS:
    [ip_record.csv]        CSV file containing successful SMB connection records
                          Generated by: python3 smb_scan.py
                          If not specified, looks for "ip_record.csv" in current directory

OPTIONS:
    -h, --help            Show this help message and exit
    -q, --quiet           Suppress output to screen (useful for scripting)
    -v, --verbose         Enable verbose output showing detailed share testing
    -o, --output FILE     Specify output JSON file (default: timestamped)
    -x, --no-colors       Disable colored output

AUTHENTICATION:
    Uses the original authentication method from the CSV record for each IP:
    • Anonymous: Empty username and password
    • Guest/Blank: Username "guest" with empty password  
    • Guest/Guest: Username "guest" with password "guest"

SHARE TESTING:
    • Re-enumerates shares fresh (ignores CSV share data)
    • Tests only non-administrative shares (excludes shares ending with $)
    • Validates READ ACCESS ONLY - no write operations attempted
    • Uses SMB protocol to test actual share accessibility
    • Rate limited between share tests (configurable in config.json)

OUTPUT FORMAT:
    JSON file containing:
    • Metadata: tool info, scan date, configuration
    • Results: per-IP analysis with accessible shares and details
    
    Example structure:
    {
      "metadata": {...},
      "results": [
        {
          "ip_address": "192.168.1.100",
          "accessible_shares": ["Documents", "Public"],
          "share_details": [...]
        }
      ]
    }

CONFIGURATION:
    Uses same config.json as other SMBSeek tools.
    New setting: connection.share_access_delay (default: 7 seconds)

PREREQUISITES:
    Python Dependencies:
        pip install smbprotocol pyspnego

    System Requirements:
        smbclient (recommended for share enumeration)

INTEGRATION WORKFLOW:
    1. Run SMBSeek to discover vulnerable servers:
       python3 smb_scan.py -c US

    2. Test share accessibility:
       python3 smb_peep.py ip_record.csv

    3. Analyze JSON results for accessible shares

EXAMPLES:
    # Basic share access testing
    python3 smb_peep.py ip_record.csv

    # Quiet mode with custom output
    python3 smb_peep.py -q -o share_analysis.json ip_record.csv

    # Verbose testing with detailed output
    python3 smb_peep.py -v ip_record.csv

    # Show help information
    python3 smb_peep.py --help

SECURITY CONSIDERATIONS:
    • READ ONLY: No write operations are ever attempted
    • Uses original authentication methods only
    • Respects rate limits to avoid aggressive testing
    • Designed for authorized security testing only

    Ensure you have proper authorization before testing any network targets.
    Use findings responsibly for defensive security improvements only.

For more information, see the SMBSeek README.md documentation.
"""
    print(help_text)

def main():
    """Main function for standalone execution."""
    parser = argparse.ArgumentParser(
        description='SMB Peep - Share Access Verification Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False  # We'll handle help manually
    )
    
    parser.add_argument('csv_file', nargs='?', help='CSV file containing IP records')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output to screen')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-o', '--output', type=str, metavar='FILE', help='Specify output JSON file')
    parser.add_argument('-x', '--no-colors', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.help:
        print_help()
        sys.exit(0)
    
    # Check for default input file if none specified
    if not args.csv_file:
        default_file = "ip_record.csv"
        if os.path.exists(default_file):
            args.csv_file = default_file
            print(f"ℹ Using default input file: {default_file}")
        else:
            print(f"✗ No input file specified and default file '{default_file}' not found")
            print("  Use: python3 smb_peep.py <ip_record.csv>")
            print("  Or:  python3 smb_peep.py --help")
            sys.exit(1)
    
    if args.quiet and args.verbose:
        print("Warning: Cannot use both --quiet and --verbose. Using quiet mode.")
        args.verbose = False
    
    try:
        config = load_configuration()
        peep = SMBPeep(
            config=config,
            quiet=args.quiet,
            verbose=args.verbose,
            output_file=args.output,
            no_colors=args.no_colors
        )
        peep.run_analysis(args.csv_file)
        
    except KeyboardInterrupt:
        print("\n\n✗ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()