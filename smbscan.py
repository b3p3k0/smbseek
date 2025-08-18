#!/usr/bin/env python3
"""
SMB Scanner Tool
Scans for SMB servers with weak authentication using Shodan API
"""

import shodan
import csv
import time
import sys
import argparse
import uuid
import re
import os
import threading
from datetime import datetime
from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBException
import socket
import spnego
from contextlib import redirect_stderr
from io import StringIO

# Configuration
SHODAN_API_KEY = "***REVOKED_API_KEY***"  # API key for testing
CONNECTION_TIMEOUT = 30  # seconds
PORT_CHECK_TIMEOUT = 10  # seconds for port check
RATE_LIMIT_DELAY = 3  # seconds between connection attempts
DEFAULT_EXCLUSION_FILE = "exclusion_list.txt"

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

# Default target countries (country codes for Shodan)
DEFAULT_COUNTRIES = {
    'US': 'United States',
    'GB': 'United Kingdom',
    'CA': 'Canada',
    'IE': 'Ireland',
    'AU': 'Australia',
    'NZ': 'New Zealand',
    'ZA': 'South Africa'
}

class SMBScanner:
    def __init__(self, api_key, quiet=False, verbose=False, output_file=None, exclusion_file=None, additional_excludes=None, no_default_excludes=False, no_colors=False):
        """Initialize the SMB scanner with Shodan API key."""
        self.quiet = quiet
        self.verbose = verbose
        self.output_file = output_file or f"smb_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.exclusion_file = exclusion_file or DEFAULT_EXCLUSION_FILE
        self.additional_excludes = additional_excludes or []
        self.no_default_excludes = no_default_excludes
        self.no_colors = no_colors

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

        try:
            self.api = shodan.Shodan(api_key)
            # Test API key validity
            self.api.info()
            if not self.quiet:
                print("✓ Connected to Shodan API successfully")
        except shodan.APIError as e:
            print(f"✗ Shodan API Error: {str(e)}")
            if "Invalid API key" in str(e):
                print("Please check your API key in the configuration section.")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Unable to connect to Shodan: Network connection failed")
            sys.exit(1)

        self.successful_connections = []
        self.total_targets = 0
        self.current_target = 0

        # Load organization exclusions
        self.excluded_orgs = self.load_exclusions()

    def print_if_not_quiet(self, message):
        """Print message only if not in quiet mode."""
        if not self.quiet:
            print(message)
    
    def print_if_verbose(self, message):
        """Print message only if in verbose mode and not quiet."""
        if self.verbose and not self.quiet:
            print(message)

    def load_exclusions(self):
        """Load organization exclusions from file."""
        excluded_orgs = []

        # Skip loading default exclusions if requested
        if not self.no_default_excludes:
            if os.path.exists(self.exclusion_file):
                try:
                    with open(self.exclusion_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            # Skip empty lines and comments
                            if line and not line.startswith('#'):
                                excluded_orgs.append(line)
                    self.print_if_not_quiet(f"✓ Loaded {len(excluded_orgs)} organization exclusions from {self.exclusion_file}")
                except Exception as e:
                    print(f"✗ Warning: Could not load exclusion file {self.exclusion_file}: {e}")
            else:
                print(f"✗ Warning: Exclusion file {self.exclusion_file} not found. No organizations will be excluded.")

        # Add additional exclusions from command line
        if self.additional_excludes:
            excluded_orgs.extend(self.additional_excludes)
            self.print_if_not_quiet(f"✓ Added {len(self.additional_excludes)} additional exclusions from command line")

        return excluded_orgs

    def build_search_query(self, countries):
        """Build the search query with all filters and exclusions."""
        # Base query components
        base_query = 'smb authentication: disabled'

        # Countries - comma-separated format (only if countries list is not empty)
        query_parts = [base_query]

        if countries:
            country_codes = ','.join(countries)
            country_filter = f'country:{country_codes}'
            query_parts.append(country_filter)

        # Product filter
        product_filter = 'product:"Samba"'
        query_parts.append(product_filter)

        # Organization exclusions
        org_exclusions = []
        for org in self.excluded_orgs:
            # Escape quotes if they exist in org name
            escaped_org = org.replace('"', '\\"')
            org_exclusions.append(f'-org:"{escaped_org}"')

        # Other exclusions
        other_exclusions = ['-"DSL"']

        # Combine all parts
        query_parts.extend(org_exclusions)
        query_parts.extend(other_exclusions)

        final_query = ' '.join(query_parts)
        self.print_if_not_quiet(f"Search query: {final_query}")

        return final_query

    def search_smb_servers(self, countries, country_names_map):
        """Search for SMB servers in specified countries."""
        query = self.build_search_query(countries)

        try:
            if countries:
                country_names = [country_names_map.get(c, c) for c in countries]
                self.print_if_not_quiet(f"Searching for SMB servers in: {', '.join(country_names)}")
            else:
                self.print_if_not_quiet("Searching for SMB servers globally (no country filter)")

            results = self.api.search(query)

            servers = [(result['ip_str'], result.get('location', {}).get('country_code', 'Unknown')) for result in results['matches']]
            self.print_if_not_quiet(f"Found {len(servers)} SMB servers")

            return servers
        except shodan.APIError as e:
            if "upgrade your API plan" in str(e).lower():
                print(f"✗ API limit reached. You've used all available query credits for this month.")
            else:
                print(f"✗ Search failed: {str(e)}")
            return []
        except Exception as e:
            print(f"✗ Network error while searching")
            return []

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

    def test_smb_connection(self, ip, auth_methods):
        """Test SMB connection with different authentication methods."""

        for method_name, username, password in auth_methods:
            connection = None
            session = None

            self.print_if_verbose(f"    {self.CYAN}Testing {method_name}...{self.RESET}")

            # Suppress stderr output from SMB libraries
            stderr_buffer = StringIO()
            try:
                with redirect_stderr(stderr_buffer):
                    # Create unique connection ID
                    conn_uuid = uuid.uuid4()

                    # Create connection with less strict requirements
                    connection = Connection(conn_uuid, ip, 445, require_signing=False)
                    connection.connect(timeout=CONNECTION_TIMEOUT)

                    # Create session with appropriate auth
                    # For anonymous, use empty strings
                    # For guest, use NTLM with guest account
                    if username == "" and password == "":
                        # Anonymous connection
                        session = Session(connection, username="", password="", require_encryption=False)
                    else:
                        # Guest connection - use NTLM auth
                        session = Session(connection, username=username, password=password,
                                        require_encryption=False, auth_protocol="ntlm")

                    session.connect()

                # If we get here, authentication succeeded
                # Clean disconnect
                try:
                    with redirect_stderr(stderr_buffer):
                        session.disconnect()
                except:
                    pass
                try:
                    with redirect_stderr(stderr_buffer):
                        connection.disconnect()
                except:
                    pass

                return method_name

            except spnego.exceptions.SpnegoError as e:
                # SPNEGO/Auth negotiation failed - don't print detailed error
                pass
            except SMBException as e:
                # SMB-specific error - don't print detailed error
                pass
            except (socket.error, socket.timeout) as e:
                # Network error - don't print detailed error
                pass
            except Exception as e:
                # Catch any other unexpected exceptions - don't print detailed error
                pass
            finally:
                # Ensure cleanup with stderr suppression
                if session:
                    try:
                        with redirect_stderr(stderr_buffer):
                            session.disconnect()
                    except:
                        pass
                if connection:
                    try:
                        with redirect_stderr(stderr_buffer):
                            connection.disconnect(close=False)
                    except:
                        pass

        return None

    def test_smb_alternative(self, ip):
        """Alternative testing method using minimal SMB connection."""
        import subprocess

        # Try using smbclient as a fallback to verify connectivity
        test_commands = [
            ("Anonymous", ["smbclient", "-L", f"//{ip}", "-N"]),
            ("Guest/Blank", ["smbclient", "-L", f"//{ip}", "--user", "guest%"]),
            ("Guest/Guest", ["smbclient", "-L", f"//{ip}", "--user", "guest%guest"])
        ]

        stderr_buffer = StringIO()
        for method_name, cmd in test_commands:
            try:
                # Suppress both stdout and stderr from smbclient
                with redirect_stderr(stderr_buffer):
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, stderr=subprocess.DEVNULL)
                    if result.returncode == 0 or "Sharename" in result.stdout:
                        return method_name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except Exception:
                continue

        return None

    def scan_target(self, ip, country_code, country_names_map):
        """Scan a single target with multiple authentication methods."""
        # Authentication methods to try
        auth_methods = [
            ("Anonymous", "", ""),
            ("Guest/Blank", "guest", ""),
            ("Guest/Guest", "guest", "guest")
        ]

        self.current_target += 1
        country_name = country_names_map.get(country_code, country_code)
        self.print_if_not_quiet(f"[{self.current_target}/{self.total_targets}] Testing {self.YELLOW}{ip}{self.RESET} ({country_name})...")

        try:
            # First check if port 445 is open
            if not self.check_port(ip, 445, PORT_CHECK_TIMEOUT):
                self.print_if_not_quiet(f"  {self.RED}✗ Port 445 not accessible{self.RESET}")
                return

            # Test with smbprotocol library
            successful_method = self.test_smb_connection(ip, auth_methods)

            # If smbprotocol fails, try smbclient as fallback
            if not successful_method:
                self.print_if_verbose(f"    {self.CYAN}Trying smbclient fallback...{self.RESET}")
                successful_method = self.test_smb_alternative(ip)
                if successful_method:
                    successful_method = f"{successful_method} (smbclient)"

            if successful_method:
                self.print_if_not_quiet(f"  {self.GREEN}✓ Success! Authentication: {successful_method}{self.RESET}")
                self.successful_connections.append({
                    'ip': ip,
                    'country': country_name,
                    'auth_method': successful_method,
                    'timestamp': datetime.now().isoformat()
                })
            else:
                self.print_if_not_quiet(f"  {self.RED}✗ All authentication methods failed{self.RESET}")

        except KeyboardInterrupt:
            raise  # Re-raise to allow script interruption
        except Exception as e:
            self.print_if_not_quiet(f"  {self.RED}✗ Unexpected error during scan: {str(e)[:50]}{self.RESET}")

    def save_results(self):
        """Save successful connections to CSV file."""
        if not self.successful_connections:
            self.print_if_not_quiet("No successful connections found.")
            return

        try:
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['ip_address', 'country', 'auth_method']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for conn in self.successful_connections:
                    writer.writerow({
                        'ip_address': conn['ip'],
                        'country': conn['country'],
                        'auth_method': conn['auth_method']
                    })

            self.print_if_not_quiet(f"✓ Results saved to {self.output_file}")
            self.print_if_not_quiet(f"✓ Total successful connections: {len(self.successful_connections)}")

        except Exception as e:
            print(f"✗ Failed to save results: Unable to write to file")

    def run_scan(self, countries=None, country_names_map=None):
        """Run the complete SMB scanning process."""
        if countries is None:
            countries = list(DEFAULT_COUNTRIES.keys())
        if country_names_map is None:
            country_names_map = DEFAULT_COUNTRIES

        self.print_if_not_quiet("Starting SMB Scanner...")
        self.print_if_not_quiet("=" * 50)

        # Search all countries at once with the new query format
        all_targets = self.search_smb_servers(countries, country_names_map)

        if not all_targets:
            self.print_if_not_quiet("No SMB servers found matching search criteria.")
            return

        self.total_targets = len(all_targets)
        self.print_if_not_quiet(f"\nTotal targets to scan: {self.total_targets}")
        self.print_if_not_quiet("Starting connection tests...\n")

        # Scan each target
        for ip, country_code in all_targets:
            self.scan_target(ip, country_code, country_names_map)

            # Rate limiting - wait between connection attempts to different servers
            if self.current_target < self.total_targets:
                time.sleep(RATE_LIMIT_DELAY)

        self.print_if_not_quiet("\n" + "=" * 50)
        self.print_if_not_quiet("Scan completed!")
        self.save_results()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SMB Scanner Tool - Scans for SMB servers with weak authentication using Shodan API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python smb_scanner.py                    # Scan all default countries
  python smb_scanner.py -c US              # Scan only United States
  python smb_scanner.py -a FR,DE           # Scan defaults plus France and Germany
  python smb_scanner.py -t                 # Scan globally (no country filter)
  python smb_scanner.py -q -o results.csv  # Quiet mode with custom output file
  python smb_scanner.py -c GB -q           # Scan UK in quiet mode
  python smb_scanner.py -v                 # Enable verbose authentication testing output
  python smb_scanner.py -x                 # Disable colored output
  python smb_scanner.py --exclude-file custom_exclusions.txt  # Use custom exclusion file
  python smb_scanner.py --additional-excludes "My ISP,Another Org"  # Add more exclusions
  python smb_scanner.py --no-default-excludes  # Skip default exclusions

Default country codes:
  US - United States    GB - United Kingdom  CA - Canada
  IE - Ireland          AU - Australia       NZ - New Zealand
  ZA - South Africa

Connection behavior:
  - Tests port 445 (SMB)
  - Tests three auth methods: Anonymous, Guest/Blank, Guest/Guest
  - Falls back to smbclient if smbprotocol fails

Organization Exclusions:
  By default, the tool excludes known ISPs, hosting providers, and cloud services
  from the scan. See exclusion_list.txt for the complete list.
        """
    )

    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Suppress output to screen (useful for scripting)')

    parser.add_argument('-c', '--country',
                       type=str,
                       metavar='CODE',
                       help='Search only the specified country using two-letter country code')

    parser.add_argument('-a', '--additional-country',
                       type=str,
                       metavar='CODES',
                       help='Comma-separated list of additional country codes to scan (e.g., FR,DE,IT)')

    parser.add_argument('-t', '--terra',
                       action='store_true',
                       help='Search globally without country filters (terra = Earth)')

    parser.add_argument('-v', '--vox',
                       action='store_true',
                       help='Enable verbose output showing detailed authentication testing steps')

    parser.add_argument('-x', '--nyx',
                       action='store_true',
                       help='Disable colored output (nyx = darkness/no colors)')

    parser.add_argument('-o', '--output',
                       type=str,
                       metavar='FILE',
                       help='Specify output CSV file (default: smb_scan_results_YYYYMMDD_HHMMSS.csv)')

    parser.add_argument('--exclude-file',
                       type=str,
                       metavar='FILE',
                       help=f'Load organization exclusions from file (default: {DEFAULT_EXCLUSION_FILE})')

    parser.add_argument('--additional-excludes',
                       type=str,
                       metavar='ORGS',
                       help='Comma-separated list of additional organizations to exclude')

    parser.add_argument('--no-default-excludes',
                       action='store_true',
                       help='Skip loading default organization exclusions')

    return parser.parse_args()

def main():
    """Main function."""

    # Suppress thread exception output from smbprotocol library
    def thread_exception_handler(args):
        # Silently ignore thread exceptions from smbprotocol
        pass

    threading.excepthook = thread_exception_handler

    args = parse_arguments()

    if not args.quiet:
        print("SMB Scanner Tool")
        print("Scanning for SMB servers with weak authentication")

    # Determine target countries
    countries = []
    country_names_map = DEFAULT_COUNTRIES.copy()

    if args.terra:
        # Global search - no country filter
        countries = []
        if not args.quiet:
            print("Target: Global (no country filter)")
    elif args.country:
        # Single country specified
        country_code = args.country.upper()
        countries = [country_code]
        if country_code not in DEFAULT_COUNTRIES:
            # Add custom country to the map
            country_names_map[country_code] = country_code
        if not args.quiet:
            print(f"Target country: {country_names_map.get(country_code, country_code)}")
    else:
        # Use default countries
        countries = list(DEFAULT_COUNTRIES.keys())

    # Add additional countries if specified
    if args.additional_country and not args.terra:
        additional_codes = [code.strip().upper() for code in args.additional_country.split(',')]
        for code in additional_codes:
            if len(code) == 2:  # Basic validation for 2-letter country codes
                if code not in countries:
                    countries.append(code)
                if code not in country_names_map:
                    country_names_map[code] = code
            else:
                print(f"✗ Warning: Invalid country code '{code}' - must be 2 letters")

        if not args.quiet and not args.country:
            country_names = [country_names_map.get(c, c) for c in countries]
            print("Target countries: " + ", ".join(country_names))

    # Parse additional exclusions if provided
    additional_excludes = []
    if args.additional_excludes:
        additional_excludes = [org.strip() for org in args.additional_excludes.split(',')]

    if not args.quiet:
        print()

    # Check if API key is configured
    if SHODAN_API_KEY == "YOUR_API_KEY_HERE":
        print("✗ Please configure your Shodan API key in the SHODAN_API_KEY variable")
        sys.exit(1)

    try:
        scanner = SMBScanner(
            SHODAN_API_KEY,
            quiet=args.quiet,
            verbose=args.vox,
            output_file=args.output,
            exclusion_file=args.exclude_file,
            additional_excludes=additional_excludes,
            no_default_excludes=args.no_default_excludes,
            no_colors=args.nyx
        )
        scanner.run_scan(countries=countries, country_names_map=country_names_map)
    except KeyboardInterrupt:
        print("\n\n✗ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: The program encountered an unexpected problem")
        sys.exit(1)

if __name__ == "__main__":
    main()
