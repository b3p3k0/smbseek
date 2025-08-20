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
import json
import subprocess
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
            "rate_limit_delay": 3
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

# Load configuration at module level
CONFIG = load_configuration()
DEFAULT_EXCLUSION_FILE = CONFIG["files"]["default_exclusion_file"]

class SMBScanner:
    def __init__(self, config, quiet=False, verbose=False, output_file=None, exclusion_file=None, additional_excludes=None, no_default_excludes=False, no_colors=False, new_file=False, record_name=None, log_failures=False):
        """Initialize the SMB scanner with configuration object."""
        self.config = config
        self.quiet = quiet
        self.verbose = verbose
        self.new_file = new_file
        self.record_name = record_name or "ip_record.csv"
        
        # Determine output file based on flags
        if output_file:
            self.output_file = output_file
            self.append_mode = False
        elif new_file:
            self.output_file = f"ip_record_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.append_mode = False
        else:
            self.output_file = self.record_name
            self.append_mode = True
            
        self.exclusion_file = exclusion_file or config["files"]["default_exclusion_file"]
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

        # Check smbclient availability for share enumeration
        self.smbclient_available = self.check_smbclient_availability()
        if not self.smbclient_available and not self.quiet:
            print(f"{self.YELLOW}⚠ smbclient unavailable; scan will continue with less features.{self.RESET}")

        try:
            self.api = shodan.Shodan(config["shodan"]["api_key"])
            # Test API key validity
            self.api.info()
            if not self.quiet:
                print(f"✓ Connected to Shodan API successfully")
        except shodan.APIError as e:
            print(f"✗ Shodan API Error: {str(e)}")
            if "Invalid API key" in str(e):
                print("Please check your API key in the config.json file.")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Unable to connect to Shodan: Network connection failed")
            sys.exit(1)

        self.successful_connections = []
        self.total_targets = 0
        self.current_target = 0
        
        # Failure logging setup
        self.log_failures = log_failures
        self.failed_connections = []
        if log_failures:
            # Determine failure output file based on flags (mirror success logic)
            if output_file:
                # If custom output specified, use similar naming for failures
                base_name = output_file.rsplit('.', 1)[0] if '.' in output_file else output_file
                self.failure_output_file = f"{base_name}_failures.csv"
                self.failure_append_mode = False
            elif new_file:
                self.failure_output_file = f"failed_record_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                self.failure_append_mode = False
            else:
                failure_record_name = record_name.replace('ip_record', 'failed_record') if record_name else "failed_record.csv"
                self.failure_output_file = failure_record_name
                self.failure_append_mode = True
        
        # Load organization exclusions
        self.excluded_orgs = self.load_exclusions()

    def check_smbclient_availability(self):
        """Check if smbclient command is available on the system."""
        try:
            # Try to run smbclient --help to check if it's available
            result = subprocess.run(['smbclient', '--help'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False

    def print_if_not_quiet(self, *args, **kwargs):
        """Print message only if not in quiet mode."""
        if not self.quiet:
            print(*args, **kwargs)
    
    def print_if_verbose(self, *args, **kwargs):
        """Print message only if in verbose mode and not quiet."""
        if self.verbose and not self.quiet:
            print(*args, **kwargs)

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
        self.print_if_verbose(f"Search query: {final_query}")

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
                    connection.connect(timeout=self.config["connection"]["timeout"])

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
                # Try to list shares after successful authentication
                shares = []
                try:
                    shares = self.list_smb_shares(ip, username, password)
                    if hasattr(self, 'verbose') and self.verbose and hasattr(self, 'quiet') and not self.quiet:
                        print(f"  {getattr(self, 'CYAN', '')}Debug: Found {len(shares)} shares via smbprotocol: {shares}{getattr(self, 'RESET', '')}")
                except Exception as e:
                    if hasattr(self, 'verbose') and self.verbose and hasattr(self, 'quiet') and not self.quiet:
                        print(f"  {getattr(self, 'CYAN', '')}Debug: Share listing failed: {str(e)}{getattr(self, 'RESET', '')}")
                    # If share listing fails, continue with empty list
                    pass
                
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

                return method_name, shares

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

        return None, []

    def test_smb_alternative(self, ip):
        """Alternative testing method using minimal SMB connection."""
        if not self.smbclient_available:
            return None, []

        # Try using smbclient as a fallback to verify connectivity
        test_commands = [
            ("Anonymous", ["smbclient", "-L", f"//{ip}", "-N"]),
            ("Guest/Blank", ["smbclient", "-L", f"//{ip}", "--user", "guest%"]),
            ("Guest/Guest", ["smbclient", "-L", f"//{ip}", "--user", "guest%guest"])
        ]

        stderr_buffer = StringIO()
        for method_name, cmd in test_commands:
            try:
                # Suppress both stdout and stderr from smbclient, prevent password prompts
                with redirect_stderr(stderr_buffer):
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10, 
                                          stdin=subprocess.DEVNULL)
                    if result.returncode == 0 or "Sharename" in result.stdout:
                        # Try to parse shares from the output if available
                        shares = self.parse_share_list(result.stdout) if "Sharename" in result.stdout else []
                        if hasattr(self, 'verbose') and self.verbose and hasattr(self, 'quiet') and not self.quiet:
                            print(f"  {getattr(self, 'CYAN', '')}Debug: smbclient fallback found {len(shares)} shares: {shares}{getattr(self, 'RESET', '')}")
                        return method_name, shares
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except Exception:
                continue

        return None, []

    def list_smb_shares(self, ip, username="", password=""):
        """List available SMB shares on the target server."""
        if not self.smbclient_available:
            return []
        
        try:
            # Use smbclient command as fallback to list shares
            cmd = ["smbclient", "-L", f"//{ip}"]
            
            # Add authentication based on successful method
            if username == "" and password == "":
                cmd.append("-N")  # No password (anonymous)
            elif username == "guest":
                if password == "":
                    cmd.extend(["--user", "guest%"])
                else:
                    cmd.extend(["--user", f"guest%{password}"])
            else:
                cmd.extend(["--user", f"{username}%{password}"])
            
            # Debug output in verbose mode
            if hasattr(self, 'verbose') and self.verbose and hasattr(self, 'quiet') and not self.quiet:
                print(f"  {getattr(self, 'CYAN', '')}Debug: Running share enumeration: {' '.join(cmd)}{getattr(self, 'RESET', '')}")
            
            # Run command with timeout, prevent password prompts
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=15, stdin=subprocess.DEVNULL)
            
            # Use same success logic as test_smb_alternative
            if result.returncode == 0 or "Sharename" in result.stdout:
                parsed_shares = self.parse_share_list(result.stdout)
                return parsed_shares
            
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        
        return []

    def parse_share_list(self, smbclient_output):
        """Parse smbclient -L output to extract share names."""
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
                    
                    # Skip default/administrative shares (ending with $)
                    if not share_name.endswith('$') and share_type == "Disk":
                        shares.append(share_name)
        
        # Return first 5 shares, add "(and more)" if there are more
        if len(shares) > 5:
            return shares[:5] + ["(and more)"]
        
        return shares

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
            self.print_if_not_quiet(f"  ⏳ Checking port 445...", end='', flush=True)
            if not self.check_port(ip, 445, self.config["connection"]["port_check_timeout"]):
                print(f"\r  {self.RED}✗ Port 445 not accessible{self.RESET}")
                return
            print(f"\r  {self.GREEN}✓ Port 445 open{self.RESET}")

            # Test with smbprotocol library
            self.print_if_not_quiet(f"  ⏳ Testing authentication...", end='', flush=True)
            successful_method, shares = self.test_smb_connection(ip, auth_methods)

            # If smbprotocol fails, try smbclient as fallback
            if not successful_method:
                print(f"\r  ⏳ Trying smbclient fallback...", end='', flush=True)
                fallback_method, fallback_shares = self.test_smb_alternative(ip)
                if fallback_method:
                    successful_method = f"{fallback_method} (smbclient)"
                    shares = fallback_shares

            if successful_method:
                # Format shares for display
                shares_text = ", ".join(shares) if shares else ""
                if shares_text:
                    print(f"\r  {self.GREEN}✓ Success! Authentication: {successful_method} | Shares: {shares_text}{self.RESET}")
                else:
                    print(f"\r  {self.GREEN}✓ Success! Authentication: {successful_method}{self.RESET}")
                
                self.successful_connections.append({
                    'ip': ip,
                    'country': country_name,
                    'auth_method': successful_method,
                    'shares': shares_text,
                    'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M')
                })
            else:
                print(f"\r  {self.RED}✗ All authentication methods failed{self.RESET}")
                
                # Log failure if failure logging is enabled
                if self.log_failures:
                    # Create list of attempted authentication methods
                    attempted_methods = [method_name for method_name, _, _ in auth_methods]
                    attempted_methods_text = ", ".join(attempted_methods)
                    
                    self.failed_connections.append({
                        'ip': ip,
                        'country': country_name,
                        'auth_method': 'All authentication methods failed',
                        'shares': attempted_methods_text,  # Use shares field to store attempted methods
                        'timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M')
                    })

        except KeyboardInterrupt:
            raise  # Re-raise to allow script interruption
        except Exception as e:
            self.print_if_not_quiet(f"  {self.RED}✗ Unexpected error during scan: {str(e)[:50]}{self.RESET}")

    def save_results(self):
        """Save successful connections to CSV file with deduplication."""
        if not self.successful_connections:
            self.print_if_not_quiet("No successful connections found.")
            return

        fieldnames = ['ip_address', 'country', 'auth_method', 'shares', 'timestamp']
        
        try:
            # Load existing records for deduplication
            existing_records = {}
            if self.append_mode and os.path.exists(self.output_file):
                # Check if existing file has compatible headers
                if not self.check_csv_compatibility(self.output_file, fieldnames):
                    # Create new file with timestamp
                    backup_file = f"ip_record_{datetime.now().strftime('%Y%m%d')}.csv"
                    self.print_if_not_quiet(f"{self.YELLOW}⚠ CSV header mismatch detected. Creating new file: {backup_file}{self.RESET}")
                    self.output_file = backup_file
                    self.append_mode = False
                else:
                    # Load existing records for deduplication
                    existing_records = self.load_existing_records(self.output_file)
            
            # Process new connections and merge with existing records
            updated_count = 0
            new_count = 0
            
            for conn in self.successful_connections:
                ip = conn['ip']
                new_record = {
                    'ip_address': ip,
                    'country': conn['country'],
                    'auth_method': conn['auth_method'],
                    'shares': conn.get('shares', ''),
                    'timestamp': conn['timestamp']
                }
                
                if ip in existing_records:
                    # Check if any fields have changed
                    existing = existing_records[ip]
                    fields_changed = False
                    
                    for field in ['country', 'auth_method', 'shares']:
                        if existing.get(field, '') != new_record[field]:
                            fields_changed = True
                            break
                    
                    if fields_changed:
                        # Update existing record with new data and timestamp
                        existing_records[ip] = new_record
                        updated_count += 1
                    else:
                        # Just update timestamp if no other changes
                        existing_records[ip]['timestamp'] = new_record['timestamp']
                        updated_count += 1
                else:
                    # New IP address
                    existing_records[ip] = new_record
                    new_count += 1
            
            # Write all records back to file
            with open(self.output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Sort by IP address for consistent output
                for ip in sorted(existing_records.keys()):
                    writer.writerow(existing_records[ip])

            # Report results
            total_records = len(existing_records)
            self.print_if_not_quiet(f"{self.GREEN}✓{self.RESET} Results saved to {self.output_file}")
            self.print_if_not_quiet(f"{self.GREEN}✓{self.RESET} New IPs: {new_count}, Updated: {updated_count}, Total records: {total_records}")

        except Exception as e:
            print(f"✗ Failed to save results: Unable to write to file")

    def check_csv_compatibility(self, filename, expected_fieldnames):
        """Check if existing CSV file has compatible headers."""
        try:
            with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.reader(csvfile)
                existing_headers = next(reader, None)
                if existing_headers is None:
                    return True  # Empty file, compatible
                return existing_headers == expected_fieldnames
        except Exception:
            return True  # If we can't read it, assume it's compatible

    def load_existing_records(self, filename):
        """Load existing CSV records into a dictionary keyed by IP address."""
        existing_records = {}
        try:
            if os.path.exists(filename):
                with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        ip = row.get('ip_address')
                        if ip:
                            existing_records[ip] = row
        except Exception:
            # If we can't read existing file, start fresh
            pass
        return existing_records

    def save_failed_results(self):
        """Save failed connections to CSV file with deduplication."""
        if not self.log_failures or not self.failed_connections:
            return

        fieldnames = ['ip_address', 'country', 'auth_method', 'shares', 'timestamp']
        
        try:
            # Load existing failure records for deduplication
            existing_records = {}
            if self.failure_append_mode and os.path.exists(self.failure_output_file):
                # Check if existing file has compatible headers
                if not self.check_csv_compatibility(self.failure_output_file, fieldnames):
                    # Create new file with timestamp
                    backup_file = f"failed_record_{datetime.now().strftime('%Y%m%d')}.csv"
                    self.print_if_not_quiet(f"{self.YELLOW}⚠ Failure CSV header mismatch detected. Creating new file: {backup_file}{self.RESET}")
                    self.failure_output_file = backup_file
                    self.failure_append_mode = False
                else:
                    # Load existing records for deduplication
                    existing_records = self.load_existing_records(self.failure_output_file)
            
            # Process new failed connections and merge with existing records
            updated_count = 0
            new_count = 0
            
            for conn in self.failed_connections:
                ip = conn['ip']
                new_record = {
                    'ip_address': ip,
                    'country': conn['country'],
                    'auth_method': conn['auth_method'],
                    'shares': conn.get('shares', ''),
                    'timestamp': conn['timestamp']
                }
                
                if ip in existing_records:
                    # Check if any fields have changed
                    existing = existing_records[ip]
                    fields_changed = False
                    
                    for field in ['country', 'auth_method', 'shares']:
                        if existing.get(field, '') != new_record[field]:
                            fields_changed = True
                            break
                    
                    if fields_changed:
                        # Update existing record with new data and timestamp
                        existing_records[ip] = new_record
                        updated_count += 1
                    else:
                        # Just update timestamp if no other changes
                        existing_records[ip]['timestamp'] = new_record['timestamp']
                        updated_count += 1
                else:
                    # New IP address
                    existing_records[ip] = new_record
                    new_count += 1
            
            # Write all records back to file
            with open(self.failure_output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                # Sort by IP address for consistent output
                for ip in sorted(existing_records.keys()):
                    writer.writerow(existing_records[ip])

            # Report results
            total_records = len(existing_records)
            self.print_if_not_quiet(f"{self.GREEN}✓{self.RESET} Failed connections saved to {self.failure_output_file}")
            self.print_if_not_quiet(f"{self.GREEN}✓{self.RESET} New failures: {new_count}, Updated: {updated_count}, Total failure records: {total_records}")

        except Exception as e:
            print(f"✗ Failed to save failure results: Unable to write to file")

    def run_scan(self, countries=None, country_names_map=None):
        """Run the complete SMB scanning process."""
        if countries is None:
            countries = list(self.config["countries"].keys())
        if country_names_map is None:
            country_names_map = self.config["countries"]

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
                time.sleep(self.config["connection"]["rate_limit_delay"])

        self.print_if_not_quiet("\n" + "=" * 50)
        self.print_if_not_quiet("Scan completed!")
        self.save_results()
        
        # Save failed results if failure logging is enabled
        if self.log_failures:
            self.save_failed_results()

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SMB Scanner Tool - Scans for SMB servers with weak authentication using Shodan API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python smb_scan.py                    # Scan all default countries
  python smb_scan.py -c US              # Scan only United States
  python smb_scan.py -a FR,DE           # Scan defaults plus France and Germany
  python smb_scan.py -t                 # Scan globally (no country filter)
  python smb_scan.py -q -o results.csv  # Quiet mode with custom output file
  python smb_scan.py -c GB -q           # Scan UK in quiet mode
  python smb_scan.py -v                 # Enable verbose authentication testing output
  python smb_scan.py -f                 # Log failed connections to failed_record.csv
  python smb_scan.py -f -v              # Verbose mode with failure logging
  python smb_scan.py -x                 # Disable colored output
  python smb_scan.py --exclude-file custom_exclusions.txt  # Use custom exclusion file
  python smb_scan.py --additional-excludes "My ISP,Another Org"  # Add more exclusions
  python smb_scan.py --no-default-excludes  # Skip default exclusions

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

    parser.add_argument('-a', '--additional-country',
                       type=str,
                       metavar='CODES',
                       help='Comma-separated list of additional country codes to scan (e.g., FR,DE,IT)')

    parser.add_argument('--additional-excludes',
                       type=str,
                       metavar='ORGS',
                       help='Comma-separated list of additional organizations to exclude')

    parser.add_argument('-c', '--country',
                       type=str,
                       metavar='CODE',
                       help='Search only the specified country using two-letter country code')

    parser.add_argument('--exclude-file',
                       type=str,
                       metavar='FILE',
                       help=f'Load organization exclusions from file (default: {DEFAULT_EXCLUSION_FILE})')

    parser.add_argument('-f', '--log-failures',
                       action='store_true',
                       help='Log failed connection attempts to separate CSV file (failed_record.csv)')

    parser.add_argument('-n', '--new-file',
                       action='store_true',
                       help='Create new timestamped file instead of appending to default')

    parser.add_argument('--no-default-excludes',
                       action='store_true',
                       help='Skip loading default organization exclusions')

    parser.add_argument('-o', '--output',
                       type=str,
                       metavar='FILE',
                       help='Specify output CSV file (default: appends to ip_record.csv)')

    parser.add_argument('-q', '--quiet',
                       action='store_true',
                       help='Suppress output to screen (useful for scripting)')

    parser.add_argument('-r', '--record-name',
                       type=str,
                       metavar='NAME',
                       help='Specify name for consolidated results file (default: ip_record.csv)')

    parser.add_argument('-t', '--terra',
                       action='store_true',
                       help='Search globally without country filters (terra = Earth)')

    parser.add_argument('-v', '--vox',
                       action='store_true',
                       help='Enable verbose output showing detailed authentication testing steps')

    parser.add_argument('-x', '--nyx',
                       action='store_true',
                       help='Disable colored output (nyx = darkness/no colors)')

    return parser.parse_args()

def main():
    """Main function."""

    # Suppress thread exception output from smbprotocol library
    def thread_exception_handler(args):
        # Silently ignore thread exceptions from smbprotocol
        pass

    threading.excepthook = thread_exception_handler

    args = parse_arguments()
    
    if args.quiet and args.vox:
        print("🤔 Well, that's... interesting. You want me to be both chatty AND silent?")
        print("I'll go with quiet mode since silence is golden (unlike this contradiction).")
        args.vox = False

    if not args.quiet:
        print("SMB Scanner Tool")
        print("Scanning for SMB servers with weak authentication")

    # Determine target countries
    countries = []
    country_names_map = CONFIG["countries"].copy()

    if args.terra:
        # Global search - no country filter
        countries = []
        if not args.quiet:
            print("Target: Global (no country filter)")
    elif args.country:
        # Single country specified
        country_code = args.country.upper()
        countries = [country_code]
        if country_code not in CONFIG["countries"]:
            # Add custom country to the map
            country_names_map[country_code] = country_code
        if not args.quiet:
            print(f"Target country: {country_names_map.get(country_code, country_code)}")
    else:
        # Use default countries
        countries = list(CONFIG["countries"].keys())

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
    if CONFIG["shodan"]["api_key"] == "YOUR_API_KEY_HERE":
        print("✗ Please configure your Shodan API key in config.json")
        sys.exit(1)

    try:
        scanner = SMBScanner(
            CONFIG,
            quiet=args.quiet,
            verbose=args.vox,
            output_file=args.output,
            exclusion_file=args.exclude_file,
            additional_excludes=additional_excludes,
            no_default_excludes=args.no_default_excludes,
            no_colors=args.nyx,
            new_file=args.new_file,
            record_name=args.record_name,
            log_failures=args.log_failures
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
