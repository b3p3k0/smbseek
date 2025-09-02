"""
SMBSeek Discover Command

Discovery and authentication testing functionality adapted for the unified CLI.
Implements Shodan querying and SMB authentication testing with intelligent filtering.
"""

import shodan
import sys
import os
import time
import uuid
import socket
import subprocess
from datetime import datetime
from typing import Set, List, Dict, Optional
from contextlib import redirect_stderr
from io import StringIO

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
tools_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
sys.path.insert(0, tools_path)

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager

# SMB imports (with error handling for missing dependencies)
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.exceptions import SMBException
    SMB_AVAILABLE = True
except ImportError:
    SMB_AVAILABLE = False


class DiscoverCommand:
    """
    SMB discovery and authentication testing command.
    
    Queries Shodan for SMB servers and tests authentication methods
    with intelligent host filtering and database integration.
    """
    
    def __init__(self, args):
        """
        Initialize discover command.
        
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
        self.database = create_workflow_database(self.config)
        
        # Initialize Shodan API
        try:
            api_key = self.config.get_shodan_api_key()
            self.shodan_api = shodan.Shodan(api_key)
        except ValueError as e:
            self.shodan_api = None
            self.output.error(str(e))
        
        # Load exclusion list
        self.exclusions = self._load_exclusions()
        
        # Check smbclient availability for fallback authentication
        self.smbclient_available = self._check_smbclient_availability()
        if not self.smbclient_available and not args.quiet:
            self.output.warning("smbclient unavailable; authentication will use smbprotocol only")
        
        # Statistics
        self.stats = {
            'shodan_results': 0,
            'excluded_ips': 0,
            'new_hosts': 0,
            'skipped_hosts': 0,
            'successful_auth': 0,
            'failed_auth': 0,
            'total_processed': 0
        }
    
    def execute(self) -> int:
        """
        Execute the discover command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        if not SMB_AVAILABLE:
            self.output.error("SMB libraries not available. Please install: pip install smbprotocol")
            return 1
        
        if not self.shodan_api:
            return 1
        
        try:
            self.output.header("SMB Discovery & Authentication Testing")
            
            # Show database status
            self.database.show_database_status()
            
            # Query Shodan
            shodan_results = self._query_shodan()
            if not shodan_results:
                self.output.warning("No results from Shodan query")
                return 0
            
            # Apply exclusions
            filtered_results = self._apply_exclusions(shodan_results)
            
            # Filter for new hosts
            hosts_to_scan, filter_stats = self.database.get_new_hosts_filter(
                filtered_results,
                rescan_all=getattr(self.args, 'rescan_all', False),
                rescan_failed=getattr(self.args, 'rescan_failed', False),
                output_manager=self.output
            )
            
            # Display scan statistics
            self.database.display_scan_statistics(filter_stats, hosts_to_scan)
            
            if not hosts_to_scan:
                return 0
            
            # Test SMB authentication
            successful_hosts = self._test_smb_authentication(hosts_to_scan)
            
            # Display final results
            self._display_results(successful_hosts)
            
            return 0
        
        except KeyboardInterrupt:
            self.output.warning("Discovery interrupted by user")
            return 130
        except Exception as e:
            self.output.error(f"Discovery failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()
    
    def _query_shodan(self) -> Set[str]:
        """
        Query Shodan for SMB servers in specified country.
        
        Returns:
            Set of IP addresses from Shodan results
        """
        # Resolve target countries using 3-tier fallback logic
        target_countries = self.config.resolve_target_countries(self.args.country)
        
        # Display what we're scanning
        if target_countries:
            countries_dict = self.config.get("countries") or {}
            country_names = [countries_dict.get(c, c) for c in target_countries]
            self.output.info(f"Querying Shodan for SMB servers in: {', '.join(country_names)}")
        else:
            if not self.args.country and not self.args.quiet:
                self.output.info("No --country specified, loading from config")
            self.output.info("Querying Shodan for SMB servers globally (no country filter)")
        
        try:
            # Build targeted Shodan query 
            query = self._build_targeted_query(target_countries)
            
            # Execute query with configured limit
            shodan_config = self.config.get_shodan_config()
            max_results = shodan_config['query_limits']['max_results']
            results = self.shodan_api.search(query, limit=max_results)
            
            # Extract IP addresses
            ip_addresses = {result['ip_str'] for result in results['matches']}
            
            self.stats['shodan_results'] = len(ip_addresses)
            self.output.success(f"Found {len(ip_addresses)} SMB servers in Shodan database")
            
            return ip_addresses
        
        except shodan.APIError as e:
            self.output.error(f"Shodan API error: {e}")
            return set()
        except Exception as e:
            self.output.error(f"Shodan query failed: {e}")
            return set()
    
    def _build_targeted_query(self, countries: list) -> str:
        """
        Build a targeted Shodan query for vulnerable SMB servers.
        
        Args:
            countries: List of country codes for search (empty list for global)
            
        Returns:
            Formatted Shodan query string
        """
        # Get query configuration
        query_config = self.config.get("shodan", "query_components", {})
        
        # Base query components (configurable)
        base_query = query_config.get("base_query", "smb authentication: disabled")
        product_filter = query_config.get("product_filter", 'product:"Samba"')
        
        # Start with base components
        query_parts = [base_query, product_filter]
        
        # Add country filter only if countries specified
        if countries:
            if len(countries) == 1:
                country_filter = f'country:{countries[0]}'
            else:
                # Multiple countries: comma-separated format
                country_codes = ','.join(countries)
                country_filter = f'country:{country_codes}'
            query_parts.append(country_filter)
        
        # Organization exclusions (if enabled)
        org_exclusions = []
        if query_config.get("use_organization_exclusions", True):
            for org in self.exclusions:
                # Escape quotes if they exist in org name
                escaped_org = org.replace('"', '\\"')
                org_exclusions.append(f'-org:"{escaped_org}"')
        
        # Additional exclusions from config
        additional_exclusions = query_config.get("additional_exclusions", ['-"DSL"'])
        
        # Add exclusions
        query_parts.extend(org_exclusions)
        query_parts.extend(additional_exclusions)
        
        final_query = ' '.join(query_parts)
        self.output.print_if_verbose(f"Shodan query: {final_query}")
        
        return final_query
    
    def _apply_exclusions(self, ip_addresses: Set[str]) -> Set[str]:
        """
        Apply exclusion filters to IP addresses.
        
        Args:
            ip_addresses: Set of IP addresses to filter
            
        Returns:
            Filtered set of IP addresses
        """
        if not self.exclusions:
            return ip_addresses
        
        total_ips = len(ip_addresses)
        self.output.info(f"Applying exclusion filters to {total_ips} IPs...")
        
        filtered_ips = set()
        excluded_count = 0
        processed_count = 0
        
        for ip in ip_addresses:
            processed_count += 1
            
            # Show progress every 50 IPs or at key milestones
            if processed_count % 50 == 0 or processed_count == 1 or processed_count == total_ips:
                progress_pct = (processed_count / total_ips) * 100
                self.output.info(f"🔍 Filtering progress: {processed_count}/{total_ips} ({progress_pct:.1f}%) | Excluded: {excluded_count}")
            
            if self._should_exclude_ip(ip):
                excluded_count += 1
            else:
                filtered_ips.add(ip)
        
        self.stats['excluded_ips'] = excluded_count
        
        if excluded_count > 0:
            self.output.info(f"✓ Excluded {excluded_count} IPs (ISPs, cloud providers, etc.)")
        
        return filtered_ips
    
    def _should_exclude_ip(self, ip: str) -> bool:
        """
        Check if IP should be excluded based on organization.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP should be excluded
        """
        try:
            # Get organization info from Shodan
            host_info = self.shodan_api.host(ip)
            org = host_info.get('org', '').lower()
            isp = host_info.get('isp', '').lower()
            
            # Check against exclusion patterns
            for exclusion in self.exclusions:
                if exclusion.lower() in org or exclusion.lower() in isp:
                    return True
            
            return False
        
        except:
            # If we can't get org info, don't exclude
            return False
    
    def _load_exclusions(self) -> List[str]:
        """
        Load exclusion list from file.
        
        Returns:
            List of exclusion patterns
        """
        exclusion_file = self.config.get_exclusion_file_path()
        
        try:
            with open(exclusion_file, 'r', encoding='utf-8') as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.output.print_if_verbose(f"Loaded {len(exclusions)} exclusion patterns")
            return exclusions
        
        except FileNotFoundError:
            self.output.warning(f"Exclusion file not found: {exclusion_file}")
            return []
        except Exception as e:
            self.output.warning(f"Error loading exclusion file: {e}")
            return []
    
    def _check_smbclient_availability(self) -> bool:
        """Check if smbclient command is available on the system."""
        try:
            result = subprocess.run(['smbclient', '--help'], 
                                  capture_output=True, 
                                  timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return False
    
    def _test_smb_authentication(self, ip_addresses: Set[str]) -> List[Dict]:
        """
        Test SMB authentication on IP addresses.
        
        Args:
            ip_addresses: Set of IP addresses to test
            
        Returns:
            List of successful authentication results
        """
        self.output.info(f"Testing SMB authentication on {len(ip_addresses)} hosts...")
        
        successful_hosts = []
        total_hosts = len(ip_addresses)
        
        for i, ip in enumerate(ip_addresses, 1):
            # Show progress every 25 hosts or at significant milestones
            if i % 25 == 0 or i == 1 or i == total_hosts:
                progress_pct = (i / total_hosts) * 100
                success_count = self.stats['successful_auth']
                failed_count = self.stats['failed_auth']
                self.output.info(f"📊 Progress: {i}/{total_hosts} ({progress_pct:.1f}%) | Success: {success_count}, Failed: {failed_count}")
            
            self.output.print_if_verbose(f"[{i}/{total_hosts}] Testing {ip}...")
            
            result = self._test_single_host(ip)
            if result:
                successful_hosts.append(result)
                self.stats['successful_auth'] += 1
                self.output.print_if_verbose(f"  ✓ {ip}: {result['auth_method']}")
            else:
                self.stats['failed_auth'] += 1
            
            # Rate limiting
            if i < total_hosts:
                time.sleep(self.config.get_rate_limit_delay())
        
        self.stats['total_processed'] = total_hosts
        return successful_hosts
    
    def _test_single_host(self, ip: str) -> Optional[Dict]:
        """
        Test SMB authentication on a single host.
        
        Args:
            ip: IP address to test
            
        Returns:
            Authentication result dictionary or None if failed
        """
        # Test port 445 availability first
        if not self._check_port(ip, 445):
            return None
        
        # Test authentication methods in order
        auth_methods = [
            ("Anonymous", "", ""),
            ("Guest/Blank", "guest", ""),
            ("Guest/Guest", "guest", "guest")
        ]
        
        for method_name, username, password in auth_methods:
            if self._test_smb_auth(ip, username, password):
                return {
                    'ip_address': ip,
                    'country': getattr(self.args, 'country', 'Unknown') or 'Unknown',
                    'auth_method': method_name,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'accessible'
                }
        
        # If smbprotocol fails, try smbclient fallback
        if self.smbclient_available:
            fallback_result = self._test_smb_alternative(ip)
            if fallback_result:
                return {
                    'ip_address': ip,
                    'country': getattr(self.args, 'country', 'Unknown') or 'Unknown',
                    'auth_method': f"{fallback_result} (smbclient)",
                    'timestamp': datetime.now().isoformat(),
                    'status': 'accessible'
                }
        
        return None
    
    def _check_port(self, ip: str, port: int) -> bool:
        """
        Check if port is open.
        
        Args:
            ip: IP address
            port: Port number
            
        Returns:
            True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.get("connection", "port_check_timeout", 10))
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _test_smb_auth(self, ip: str, username: str, password: str) -> bool:
        """
        Test SMB authentication.
        
        Args:
            ip: IP address
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            True if authentication successful
        """
        conn_uuid = str(uuid.uuid4())
        connection = None
        session = None
        
        try:
            # Suppress stderr output
            stderr_buffer = StringIO()
            with redirect_stderr(stderr_buffer):
                # Create connection
                connection = Connection(conn_uuid, ip, 445, require_signing=False)
                connection.connect(timeout=self.config.get_connection_timeout())
                
                # Create session
                session = Session(
                    connection,
                    username=username,
                    password=password,
                    require_encryption=False,
                    auth_protocol="ntlm"
                )
                session.connect()
                
                return True
        
        except SMBException:
            return False
        except Exception:
            return False
        finally:
            # Cleanup connections
            try:
                if session:
                    session.disconnect()
                if connection:
                    connection.disconnect()
            except:
                pass
    
    def _test_smb_alternative(self, ip: str) -> Optional[str]:
        """
        Alternative testing method using smbclient as fallback.
        
        Args:
            ip: IP address to test
            
        Returns:
            Authentication method name if successful, None otherwise
        """
        if not self.smbclient_available:
            return None
        
        # Test commands matching legacy system
        test_commands = [
            ("Anonymous", ["smbclient", "-L", f"//{ip}", "-N"]),
            ("Guest/Blank", ["smbclient", "-L", f"//{ip}", "--user", "guest%"]),
            ("Guest/Guest", ["smbclient", "-L", f"//{ip}", "--user", "guest%guest"])
        ]
        
        stderr_buffer = StringIO()
        for method_name, cmd in test_commands:
            try:
                with redirect_stderr(stderr_buffer):
                    result = subprocess.run(cmd, capture_output=True, text=True, 
                                          timeout=10, stdin=subprocess.DEVNULL)
                    if result.returncode == 0 or "Sharename" in result.stdout:
                        return method_name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except Exception:
                continue
        
        return None
    
    def _display_results(self, successful_hosts: List[Dict]):
        """
        Display final results and save to database.
        
        Args:
            successful_hosts: List of successful authentication results
        """
        self.output.subheader("Discovery Results")
        
        # Display statistics
        self.output.print_if_not_quiet(f"Shodan Results: {self.stats['shodan_results']}")
        self.output.print_if_not_quiet(f"Excluded IPs: {self.stats['excluded_ips']}")
        self.output.print_if_not_quiet(f"Hosts Tested: {self.stats['total_processed']}")
        self.output.print_if_not_quiet(f"Successful Auth: {self.stats['successful_auth']}")
        self.output.print_if_not_quiet(f"Failed Auth: {self.stats['failed_auth']}")
        
        if successful_hosts:
            self.output.success(f"Found {len(successful_hosts)} accessible SMB servers")
            
            # Save to database
            self._save_to_database(successful_hosts)
        else:
            self.output.warning("No accessible SMB servers found")
    
    def _save_to_database(self, successful_hosts: List[Dict]):
        """
        Save successful authentication results to database.
        
        Args:
            successful_hosts: List of successful results to save
        """
        try:
            # Record scan session
            # Resolve target countries for session data
            target_countries = self.config.resolve_target_countries(self.args.country)
            
            session_data = {
                'tool_name': 'smbseek-discover',
                'countries': target_countries if target_countries else ['global'],
                'targets_found': self.stats['shodan_results'],
                'successful_connections': len(successful_hosts),
                'total_shares': 0,  # Will be updated by access command
                'accessible_shares': 0,  # Will be updated by access command
                'config_used': {
                    'country_arg': self.args.country,
                    'resolved_countries': target_countries,
                    'rescan_all': getattr(self.args, 'rescan_all', False),
                    'rescan_failed': getattr(self.args, 'rescan_failed', False)
                }
            }
            
            session_id = self.database.record_scan_session(session_data)
            
            # Save individual host results
            from db_manager import SMBSeekDataAccessLayer
            dal = SMBSeekDataAccessLayer(self.database.db_manager)
            
            for host in successful_hosts:
                server_id = dal.get_or_create_server(
                    ip_address=host['ip_address'],
                    country=host['country'],
                    auth_method=host['auth_method']
                )
            
            self.output.success(f"Results saved to database (session: {session_id})")
        
        except Exception as e:
            self.output.error(f"Failed to save results to database: {e}")