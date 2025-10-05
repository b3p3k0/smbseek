"""
SMBSeek Discover Operations

Discovery and authentication testing functionality for the unified workflow.
Implements Shodan querying and SMB authentication testing with intelligent filtering.
"""

import shodan
import sys
import os
import time
import uuid
import socket
import subprocess
import threading
from datetime import datetime
from dataclasses import dataclass
from typing import Set, List, Dict, Optional
from contextlib import redirect_stderr
from io import StringIO
from concurrent.futures import ThreadPoolExecutor

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


@dataclass
class DiscoverResult:
    """Results from discovery operation"""
    query_used: str
    total_hosts: int
    authenticated_hosts: int
    host_ips: Set[str]


class DiscoverOperation:
    """
    SMB discovery and authentication testing operation.

    Queries Shodan for SMB servers and tests authentication methods
    with intelligent host filtering and database integration.
    """

    def __init__(self, config, output, database, session_id, risky_mode=False):
        """
        Initialize discover operation.

        Args:
            config: SMBSeekConfig instance
            output: SMBSeekOutput instance
            database: SMBSeekWorkflowDatabase instance
            session_id: Database session ID for this operation
            risky_mode: Enable legacy insecure SMB settings if True
        """
        self.config = config
        self.output = output
        self.database = database
        self.session_id = session_id
        self.risky_mode = risky_mode

        # Initialize Shodan host metadata tracking
        self.shodan_host_metadata = {}

        # Initialize memoization cache for API calls (cleared per operation)
        self._host_lookup_cache = {}

        # Initialize thread-safe rate limiting for discovery concurrency
        self._auth_rate_lock = threading.Lock()
        self._last_auth_attempt = 0

        # Initialize SMBClient authentication cache for fallback outcomes
        self._smbclient_auth_cache = {}

        # Initialize Shodan API
        try:
            api_key = self.config.get_shodan_api_key()
            self.shodan_api = shodan.Shodan(api_key)
        except ValueError as e:
            self.shodan_api = None
            self.output.error(str(e))

        # Load exclusion list and normalized patterns
        self.exclusions = self._load_exclusions()
        # Note: self.exclusion_patterns is set by _load_exclusions()

        # Check smbclient availability for fallback authentication
        self.smbclient_available = self._check_smbclient_availability()
        if not self.smbclient_available:
            self.output.print_if_verbose("smbclient unavailable; authentication will use smbprotocol only")

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

    def execute(self, country=None, rescan_all=False, rescan_failed=False, force_hosts=None) -> DiscoverResult:
        """
        Execute the discover operation.

        Args:
            country: Target country code for Shodan search
            rescan_all: Force rescan of all discovered hosts
            rescan_failed: Include previously failed hosts for rescanning
            force_hosts: Set of IP addresses to force scan regardless of filters

        Returns:
            DiscoverResult with discovery statistics

        Raises:
            RuntimeError: If SMB libraries unavailable or Shodan API fails
        """
        if not SMB_AVAILABLE:
            raise RuntimeError("SMB libraries not available. Please install: pip install smbprotocol")

        if not self.shodan_api:
            raise RuntimeError("Shodan API not available")

        # Clear metadata and cache from any previous runs to prevent stale data leakage
        self.shodan_host_metadata = {}
        self._host_lookup_cache = {}
        self._smbclient_auth_cache = {}

        # Initialize force_hosts to empty set if None
        if force_hosts is None:
            force_hosts = set()

        self.output.print_if_verbose("Starting discovery operation...")
        if force_hosts:
            self.output.print_if_verbose(f"Forced hosts specified: {', '.join(sorted(force_hosts))}")

        # Query Shodan
        shodan_results = self._query_shodan(country)

        # Add forced hosts to results and create placeholder metadata
        if force_hosts:
            forced_hosts_added = force_hosts - shodan_results
            if forced_hosts_added:
                self.output.print_if_verbose(f"Adding {len(forced_hosts_added)} forced hosts not in Shodan results")
                for ip in forced_hosts_added:
                    # Create minimal placeholder metadata for forced hosts
                    self.shodan_host_metadata[ip] = {'country_name': 'Unknown'}
            shodan_results = shodan_results.union(force_hosts)

        if not shodan_results:
            self.output.warning("No results from Shodan query and no forced hosts")
            return DiscoverResult(
                query_used="",
                total_hosts=0,
                authenticated_hosts=0,
                host_ips=set()
            )

        # Build the query string for summary display
        target_countries = self.config.resolve_target_countries(country)
        query_used = self._build_targeted_query(target_countries)

        # Apply exclusions
        # Debug trace before exclusion filtering
        self.output.print_if_verbose(f"DEBUG: Before exclusions - shodan_host_metadata type: {type(self.shodan_host_metadata)}, len: {len(self.shodan_host_metadata) if isinstance(self.shodan_host_metadata, dict) else 'N/A'}")
        filtered_results = self._apply_exclusions(shodan_results)

        # Filter for new hosts
        hosts_to_scan, filter_stats = self.database.get_new_hosts_filter(
            filtered_results,
            rescan_all=rescan_all,
            rescan_failed=rescan_failed,
            output_manager=self.output
        )

        # Re-add forced hosts after database filtering (bypass filters)
        if force_hosts:
            forced_hosts_bypassed = force_hosts - hosts_to_scan
            if forced_hosts_bypassed:
                self.output.print_if_verbose(f"Adding {len(forced_hosts_bypassed)} forced hosts (bypassing database filters)")
                hosts_to_scan = hosts_to_scan.union(force_hosts)
                # Update stats to reflect forced hosts
                filter_stats['forced_hosts'] = len(force_hosts)
                filter_stats['to_scan'] = len(hosts_to_scan)

        # Trim metadata to only hosts that will be scanned to maintain alignment
        # Keep forced host metadata even if minimal
        # Defensive type check before dictionary comprehension
        if not isinstance(self.shodan_host_metadata, dict):
            self.output.error(f"CRITICAL: shodan_host_metadata corrupted before trimming - expected dict, got {type(self.shodan_host_metadata)}: {self.shodan_host_metadata}")
            self.shodan_host_metadata = {}

        # Additional type safety checks for the comprehension inputs
        if not isinstance(hosts_to_scan, (set, list, tuple)):
            self.output.error(f"CRITICAL: hosts_to_scan has unexpected type - expected set/list/tuple, got {type(hosts_to_scan)}: {hosts_to_scan}")
            hosts_to_scan = set()

        try:
            # Safe dictionary comprehension with error handling
            new_metadata = {}
            for ip in hosts_to_scan:
                if ip in self.shodan_host_metadata:
                    if isinstance(self.shodan_host_metadata[ip], dict):
                        new_metadata[ip] = self.shodan_host_metadata[ip]
                    else:
                        self.output.warning(f"Skipping corrupted metadata for IP {ip}: expected dict, got {type(self.shodan_host_metadata[ip])}")

            self.shodan_host_metadata = new_metadata
        except Exception as e:
            self.output.error(f"CRITICAL: Error during metadata trimming: {e}")
            self.shodan_host_metadata = {}

        # Display scan statistics
        self.database.display_scan_statistics(filter_stats, hosts_to_scan)

        if not hosts_to_scan:
            self.output.info("No new hosts to scan")
            return DiscoverResult(
                query_used=query_used,
                total_hosts=len(filtered_results),
                authenticated_hosts=0,
                host_ips=set()
            )

        # Test SMB authentication
        successful_hosts = self._test_smb_authentication(hosts_to_scan, country)

        # Save results to database using provided session_id
        authenticated_ips = self._save_to_database(successful_hosts, country)

        self.output.print_if_verbose(f"Discovery operation completed: {len(authenticated_ips)} authenticated hosts")

        return DiscoverResult(
            query_used=query_used,
            total_hosts=len(hosts_to_scan),
            authenticated_hosts=len(authenticated_ips),
            host_ips=authenticated_ips
        )
    
    def _query_shodan(self, country=None) -> Set[str]:
        """
        Query Shodan for SMB servers in specified country.

        Args:
            country: Target country code for search

        Returns:
            Set of IP addresses from Shodan results
        """
        # Debug trace at start of Shodan query
        self.output.print_if_verbose(f"DEBUG: At start of _query_shodan - shodan_host_metadata type: {type(self.shodan_host_metadata)}, len: {len(self.shodan_host_metadata) if isinstance(self.shodan_host_metadata, dict) else 'N/A'}")
        # Resolve target countries using 3-tier fallback logic
        target_countries = self.config.resolve_target_countries(country)
        
        # Display what we're scanning
        if target_countries:
            countries_dict = self.config.get("countries") or {}
            country_names = [countries_dict.get(c, c) for c in target_countries]
            self.output.info(f"Querying Shodan for SMB servers in: {', '.join(country_names)}")
        else:
            if not country:
                self.output.print_if_verbose("No country specified, using global search")
            self.output.info("Querying Shodan for SMB servers globally (no country filter)")
        
        try:
            # Build targeted Shodan query 
            query = self._build_targeted_query(target_countries)
            
            # Execute query with configured limit
            shodan_config = self.config.get_shodan_config()
            max_results = shodan_config['query_limits']['max_results']
            results = self.shodan_api.search(query, limit=max_results)
            
            # Extract IP addresses and capture metadata for exclusion optimization
            ip_addresses = set()
            for result in results['matches']:
                ip = result['ip_str']
                ip_addresses.add(ip)

                # Extract location metadata with fallbacks
                location = result.get('location', {})
                country_name = location.get('country_name') or result.get('country_name')
                country_code = location.get('country_code') or result.get('country_code')

                # Extract org/ISP metadata for exclusion filtering performance
                org = result.get('org', '')
                isp = result.get('isp', '')

                # Store metadata using "first complete record wins" strategy
                # Defensive type check before setdefault operation
                if not isinstance(self.shodan_host_metadata, dict):
                    self.output.error(f"CRITICAL: shodan_host_metadata corrupted during Shodan result processing - expected dict, got {type(self.shodan_host_metadata)}: {self.shodan_host_metadata}")
                    self.shodan_host_metadata = {}

                metadata = self.shodan_host_metadata.setdefault(ip, {})

                if country_name and not metadata.get('country_name'):
                    metadata['country_name'] = country_name
                if country_code and not metadata.get('country_code'):
                    metadata['country_code'] = country_code

                # Cache org/ISP with safe normalization to avoid repeated API calls during exclusions
                if org and not metadata.get('org_normalized') and isinstance(org, str):
                    metadata['org'] = org
                    metadata['org_normalized'] = org.lower()
                if isp and not metadata.get('isp_normalized') and isinstance(isp, str):
                    metadata['isp'] = isp
                    metadata['isp_normalized'] = isp.lower()

            self.stats['shodan_results'] = len(ip_addresses)
            self.output.success(f"Found {len(ip_addresses)} SMB servers in Shodan database")
            self.output.print_if_verbose(f"Captured metadata for {len(self.shodan_host_metadata)} hosts")
            
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
        # Defensive type check at start of exclusion filtering
        if not isinstance(self.shodan_host_metadata, dict):
            self.output.error(f"CRITICAL: shodan_host_metadata corrupted at start of exclusion filtering - expected dict, got {type(self.shodan_host_metadata)}: {self.shodan_host_metadata}")
            self.shodan_host_metadata = {}

        if not self.exclusions:
            return ip_addresses
        
        total_ips = len(ip_addresses)
        self.output.info(f"Applying exclusion filters to {total_ips} IPs...")
        
        filtered_ips = set()
        excluded_count = 0
        processed_count = 0
        
        # Get configurable progress interval with safe integer conversion
        try:
            progress_interval = int(self.config.get("exclusions", "progress_interval", 100))
        except (ValueError, TypeError):
            progress_interval = 100

        for ip in ip_addresses:
            processed_count += 1

            # Show progress at configurable intervals or key milestones
            if processed_count % progress_interval == 0 or processed_count == 1 or processed_count == total_ips:
                progress_pct = (processed_count / total_ips) * 100
                self.output.info(f"🔍 Filtering progress: {processed_count}/{total_ips} ({progress_pct:.1f}%) | Excluded: {excluded_count}")
            
            if self._should_exclude_ip(ip):
                excluded_count += 1
                # Remove excluded IP from metadata to maintain alignment
                self.shodan_host_metadata.pop(ip, None)
            else:
                filtered_ips.add(ip)
        
        self.stats['excluded_ips'] = excluded_count
        
        if excluded_count > 0:
            self.output.info(f"✓ Excluded {excluded_count} IPs (ISPs, cloud providers, etc.)")
        
        return filtered_ips
    
    def _should_exclude_ip(self, ip: str) -> bool:
        """
        Check if IP should be excluded based on organization using cached metadata.

        Args:
            ip: IP address to check

        Returns:
            True if IP should be excluded
        """
        # Fail open if API unavailable
        if not self.shodan_api:
            return False

        # Check if we already have normalized org/ISP metadata cached
        # Defensive type check to prevent "int has no attribute get" error
        if not isinstance(self.shodan_host_metadata, dict):
            self.output.error(f"CRITICAL: shodan_host_metadata corrupted - expected dict, got {type(self.shodan_host_metadata)}: {self.shodan_host_metadata}")
            # Reset to empty dict to continue operation
            self.shodan_host_metadata = {}

        metadata = self.shodan_host_metadata.get(ip, {})
        org_normalized = metadata.get('org_normalized')
        isp_normalized = metadata.get('isp_normalized')

        # If we have cached normalized data, use it directly
        if org_normalized is not None and isp_normalized is not None:
            for pattern in self.exclusion_patterns:
                if pattern in org_normalized or pattern in isp_normalized:
                    return True
            return False

        # Check memoization cache before making API call
        if ip in self._host_lookup_cache:
            cached_result = self._host_lookup_cache[ip]
            if cached_result is None:
                # Previous API call failed, don't retry
                return False

            # Use cached API result
            org_normalized = cached_result.get('org_normalized', '')
            isp_normalized = cached_result.get('isp_normalized', '')

            for pattern in self.exclusion_patterns:
                if pattern in org_normalized or pattern in isp_normalized:
                    return True
            return False

        # Need to make API call - get fresh org/ISP data
        try:
            host_info = self.shodan_api.host(ip)
            org = host_info.get('org', '')
            isp = host_info.get('isp', '')

            # Safe normalization with type checking
            org_normalized = org.lower() if isinstance(org, str) else ''
            isp_normalized = isp.lower() if isinstance(isp, str) else ''

            # Cache results in both locations to mark IP as fully resolved
            api_result = {
                'org': org,
                'isp': isp,
                'org_normalized': org_normalized,
                'isp_normalized': isp_normalized
            }
            self._host_lookup_cache[ip] = api_result

            # Update metadata cache with complete org/ISP info
            # Defensive type check before setdefault operation
            if not isinstance(self.shodan_host_metadata, dict):
                self.output.error(f"CRITICAL: shodan_host_metadata corrupted during API call processing - expected dict, got {type(self.shodan_host_metadata)}: {self.shodan_host_metadata}")
                self.shodan_host_metadata = {}

            metadata = self.shodan_host_metadata.setdefault(ip, {})
            metadata.update(api_result)

            # Check against exclusion patterns
            for pattern in self.exclusion_patterns:
                if pattern in org_normalized or pattern in isp_normalized:
                    return True
            return False

        except Exception:
            # Cache failure to prevent retry loops
            self._host_lookup_cache[ip] = None
            return False
    
    def _load_exclusions(self) -> List[str]:
        """
        Load exclusion list from file and prepare normalized patterns.

        Returns:
            List of exclusion patterns (original casing for Shodan query building)
        """
        exclusion_file = self.config.get_exclusion_file_path()

        try:
            with open(exclusion_file, 'r', encoding='utf-8') as f:
                exclusions = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            # Create normalized patterns for fast substring matching during exclusions
            self.exclusion_patterns = [pattern.lower() for pattern in exclusions]

            self.output.print_if_verbose(f"Loaded {len(exclusions)} exclusion patterns")
            return exclusions

        except FileNotFoundError:
            self.output.warning(f"Exclusion file not found: {exclusion_file}")
            self.exclusion_patterns = []
            return []
        except Exception as e:
            self.output.warning(f"Error loading exclusion file: {e}")
            self.exclusion_patterns = []
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

    def _throttled_auth_wait(self) -> None:
        """
        Thread-safe rate limiting for discovery authentication attempts.

        Enforces global rate limiting across concurrent threads by maintaining
        shared timestamp tracking with proper locking.
        """
        with self._auth_rate_lock:
            current_time = time.monotonic()

            # First run: establish baseline without sleeping
            if self._last_auth_attempt == 0:
                self._last_auth_attempt = current_time
                return

            # Calculate time since last attempt and sleep remainder if needed
            time_elapsed = current_time - self._last_auth_attempt
            rate_delay = self.config.get_rate_limit_delay()

            if time_elapsed < rate_delay:
                sleep_time = rate_delay - time_elapsed
                time.sleep(sleep_time)

            # Update timestamp for next thread
            self._last_auth_attempt = time.monotonic()

    def _test_single_host_concurrent(self, ip: str, country=None) -> Dict:
        """
        Thread-safe wrapper for _test_single_host that returns structured results.

        Args:
            ip: IP address to test
            country: Country code for metadata

        Returns:
            Dictionary with result, success/failed flags, and metadata
        """
        try:
            # Apply thread-safe rate limiting before each host attempt
            self._throttled_auth_wait()

            # Test the host using existing logic
            result = self._test_single_host(ip, country)

            if result:
                return {
                    "result": result,
                    "success": True,
                    "failed": False,
                    "metadata": {}
                }
            else:
                return {
                    "result": None,
                    "success": False,
                    "failed": True,
                    "metadata": {}
                }

        except Exception as e:
            return {
                "ip": ip,
                "error": str(e),
                "success": False,
                "failed": True,
                "result": None,
                "metadata": {}
            }

    def _test_smb_authentication(self, ip_addresses: Set[str], country=None) -> List[Dict]:
        """
        Test SMB authentication on IP addresses with configurable concurrency.

        Args:
            ip_addresses: Set of IP addresses to test
            country: Country code for metadata

        Returns:
            List of successful authentication results
        """
        if not ip_addresses:
            return []

        total_hosts = len(ip_addresses)
        self.output.info(f"Testing SMB authentication on {total_hosts} hosts...")

        # Get concurrency setting and size executor appropriately
        max_concurrent_hosts = self.config.get_max_concurrent_discovery_hosts()
        max_workers = min(max_concurrent_hosts, total_hosts)

        # Convert to list for deterministic ordering
        ip_list = list(ip_addresses)

        # If max_concurrent_hosts is 1, use sequential processing (preserve existing behavior)
        if max_workers == 1:
            return self._test_smb_authentication_sequential(ip_list, country)

        # Concurrent processing with ThreadPoolExecutor
        successful_hosts = []
        results_by_index = [None] * total_hosts

        # Progress tracking counters
        completed_count = 0
        progress_success_count = 0
        progress_failed_count = 0

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(self._test_single_host_concurrent, ip, country): i
                for i, ip in enumerate(ip_list)
            }

            # Collect results as they complete
            for future in future_to_index:
                index = future_to_index[future]
                ip = ip_list[index]

                try:
                    result_data = future.result()
                    results_by_index[index] = result_data

                    # Handle error results
                    if "error" in result_data:
                        self.output.error(f"Authentication failed for {result_data['ip']}: {result_data['error']}")

                except Exception as e:
                    # Future itself failed
                    error_result = {
                        "ip": ip,
                        "error": str(e),
                        "success": False,
                        "failed": True,
                        "result": None
                    }
                    results_by_index[index] = error_result
                    self.output.error(f"Authentication failed for {ip}: {e}")

                # Update progress counters
                completed_count += 1
                if index < len(results_by_index) and results_by_index[index] and results_by_index[index].get("success"):
                    progress_success_count += 1
                else:
                    progress_failed_count += 1

                # Show progress every 25 completions or at significant milestones
                if completed_count % 25 == 0 or completed_count == 1 or completed_count == total_hosts:
                    progress_pct = (completed_count / total_hosts) * 100
                    success_percent = int((progress_success_count / completed_count) * 100) if completed_count else 0
                    self.output.info(
                        f"📊 Progress: {completed_count}/{total_hosts} ({progress_pct:.1f}%) | "
                        f"Success: {progress_success_count}, Failed: {progress_failed_count} ({success_percent}%)"
                    )

        # Process results in original order and aggregate statistics
        success_count = 0
        failed_count = 0

        for i, result_data in enumerate(results_by_index):
            if result_data and result_data["success"] and result_data["result"]:
                successful_hosts.append(result_data["result"])
                success_count += 1
                self.output.print_if_verbose(f"  ✓ {ip_list[i]}: {result_data['result']['auth_method']}")
            else:
                failed_count += 1

        # Update statistics once after processing all results
        self.stats['successful_auth'] = success_count
        self.stats['failed_auth'] = failed_count
        self.stats['total_processed'] = total_hosts

        # Post-processing progress report with final counts
        success_percent = int((success_count / total_hosts) * 100) if total_hosts else 0
        self.output.info(
            f"📊 Authentication complete: {total_hosts} hosts | "
            f"Success: {success_count}, Failed: {failed_count} ({success_percent}%)"
        )

        return successful_hosts

    def _test_smb_authentication_sequential(self, ip_list: List[str], country=None) -> List[Dict]:
        """
        Sequential SMB authentication testing (preserved original behavior for max_concurrent_hosts=1).

        Args:
            ip_list: List of IP addresses to test
            country: Country code for metadata

        Returns:
            List of successful authentication results
        """
        successful_hosts = []
        total_hosts = len(ip_list)

        for i, ip in enumerate(ip_list, 1):
            # Show progress every 25 hosts or at significant milestones
            if i % 25 == 0 or i == 1 or i == total_hosts:
                progress_pct = (i / total_hosts) * 100
                success_count = len(successful_hosts)
                failed_count = i - 1 - success_count
                processed = success_count + failed_count
                success_percent = int((success_count / processed) * 100) if processed else 0
                self.output.info(
                    f"📊 Progress: {i}/{total_hosts} ({progress_pct:.1f}%) | "
                    f"Success: {success_count}, Failed: {failed_count} ({success_percent}%)"
                )

            self.output.print_if_verbose(f"[{i}/{total_hosts}] Testing {ip}...")

            result = self._test_single_host(ip, country)
            if result:
                successful_hosts.append(result)
                self.output.print_if_verbose(f"  ✓ {ip}: {result['auth_method']}")

            # Rate limiting between hosts (original behavior)
            if i < total_hosts:
                time.sleep(self.config.get_rate_limit_delay())

        # Update statistics
        self.stats['successful_auth'] = len(successful_hosts)
        self.stats['failed_auth'] = total_hosts - len(successful_hosts)
        self.stats['total_processed'] = total_hosts

        return successful_hosts
    
    def _test_single_host(self, ip: str, country=None) -> Optional[Dict]:
        """
        Test SMB authentication on a single host.

        Args:
            ip: IP address to test
            country: Country code for metadata

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
                # Use metadata lookup with CLI fallback
                metadata = self.shodan_host_metadata.get(ip, {})
                country_name = metadata.get('country_name') or country or 'Unknown'
                country_code = metadata.get('country_code')

                return {
                    'ip_address': ip,
                    'country': country_name,
                    'country_code': country_code,
                    'auth_method': method_name,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'accessible'
                }
        
        # If smbprotocol fails, try smbclient fallback
        if self.smbclient_available:
            fallback_result = self._test_smb_alternative(ip)
            if fallback_result:
                # Use metadata lookup with CLI fallback (same as above)
                metadata = self.shodan_host_metadata.get(ip, {})
                country_name = metadata.get('country_name') or country or 'Unknown'
                country_code = metadata.get('country_code')

                return {
                    'ip_address': ip,
                    'country': country_name,
                    'country_code': country_code,
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
        Test SMB authentication with security hardening based on risky_mode.

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

        # Determine security settings based on risky_mode
        require_signing = not self.risky_mode
        require_encryption = False  # Never require encryption to avoid false negatives
        dialects = None

        # Try to set SMB dialect restrictions in safe mode
        if not self.risky_mode:
            try:
                from smbprotocol.connection import Dialect
                # Include SMB2+ (not just SMB3) - SMB2.0/2.1 still benefit from signing
                dialects = [Dialect.SMB_2_0_2, Dialect.SMB_2_1, Dialect.SMB_3_0_2, Dialect.SMB_3_1_1]
            except ImportError:
                dialects = None
                self.output.print_if_verbose("SMB dialect restriction unavailable - using library defaults with signing")

        try:
            # Suppress stderr output
            stderr_buffer = StringIO()
            with redirect_stderr(stderr_buffer):
                # Create connection with security settings
                try:
                    connection = Connection(conn_uuid, ip, 445, require_signing=require_signing, dialects=dialects)
                except TypeError:
                    # Fallback for older smbprotocol versions that don't support dialects parameter
                    connection = Connection(conn_uuid, ip, 445, require_signing=require_signing)
                    if not self.risky_mode:
                        self.output.print_if_verbose("SMB dialect restriction not supported by library - enforcing signing only")

                connection.connect(timeout=self.config.get_connection_timeout())

                # Create session
                session = Session(
                    connection,
                    username=username,
                    password=password,
                    require_encryption=require_encryption,
                    auth_protocol="ntlm"
                )
                session.connect()

                return True

        except SMBException as e:
            # In safe mode, provide actionable error messages for rejected connections
            if not self.risky_mode:
                error_msg = str(e).lower()
                if 'signing' in error_msg or 'unsigned' in error_msg:
                    self.output.print_if_verbose(f"Host {ip} requires unsigned SMB; rerun with --risky if you accept that risk")
                elif 'smb' in error_msg and ('version' in error_msg or 'dialect' in error_msg):
                    self.output.print_if_verbose(f"Host {ip} requires SMB1 or unsupported protocol; rerun with --risky if you accept that risk")
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
        Alternative testing method using smbclient as fallback with caching.

        Args:
            ip: IP address to test

        Returns:
            Authentication method name if successful, None otherwise
        """
        if not self.smbclient_available:
            return None

        # Check cache first
        if ip in self._smbclient_auth_cache:
            return self._smbclient_auth_cache[ip]

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
                        # Cache successful result
                        self._smbclient_auth_cache[ip] = method_name
                        return method_name
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
            except Exception:
                continue

        # Cache failed result to prevent retries
        self._smbclient_auth_cache[ip] = None
        return None
    
    
    def _save_to_database(self, successful_hosts: List[Dict], country=None) -> Set[str]:
        """
        Save successful authentication results to database using provided session_id.

        Args:
            successful_hosts: List of successful results to save
            country: Country code for metadata

        Returns:
            Set of authenticated IP addresses
        """
        try:
            # Save individual host results using the workflow's session_id
            from db_manager import SMBSeekDataAccessLayer
            dal = SMBSeekDataAccessLayer(self.database.db_manager)

            authenticated_ips = set()
            for host in successful_hosts:
                server_id = dal.get_or_create_server(
                    ip_address=host['ip_address'],
                    country=host['country'],
                    auth_method=host['auth_method'],
                    country_code=host.get('country_code')
                )
                authenticated_ips.add(host['ip_address'])

            self.output.print_if_verbose(f"Saved {len(successful_hosts)} authenticated hosts to database")
            return authenticated_ips

        except Exception as e:
            self.output.error(f"Failed to save results to database: {e}")
            return set()


# Compatibility layer for old DiscoverCommand interface
class DiscoverCommand:
    """
    DEPRECATED: Legacy compatibility wrapper for DiscoverOperation.
    Use workflow.UnifiedWorkflow or DiscoverOperation directly.
    """

    def __init__(self, args):
        """
        Initialize legacy discover command.

        Args:
            args: Parsed command line arguments
        """
        import warnings
        warnings.warn("DiscoverCommand is deprecated, use DiscoverOperation or UnifiedWorkflow",
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
        self.database = create_workflow_database(self.config)

    def execute(self) -> int:
        """
        Execute the legacy discover command.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Create a session for backward compatibility
            session_data = {
                'tool_name': 'smbseek-discover-legacy',
                'config_snapshot': '{}',
                'status': 'running'
            }
            session_id = self.database.dal.create_session(session_data)

            # Create and execute the operation
            operation = DiscoverOperation(
                self.config,
                self.output,
                self.database,
                session_id
            )

            result = operation.execute(
                country=getattr(self.args, 'country', None),
                rescan_all=getattr(self.args, 'rescan_all', False),
                rescan_failed=getattr(self.args, 'rescan_failed', False),
                force_hosts=getattr(self.args, 'force_hosts', set())
            )

            # Update session
            self.database.dal.update_session(session_id, {
                'status': 'completed',
                'total_targets': result.total_hosts,
                'successful_targets': result.authenticated_hosts
            })

            # Display legacy-style results
            self.output.subheader("Discovery Results")
            self.output.print_if_not_quiet(f"Hosts Tested: {result.total_hosts}")
            self.output.print_if_not_quiet(f"Successful Auth: {result.authenticated_hosts}")

            if result.authenticated_hosts > 0:
                self.output.success(f"Found {result.authenticated_hosts} accessible SMB servers")
            else:
                self.output.warning("No accessible SMB servers found")

            return 0

        except Exception as e:
            self.output.error(f"Discovery failed: {e}")
            if getattr(self.args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1

        finally:
            if hasattr(self.database, 'close'):
                self.database.close()
