"""
SMBSeek Collect Command

File enumeration and collection functionality adapted for the unified CLI.
Enumerates files on accessible shares with ransomware detection.
"""

import subprocess
import json
import time
import sys
import os
from datetime import datetime
from pathlib import Path

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager


class CollectCommand:
    """
    SMB file enumeration and collection command.
    
    Enumerates and optionally collects files from accessible SMB shares.
    """
    
    def __init__(self, args):
        """
        Initialize collect command.
        
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
        
        # Collection statistics
        self.total_servers = 0
        self.current_server = 0
        self.total_files_downloaded = 0
        self.total_bytes_downloaded = 0
        self.collection_directories = []
        self.download_manifest = []
        
        # File extension filters from config
        file_config = self.config.get_file_collection_config()
        self.included_extensions = [ext.lower() for ext in file_config.get("included_extensions", [])]
        self.excluded_extensions = [ext.lower() for ext in file_config.get("excluded_extensions", [])]
        
        # Configuration for enumeration
        self.max_depth = file_config.get("max_directory_depth", 3)
        self.enum_timeout = file_config.get("enumeration_timeout_seconds", 120)
        
        # Security configuration for ransomware detection
        security_config = self.config.get_security_config()
        self.ransomware_indicators = [indicator.lower() for indicator in security_config.get("ransomware_indicators", [])]
    
    def execute(self) -> int:
        """
        Execute the collect command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            self.output.header("SMB File Enumeration & Collection")
            
            # Get accessible shares from database
            accessible_hosts = self.database.get_hosts_with_accessible_shares()
            if not accessible_hosts:
                self.output.warning("No hosts with accessible shares found in database")
                self.output.info("Run access verification first: smbseek access")
                return 0
            
            self.total_servers = len(accessible_hosts)
            self.output.info(f"Processing {self.total_servers} hosts with accessible shares")
            self.output.info(f"Max directory depth: {self.max_depth} levels")
            self.output.info(f"Enumeration timeout: {self.enum_timeout}s")
            
            # Phase 1: Generate file manifest
            self.output.info("Generating file manifest...")
            
            collection_plan = []
            total_files_planned = 0
            total_size_planned = 0
            
            for host in accessible_hosts:
                self.current_server += 1
                ip = host['ip_address']
                
                self.output.info(f"Server {self.current_server}/{self.total_servers} - {ip}")
                
                target_dir, selected_files, target_size, compromised = self.collect_files_from_target(host)
                
                if compromised or selected_files:
                    collection_plan.append({
                        'target': host,
                        'directory': target_dir,
                        'files': selected_files,
                        'total_size': target_size,
                        'compromised': compromised
                    })
                    
                    if not compromised:
                        total_files_planned += len(selected_files)
                        total_size_planned += target_size
                        
                        size_mb = target_size / (1024 * 1024)
                        self.output.success(f"{len(selected_files)} files ({size_mb:.1f}MB) planned for collection")
                else:
                    self.output.warning("No eligible files found")
            
            # Generate and save manifest
            self.save_manifest(collection_plan, total_files_planned, total_size_planned)
            
            # Generate human-readable report if requested
            if getattr(self.args, 'detailed', False):
                self.generate_human_readable_report(collection_plan, total_files_planned, total_size_planned)
            
            # Stop here if downloads not requested
            if not getattr(self.args, 'download', False):
                total_size_mb = total_size_planned / (1024 * 1024) if total_size_planned > 0 else 0
                self.output.success("File manifest generated successfully")
                self.output.info(f"Servers: {len(collection_plan)}")
                self.output.info(f"Files: {total_files_planned}")
                self.output.info(f"Total Size: {total_size_mb:.1f}MB")
                self.output.info("Use --download flag to download files")
                return 0
            
            # Phase 2: File Downloads (if requested)
            if collection_plan:
                self.execute_downloads(collection_plan, total_files_planned, total_size_planned)
            
            return 0
        
        except Exception as e:
            self.output.error(f"File collection failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()
    
    def parse_auth_method(self, auth_method_str):
        """Parse authentication method string into username/password tuple."""
        auth_lower = auth_method_str.lower()
        if 'anonymous' in auth_lower:
            return "", ""
        elif 'guest/blank' in auth_lower or 'guest/' in auth_lower:
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
        compromised = False
        
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
            
            if self.args.verbose:
                self.output.debug(f"Listing files on {share_name}")
            
            # Run command with configurable timeout
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=self.enum_timeout, stdin=subprocess.DEVNULL)
            
            if result.returncode != 0:
                if self.args.verbose:
                    self.output.warning(f"smbclient error: {result.stderr.strip()}")
                return files, compromised
            
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
                            if self.args.verbose:
                                self.output.warning(f"Skipping depth {depth} directory: {current_dir}")
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
                            filename = parts[0]
                            
                            # Skip if this looks like a directory or special entry
                            if filename in ['.', '..'] or filename.endswith('/'):
                                continue
                            
                            # Check for ransomware indicators (case-insensitive)
                            filename_lower = filename.lower()
                            for indicator in self.ransomware_indicators:
                                if indicator in filename_lower:
                                    compromised = True
                                    self.output.warning("Potentially compromised host; stopping.")
                                    return files, compromised
                            
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
            if self.args.verbose:
                self.output.warning(f"Timeout listing files on {share_name}")
        except Exception as e:
            if self.args.verbose:
                self.output.warning(f"Error listing files on {share_name}: {e}")
            
        return files, compromised
    
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
                if self.args.verbose:
                    self.output.warning(f"smbclient download error: {result.stderr.strip()}")
                return False
                
        except subprocess.TimeoutExpired:
            if self.args.verbose:
                self.output.warning(f"Timeout downloading {remote_path}")
            return False
        except Exception as e:
            if self.args.verbose:
                self.output.warning(f"Error downloading {remote_path}: {e}")
            return False
    
    def collect_files_from_target(self, host_data):
        """Collect files from a single target host."""
        ip = host_data['ip_address']
        country = host_data.get('country', 'Unknown')
        auth_method = host_data['auth_method']
        accessible_shares = host_data.get('accessible_shares', [])
        
        # Create directory for this IP
        date_str = datetime.now().strftime("%Y%m%d")
        target_dir = f"{date_str}-{ip}"
        
        if not accessible_shares:
            if self.args.verbose:
                self.output.warning(f"No accessible shares for {ip}")
            return target_dir, [], 0, False
            
        # Parse authentication method
        username, password = self.parse_auth_method(auth_method)
        
        # Collection limits per target
        file_config = self.config.get_file_collection_config()
        max_files = file_config.get("max_files_per_target", 3)
        max_size_bytes = file_config.get("max_total_size_mb", 500) * 1024 * 1024
        
        # Collect all files from all accessible shares
        all_files = []
        compromised = False
        
        for i, share_name in enumerate(accessible_shares, 1):
            self.output.info(f"Scanning share {i}/{len(accessible_shares)}: {share_name}...")
            
            try:
                share_files, share_compromised = self.get_directory_listing(ip, share_name, username, password, max_files, max_size_bytes)
                
                # Check if this share is compromised
                if share_compromised:
                    compromised = True
                    # Return immediately with what we've collected so far
                    return target_dir, all_files, sum(f['size'] for f in all_files), compromised
                
                # Add share name to each file (filtering already done in get_directory_listing)
                for file_info in share_files:
                    file_info['share_name'] = share_name
                    all_files.append(file_info)
                        
                self.output.success(f"Scanned share {i}/{len(accessible_shares)}: {share_name} - {len(share_files)} files found")
                
            except Exception as e:
                self.output.error(f"Error scanning share {i}/{len(accessible_shares)}: {share_name} - {str(e)[:30]}")
                
        if not all_files:
            if self.args.verbose:
                self.output.warning(f"No eligible files found on {ip}")
            return target_dir, [], 0, compromised
            
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
            
        return target_dir, selected_files, total_size, compromised
    
    def execute_downloads(self, collection_plan, total_files, total_size):
        """Execute file downloads based on collection plan."""
        total_size_mb = total_size / (1024 * 1024)
        self.output.info(f"Download Summary:")
        self.output.info(f"  Servers: {len(collection_plan)}")
        self.output.info(f"  Files: {total_files}")
        self.output.info(f"  Total Size: {total_size_mb:.1f}MB")
        
        # Confirmation prompt (unless auto-download is enabled)
        if not getattr(self.args, 'auto', False):
            response = input(f"\nWill download {total_files} files ({total_size_mb:.1f}MB total). Continue? [Y/n]: ")
            if response.lower().strip() in ['n', 'no']:
                self.output.warning("Download cancelled by user")
                return
        
        # Execute downloads
        self.output.info("Starting file downloads...")
        
        file_config = self.config.get_file_collection_config()
        download_delay = file_config.get("download_delay_seconds", 2)
        
        server_count = 0
        for plan in collection_plan:
            server_count += 1
            target = plan['target']
            ip = target['ip_address']
            target_dir = plan['directory']
            files_to_download = plan['files']
            compromised = plan.get('compromised', False)
            
            self.output.info(f"Server {server_count}/{len(collection_plan)} - {ip}")
            
            # Skip downloads for compromised hosts
            if compromised:
                self.output.warning("Skipping downloads from compromised host")
                continue
            
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
                self.output.info(f"File {file_count}/{len(files_to_download)}: {original_filename}...")
                
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
                    
                    self.output.success(f"File {file_count}/{len(files_to_download)}: {original_filename} - downloaded")
                else:
                    self.output.error(f"File {file_count}/{len(files_to_download)}: {original_filename} - failed")
                
                # Rate limiting between downloads
                if file_count < len(files_to_download):
                    time.sleep(download_delay)
                    
            self.output.success(f"Downloaded {downloaded_count}/{len(files_to_download)} files from {ip}")
        
        # Final summary
        self.print_download_summary()
    
    def save_manifest(self, collection_plan, total_files, total_size):
        """Save file manifest to JSON file."""
        manifest_file = f"file_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Build manifest structure
        file_config = self.config.get_file_collection_config()
        manifest_data = {
            'metadata': {
                'tool': 'smbseek_collect',
                'manifest_date': datetime.now().isoformat(),
                'total_servers': len(collection_plan),
                'total_files': total_files,
                'total_size_bytes': total_size,
                'config': {
                    'max_directory_depth': self.max_depth,
                    'enumeration_timeout_seconds': self.enum_timeout,
                    'max_files_per_target': file_config.get("max_files_per_target", 3),
                    'max_total_size_mb': file_config.get("max_total_size_mb", 500)
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
                'compromised': plan.get('compromised', False),
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
            self.output.success(f"Manifest saved: {manifest_file}")
        except Exception as e:
            self.output.error(f"Error saving manifest: {e}")
    
    def print_download_summary(self):
        """Print final download summary."""
        total_size_mb = self.total_bytes_downloaded / (1024 * 1024)
        
        self.output.header("Download Complete")
        self.output.info(f"Files Downloaded: {self.total_files_downloaded}")
        self.output.info(f"Total Size: {total_size_mb:.1f}MB")
        self.output.info(f"Directories Created: {len(self.collection_directories)}")
        
        if self.collection_directories:
            self.output.info("Collection Directories:")
            for directory in self.collection_directories:
                self.output.info(f"  {directory}")
        
        # Save download manifest
        if self.download_manifest:
            manifest_file = f"download_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            manifest_data = {
                'metadata': {
                    'tool': 'smbseek_collect',
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
                    
                self.output.success(f"Download manifest saved: {manifest_file}")
                
            except Exception as e:
                self.output.error(f"Error saving download manifest: {e}")
    
    def generate_human_readable_report(self, collection_plan, total_files, total_size):
        """Generate human-readable collection report."""
        report_file = f"collection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        def format_file_size(size_bytes):
            """Convert bytes to human-readable size format."""
            if size_bytes == 0:
                return "0B"
            
            size_names = ["B", "KB", "MB", "GB", "TB"]
            i = 0
            while size_bytes >= 1024 and i < len(size_names) - 1:
                size_bytes /= 1024.0
                i += 1
            
            if i == 0:
                return f"{int(size_bytes)}{size_names[i]}"
            else:
                return f"{size_bytes:.1f}{size_names[i]}"
        
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                # Header (Markdown format)
                f.write("# SMB File Collection Report\\n\\n")
                f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \\n")
                f.write(f"**Tool**: smbseek collect\\n\\n")
                
                # Summary
                f.write("## Collection Summary\\n\\n")
                f.write(f"Servers: {len(collection_plan)}\\n")
                f.write(f"Files: {total_files}\\n")
                f.write(f"Total Size: {format_file_size(total_size)}\\n\\n")
                
                if not collection_plan:
                    f.write("No files available for collection.\\n")
                    return
                
                # Server details
                f.write("## Server Details\\n\\n")
                
                for i, plan in enumerate(collection_plan, 1):
                    target = plan['target']
                    compromised = plan.get('compromised', False)
                    
                    # Server header with compromise indicator
                    if compromised:
                        compromise_text = " (POTENTIALLY COMPROMISED)"
                    else:
                        compromise_text = ""
                        
                    f.write(f"### SERVER {i}/{len(collection_plan)}: {target['ip_address']}{compromise_text}\\n\\n")
                    f.write(f"- **Country**: {target.get('country', 'Unknown')}\\n")
                    f.write(f"- **Authentication**: {target['auth_method']}\\n")
                    
                    if compromised:
                        f.write(f"- **Status**: POTENTIALLY COMPROMISED - Scanning stopped for security\\n")
                        f.write(f"- **Files**: {len(plan['files'])} (partial scan)\\n")
                    else:
                        f.write(f"- **Files**: {len(plan['files'])}\\n")
                        
                    f.write(f"- **Total Size**: {format_file_size(plan['total_size'])}\\n\\n")
                    
                    # Only show file details for non-compromised hosts
                    if not compromised and plan['files']:
                        # Group files by share
                        shares_data = {}
                        for file_info in plan['files']:
                            share = file_info.get('share_name', 'Unknown')
                            if share not in shares_data:
                                shares_data[share] = []
                            shares_data[share].append(file_info)
                        
                        # Display shares and files
                        for share_name, files_in_share in shares_data.items():
                            share_size = sum(f.get('size', 0) for f in files_in_share)
                            f.write(f"    └── {share_name} ({len(files_in_share)} files, {format_file_size(share_size)})\\n")
                            
                            # Files in share (show first few)
                            for j, file_info in enumerate(files_in_share[:5]):  # Show max 5 files
                                file_name = file_info.get('name', 'Unknown')
                                file_size = file_info.get('size', 0)
                                f.write(f"        ├── {file_name} ({format_file_size(file_size)})\\n")
                            
                            if len(files_in_share) > 5:
                                f.write(f"        └── ... and {len(files_in_share) - 5} more files\\n")
                    
                    elif compromised:
                        # Show compromise warning instead of file details
                        f.write(f"    └── [WARNING] Ransomware indicators detected - scan terminated\\n")
                    
                    # Add spacing between servers
                    if i < len(collection_plan):
                        f.write("\\n")
                
                # Footer
                f.write(f"\\n---\\n\\n")
                f.write("*Report generated by SMBSeek Toolkit*  \\n")
                f.write("*For security research and authorized testing only*\\n")
            
            self.output.success(f"Human-readable report saved: {report_file}")
            
        except Exception as e:
            self.output.error(f"Error generating human-readable report: {e}")