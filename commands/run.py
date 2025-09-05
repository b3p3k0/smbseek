"""
SMBSeek Run Command - Workflow Orchestration

Implements the primary workflow: discover → access → collect → report
Provides intelligent host filtering, pause points, and comprehensive automation.
"""

import sys
import os
from typing import Set, Dict, Any, Optional

# Add project root to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager, create_reporter


class WorkflowOrchestrator:
    """
    Orchestrates the complete SMBSeek security assessment workflow.
    
    Implements the full discover → access → collect → report pipeline
    with intelligent host filtering and optional pause points.
    """
    
    def __init__(self, args):
        """
        Initialize workflow orchestrator.
        
        Args:
            args: Parsed command line arguments
        """
        self.args = args
        
        # Load configuration
        self.config = load_config(args.config)
        
        # Initialize shared components
        self.output = create_output_manager(
            self.config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )
        
        self.database = create_workflow_database(self.config)
        self.reporter = create_reporter(self.database, self.output)
        
        # Workflow state
        self.session_id = None
        self.discovered_hosts = set()
        self.authenticated_hosts = set()
        self.accessible_shares = []
        self.enumerated_files = []
        
        # Workflow configuration
        self.pause_between_steps = (
            args.pause_between_steps or 
            self.config.get("workflow", "pause_between_steps", False)
        )
    
    def execute(self) -> int:
        """
        Execute the complete workflow.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Validate configuration
            if not self.config.validate_configuration():
                self.output.error("Configuration validation failed")
                return 1
            
            # Show database status
            self.database.show_database_status()
            
            # Execute workflow steps
            self.output.header("SMBSeek Security Assessment Workflow")
            
            # Step 1: Discovery
            if not self._execute_discovery():
                return 1
            
            if self.pause_between_steps and not self._confirm_continue("Continue with access verification?"):
                self.output.info("Workflow stopped after discovery step")
                return 0
            
            # Step 2: Access verification
            if not self._execute_access_verification():
                return 1
            
            if self.pause_between_steps and not self._confirm_continue("Continue with file collection?"):
                self.output.info("Workflow stopped after access verification")
                return 0
            
            # Step 3: File collection
            if not self._execute_file_collection():
                return 1
            
            if self.pause_between_steps and not self._confirm_continue("Continue with report generation?"):
                self.output.info("Workflow stopped after file collection")
                return 0
            
            # Step 4: Report generation
            if not self._execute_reporting():
                return 1
            
            # Workflow completion
            self._complete_workflow()
            return 0
        
        except KeyboardInterrupt:
            self.output.warning("Workflow interrupted by user")
            return 130
        except Exception as e:
            self.output.error(f"Workflow failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            # Cleanup
            self.database.close()
    
    def _execute_discovery(self) -> bool:
        """
        Execute Step 1: Discovery and authentication testing.
        
        Returns:
            True if successful, False otherwise
        """
        self.output.workflow_step("Discovery & Authentication", 1, 4)
        
        try:
            # Import and execute discovery
            from commands.discover import DiscoverCommand
            
            # Create discovery args from workflow args
            discover_args = type('Args', (), {
                'country': self.args.country,
                'rescan_all': getattr(self.args, 'rescan_all', False),
                'rescan_failed': getattr(self.args, 'rescan_failed', False),
                'config': self.args.config,
                'quiet': self.args.quiet,
                'verbose': self.args.verbose,
                'no_colors': self.args.no_colors
            })()
            
            discover_command = DiscoverCommand(discover_args)
            result = discover_command.execute()
            
            if result != 0:
                self.output.error("Discovery step failed")
                return False
            
            # Get discovered hosts from database
            self.discovered_hosts = self._get_recent_discoveries()
            self.output.success(f"Discovery completed: {len(self.discovered_hosts)} hosts discovered")
            
            return True
        
        except Exception as e:
            self.output.error(f"Discovery step failed: {e}")
            return False
    
    def _execute_access_verification(self) -> bool:
        """
        Execute Step 2: Share access verification.
        
        Returns:
            True if successful, False otherwise
        """
        self.output.workflow_step("Share Access Verification", 2, 4)
        
        if not self.discovered_hosts:
            self.output.warning("No hosts from discovery step - skipping access verification")
            return True
        
        try:
            # Import and execute access verification
            from commands.access import AccessCommand
            
            # Create access args with intelligent recent filtering
            # Use a reasonable time window that balances efficiency with thoroughness
            access_recent_hours = self.config.get("workflow", "access_recent_hours", 2)
            
            access_args = type('Args', (), {
                'servers': None,  # Use recent discoveries
                'recent': access_recent_hours,  # Configurable recent window
                'config': self.args.config,
                'quiet': self.args.quiet,
                'verbose': self.args.verbose,
                'no_colors': self.args.no_colors
            })()
            
            access_command = AccessCommand(access_args)
            result = access_command.execute()
            
            if result != 0:
                self.output.error("Access verification step failed")
                return False
            
            # Get accessible shares from database
            self.accessible_shares = self._get_recent_accessible_shares()
            self.output.success(f"Access verification completed: {len(self.accessible_shares)} accessible shares found")
            
            return True
        
        except Exception as e:
            self.output.error(f"Access verification step failed: {e}")
            return False
    
    def _execute_file_collection(self) -> bool:
        """
        Execute Step 3: File enumeration and collection.
        
        Returns:
            True if successful, False otherwise
        """
        self.output.workflow_step("File Enumeration & Collection", 3, 4)
        
        if not self.accessible_shares:
            self.output.warning("No accessible shares found - skipping file collection")
            return True
        
        try:
            # Import and execute file collection
            from commands.collect import CollectCommand
            
            # Create collect args
            collect_args = type('Args', (), {
                'download': getattr(self.args, 'download', False),
                'max_files': getattr(self.args, 'max_files', None),
                'servers': None,  # Use recent discoveries
                'config': self.args.config,
                'quiet': self.args.quiet,
                'verbose': self.args.verbose,
                'no_colors': self.args.no_colors
            })()
            
            collect_command = CollectCommand(collect_args)
            result = collect_command.execute()
            
            if result != 0:
                self.output.error("File collection step failed")
                return False
            
            # Get enumerated files from database
            self.enumerated_files = self._get_recent_file_manifests()
            self.output.success(f"File collection completed: {len(self.enumerated_files)} files enumerated")
            
            return True
        
        except Exception as e:
            self.output.error(f"File collection step failed: {e}")
            return False
    
    def _execute_reporting(self) -> bool:
        """
        Execute Step 4: Report generation.
        
        Returns:
            True if successful, False otherwise
        """
        self.output.workflow_step("Intelligence Reporting", 4, 4)
        
        try:
            # Generate executive summary
            summary = self.reporter.generate_executive_summary(self.session_id)
            
            # Display summary
            self.reporter.print_executive_summary(summary)
            
            # Save detailed report if requested or if significant findings
            if (summary.get('summary', {}).get('accessible_servers', 0) > 0 or
                summary.get('summary', {}).get('total_files_enumerated', 0) > 0):
                
                filename = self.reporter.save_detailed_report(summary)
                if filename:
                    self.output.info(f"Detailed findings saved to: {filename}")
            
            return True
        
        except Exception as e:
            self.output.error(f"Reporting step failed: {e}")
            return False
    
    def _complete_workflow(self):
        """Complete the workflow and display final summary."""
        self.output.workflow_complete("SMBSeek security assessment completed successfully!")
        
        # Display final statistics
        total_hosts = len(self.discovered_hosts)
        total_shares = len(self.accessible_shares)
        total_files = len(self.enumerated_files)
        
        self.output.info(f"Final Summary:")
        self.output.print_if_not_quiet(f"  • Hosts Discovered: {total_hosts}")
        self.output.print_if_not_quiet(f"  • Accessible Shares: {total_shares}")
        self.output.print_if_not_quiet(f"  • Files Enumerated: {total_files}")
        
        # Show recent activity
        activity = self.database.get_recent_activity_summary(1)  # Last 24 hours
        if activity['scan_sessions'] > 0:
            self.output.info(f"Recent Activity (24h): {activity['scan_sessions']} sessions, {activity['updated_servers']} servers updated")
    
    def _confirm_continue(self, message: str) -> bool:
        """
        Ask user for confirmation to continue workflow.
        
        Args:
            message: Confirmation message to display
            
        Returns:
            True if user wants to continue, False otherwise
        """
        if self.args.quiet:
            return True  # Auto-continue in quiet mode
        
        try:
            response = input(f"\n{self.output.YELLOW}⏸  {message} [Y/n]: {self.output.RESET}").strip().lower()
            return response in ('', 'y', 'yes')
        except (EOFError, KeyboardInterrupt):
            return False
    
    def _get_recent_discoveries(self) -> Set[str]:
        """Get recently discovered hosts from database."""
        try:
            # Get hosts discovered in the last hour
            query = """
                SELECT DISTINCT ip_address 
                FROM smb_servers 
                WHERE last_seen >= datetime('now', '-1 hour')
            """
            results = self.database.db_manager.execute_query(query)
            return {row['ip_address'] for row in results}
        except Exception:
            return set()
    
    def _get_recent_accessible_shares(self) -> list:
        """Get recently discovered accessible shares."""
        try:
            query = """
                SELECT DISTINCT s.ip_address, sa.share_name
                FROM smb_servers s
                JOIN share_access sa ON s.id = sa.server_id
                WHERE sa.accessible = 1 
                AND sa.timestamp >= datetime('now', '-1 hour')
            """
            results = self.database.db_manager.execute_query(query)
            return [{'ip': row['ip_address'], 'share': row['share_name']} for row in results]
        except Exception:
            return []
    
    def _get_recent_file_manifests(self) -> list:
        """Get recently enumerated files."""
        try:
            query = """
                SELECT COUNT(*) as file_count
                FROM file_manifests 
                WHERE timestamp >= datetime('now', '-1 hour')
            """
            results = self.database.db_manager.execute_query(query)
            return results[0]['file_count'] if results else 0
        except Exception:
            return 0