"""
SMBSeek Report Command

Intelligence reporting functionality for the unified CLI.
Generates executive summaries and detailed security assessment reports.
"""

import sys
import os

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager, create_reporter


class ReportCommand:
    """
    SMB intelligence reporting command.
    
    Generates executive summaries and detailed security assessment reports.
    """
    
    def __init__(self, args):
        """
        Initialize report command.
        
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
        self.reporter = create_reporter(self.database, self.output)
    
    def execute(self) -> int:
        """
        Execute the report command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            self.output.header("SMB Security Assessment Report")
            
            # Generate executive summary
            session_id = getattr(self.args, 'session', None)
            summary = self.reporter.generate_executive_summary(session_id)
            
            # Display summary
            self.reporter.print_executive_summary(summary)
            
            # Save detailed report if requested
            if getattr(self.args, 'output', None):
                filename = self.reporter.save_detailed_report(summary, self.args.output)
                if filename:
                    self.output.success(f"Detailed report saved: {filename}")
            elif getattr(self.args, 'detailed', False):
                filename = self.reporter.save_detailed_report(summary)
                if filename:
                    self.output.info(f"Detailed report saved: {filename}")
            
            return 0
        
        except Exception as e:
            self.output.error(f"Report generation failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()