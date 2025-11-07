"""
SMBSeek Run Command - DEPRECATED

This command has been deprecated in SMBSeek 3.0.0.
The run workflow has been integrated into the main command.

Use the main SMBSeek command:
    ./smbseek.py --country US
"""

import warnings
import sys
import os

# Add project root to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class WorkflowOrchestrator:
    """
    DEPRECATED: Legacy compatibility wrapper for UnifiedWorkflow.
    Use main smbseek.py command or workflow.UnifiedWorkflow directly.
    """

    def __init__(self, args):
        """
        Initialize legacy workflow orchestrator.

        Args:
            args: Parsed command line arguments
        """
        warnings.warn("WorkflowOrchestrator is deprecated, use main smbseek.py command",
                      DeprecationWarning, stacklevel=2)

        self.args = args

        # Load configuration and components for backward compatibility
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

        # Import and initialize the new workflow
        from workflow import UnifiedWorkflow
        self.workflow = UnifiedWorkflow(
            self.config,
            self.output,
            self.database,
            getattr(args, 'cautious', False),
            getattr(args, 'enable_smb1', False)
        )

    def execute(self):
        """
        Execute the legacy workflow orchestrator.

        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            # Convert old args to new format and delegate to UnifiedWorkflow
            summary = self.workflow.run(self.args)

            # Display summary using the output manager
            self.output.print_rollup_summary(summary)

            return 0

        except Exception as e:
            self.output.error(f"Workflow failed: {e}")
            if getattr(self.args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1

        finally:
            if hasattr(self.database, 'close'):
                self.database.close()


def main():
    """Main entry point for deprecated run command."""
    print("⚠️  DEPRECATED: run command is no longer supported as a standalone script.")
    print("   Use: ./smbseek.py --country US")
    print("   The run workflow has been integrated into the main command.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
