"""
Legacy CLI wrapper for discover operation (deprecated).
"""

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager

from .operation import DiscoverOperation


class DiscoverCommand:
    """
    DEPRECATED: Legacy compatibility wrapper for DiscoverOperation.
    Use workflow.UnifiedWorkflow or DiscoverOperation directly.
    """

    def __init__(self, args):
        import warnings
        warnings.warn(
            "DiscoverCommand is deprecated, use DiscoverOperation or UnifiedWorkflow",
            DeprecationWarning,
            stacklevel=2
        )

        self.args = args

        self.config = load_config(args.config)
        self.output = create_output_manager(
            self.config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )
        self.database = create_workflow_database(self.config)

    def execute(self) -> int:
        try:
            session_data = {
                'tool_name': 'smbseek-discover-legacy',
                'config_snapshot': '{}',
                'status': 'running'
            }
            session_id = self.database.dal.create_session(session_data)

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

            self.database.dal.update_session(session_id, {
                'status': 'completed',
                'total_targets': result.total_hosts,
                'successful_targets': result.authenticated_hosts
            })

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
