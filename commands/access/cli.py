"""
Legacy CLI wrapper for access operation (deprecated).
"""

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager

from .operation import AccessOperation


class AccessCommand:
    """
    DEPRECATED: Legacy compatibility wrapper for AccessOperation.
    Use workflow.UnifiedWorkflow or AccessOperation directly.
    """

    def __init__(self, args):
        import warnings
        warnings.warn("AccessCommand is deprecated, use AccessOperation or UnifiedWorkflow",
                      DeprecationWarning, stacklevel=2)

        self.args = args

        self.config = load_config(args.config)
        self.output = create_output_manager(
            self.config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )
        self.database = create_workflow_database(self.config, args.verbose)

    def execute(self) -> int:
        try:
            session_data = {
                'tool_name': 'smbseek-access-legacy',
                'config_snapshot': '{}',
                'status': 'running'
            }
            session_id = self.database.dal.create_session(session_data)

            if hasattr(self.args, 'servers') and self.args.servers:
                target_ips = set(ip.strip() for ip in self.args.servers.split(','))
            else:
                authenticated_hosts = self.database.get_authenticated_hosts(
                    recent_hours=getattr(self.args, 'recent', None)
                )
                target_ips = set(host['ip_address'] for host in authenticated_hosts)

            if not target_ips:
                self.output.warning("No authenticated hosts found in database")
                self.output.info("Run discovery first")
                return 0

            operation = AccessOperation(
                self.config,
                self.output,
                self.database,
                session_id
            )

            result = operation.execute(
                target_ips=target_ips,
                recent_hours=getattr(self.args, 'recent', None)
            )

            self.database.dal.update_session(session_id, {
                'status': 'completed',
                'total_targets': len(target_ips),
                'successful_targets': result.accessible_hosts
            })

            self.output.subheader("Access Verification Results")
            self.output.print_if_not_quiet(f"Hosts Tested: {len(target_ips)}")
            self.output.print_if_not_quiet(f"Accessible Hosts: {result.accessible_hosts}")
            self.output.print_if_not_quiet(f"Accessible Shares: {result.accessible_shares}")

            if result.accessible_shares > 0:
                self.output.success(f"Found {result.accessible_shares} accessible shares on {result.accessible_hosts} hosts")
            else:
                self.output.warning("No accessible shares found")

            return 0

        except Exception as e:
            self.output.error(f"Access verification failed: {e}")
            if getattr(self.args, 'verbose', False):
                import traceback
                traceback.print_exc()
            return 1

        finally:
            if hasattr(self.database, 'close'):
                self.database.close()
