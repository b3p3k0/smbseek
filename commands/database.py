"""
SMBSeek Database Command

Database operations and maintenance functionality for the unified CLI.
Integrates existing database tools as subcommands.
"""

import sys
import os

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
tools_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')
sys.path.insert(0, tools_path)

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager


class DatabaseCommand:
    """
    SMB database operations command.
    
    Provides database querying, maintenance, and management operations.
    """
    
    def __init__(self, args):
        """
        Initialize database command.
        
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
    
    def execute(self) -> int:
        """
        Execute the database command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            action = getattr(self.args, 'db_action', None)
            
            if not action:
                self.output.error("No database action specified")
                self.output.info("Use: smbseek db --help for available operations")
                return 1
            
            if action == 'query':
                return self._execute_query()
            elif action == 'backup':
                return self._execute_backup()
            elif action == 'info':
                return self._execute_info()
            elif action == 'maintenance':
                return self._execute_maintenance()
            elif action == 'import':
                return self._execute_import()
            else:
                self.output.error(f"Unknown database action: {action}")
                return 1
        
        except Exception as e:
            self.output.error(f"Database operation failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()
    
    def _execute_query(self) -> int:
        """Execute database query operations."""
        try:
            from db_query import main as db_query_main
            
            # Build arguments for db_query
            query_args = ['db_query.py']
            
            if getattr(self.args, 'summary', False):
                query_args.append('--summary')
            elif getattr(self.args, 'countries', False):
                query_args.append('--countries')
            elif getattr(self.args, 'all', False):
                query_args.append('--all')
            else:
                query_args.append('--summary')  # Default to summary
            
            # Temporarily replace sys.argv
            original_argv = sys.argv
            sys.argv = query_args
            
            try:
                db_query_main()
                return 0
            finally:
                sys.argv = original_argv
        
        except Exception as e:
            self.output.error(f"Database query failed: {e}")
            return 1
    
    def _execute_backup(self) -> int:
        """Execute database backup."""
        try:
            from db_maintenance import SMBSeekDatabaseMaintenance
            
            maintenance = SMBSeekDatabaseMaintenance(
                db_path=self.config.get_database_path(),
                config=self.config.config
            )
            
            backup_path = maintenance.create_backup()
            if backup_path:
                self.output.success(f"Database backup created: {backup_path}")
                return 0
            else:
                self.output.error("Backup creation failed")
                return 1
        
        except Exception as e:
            self.output.error(f"Backup failed: {e}")
            return 1
    
    def _execute_info(self) -> int:
        """Execute database info display."""
        try:
            from db_maintenance import SMBSeekDatabaseMaintenance
            import json
            
            maintenance = SMBSeekDatabaseMaintenance(
                db_path=self.config.get_database_path(),
                config=self.config.config
            )
            
            info = maintenance.get_database_info()
            
            self.output.header("Database Information")
            print(json.dumps(info, indent=2))
            
            return 0
        
        except Exception as e:
            self.output.error(f"Info display failed: {e}")
            return 1
    
    def _execute_maintenance(self) -> int:
        """Execute database maintenance."""
        try:
            from db_maintenance import SMBSeekDatabaseMaintenance
            
            maintenance = SMBSeekDatabaseMaintenance(
                db_path=self.config.get_database_path(),
                config=self.config.config
            )
            
            results = maintenance.run_maintenance(full=False)
            
            self.output.header("Database Maintenance Results")
            for operation, success in results.items():
                status = "SUCCESS" if success else "FAILED"
                if success:
                    self.output.success(f"{operation}: {status}")
                else:
                    self.output.error(f"{operation}: {status}")
            
            return 0
        
        except Exception as e:
            self.output.error(f"Maintenance failed: {e}")
            return 1
    
    def _execute_import(self) -> int:
        """Execute data import."""
        try:
            from db_import import main as db_import_main
            
            # Build arguments for db_import
            import_args = ['db_import.py']
            
            if getattr(self.args, 'csv', None):
                import_args.extend(['--csv', self.args.csv])
            elif getattr(self.args, 'json', None):
                import_args.extend(['--json', self.args.json])
            else:
                self.output.error("No import file specified")
                return 1
            
            # Temporarily replace sys.argv
            original_argv = sys.argv
            sys.argv = import_args
            
            try:
                db_import_main()
                return 0
            finally:
                sys.argv = original_argv
        
        except Exception as e:
            self.output.error(f"Data import failed: {e}")
            return 1