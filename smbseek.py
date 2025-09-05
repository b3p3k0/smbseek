#!/usr/bin/env python3
"""
SMBSeek - Unified Security Toolkit

A defensive security toolkit for identifying and analyzing SMB servers 
with weak authentication. Provides unified CLI interface with intelligent
workflow orchestration and comprehensive reporting.

Usage:
    smbseek run --country US                    # Full workflow
    smbseek discover --country US              # Individual commands
    smbseek db query --summary                 # Database operations
    smbseek --help                             # Help system

Author: Human-AI Collaboration
Version: 2.0.0
"""

import argparse
import sys
import os
from typing import Optional

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared.config import load_config
from shared.output import create_output_manager


def create_main_parser() -> argparse.ArgumentParser:
    """
    Create the main argument parser with subcommands.
    
    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='smbseek',
        description='SMBSeek - Unified SMB Security Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  smbseek run --country US                    # Full workflow: discover → access → collect → report
  smbseek run --country US --pause-between-steps  # Interactive mode with review points
  smbseek run --country US --rescan-all      # Force rescan of all known hosts
  
  smbseek discover --country US              # Discovery and authentication testing only
  smbseek access                            # Share access verification only
  smbseek collect --download                # File enumeration and collection
  smbseek report --executive                # Generate executive summary report
  
  smbseek db query --summary                # Database operations
  smbseek db backup                         # Create database backup
  smbseek db import --csv file.csv          # Import legacy data

For detailed help on any command:
  smbseek <command> --help

Documentation: docs/USER_GUIDE.md
"""
    )
    
    # Global options
    parser.add_argument(
        '--config',
        type=str,
        metavar='FILE',
        help='Configuration file path (default: conf/config.json)'
    )
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output to screen'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--no-colors',
        action='store_true',
        help='Disable colored output'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='SMBSeek 2.0.0'
    )
    
    # Create subparsers
    subparsers = parser.add_subparsers(
        dest='command',
        title='Available Commands',
        description='SMBSeek provides multiple commands for different security assessment needs',
        help='Command to execute'
    )
    
    # Import and register subcommands
    register_run_command(subparsers)
    register_discover_command(subparsers)
    register_access_command(subparsers)
    register_collect_command(subparsers)
    register_analyze_command(subparsers)
    register_report_command(subparsers)
    register_database_command(subparsers)
    
    return parser


def add_common_arguments(parser):
    """Add common arguments to a subcommand parser."""
    common_group = parser.add_argument_group('output options')
    common_group.add_argument(
        '--config',
        type=str,
        metavar='FILE',
        help='Configuration file path (default: conf/config.json)'
    )
    common_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress output to screen'
    )
    common_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    common_group.add_argument(
        '--no-colors',
        action='store_true',
        help='Disable colored output'
    )


def register_run_command(subparsers):
    """Register the 'run' command (primary workflow)."""
    parser = subparsers.add_parser(
        'run',
        help='Execute full SMB security assessment workflow',
        description='Run complete workflow: discover → access → collect → report'
    )
    
    # Add common arguments
    add_common_arguments(parser)
    
    # Required arguments
    parser.add_argument(
        '--country',
        type=str,
        metavar='CODE',
        help='Country code for Shodan search (US, GB, CA, etc.). If not specified, uses countries from config.json or global scan if none configured.'
    )
    
    # Workflow options
    workflow_group = parser.add_argument_group('workflow options')
    workflow_group.add_argument(
        '--pause-between-steps',
        action='store_true',
        help='Pause for review between workflow steps'
    )
    workflow_group.add_argument(
        '--rescan-all',
        action='store_true',
        help='Force rescan of all discovered hosts (ignore age limits)'
    )
    workflow_group.add_argument(
        '--rescan-failed',
        action='store_true',
        help='Include previously failed hosts for rescanning'
    )
    workflow_group.add_argument(
        '--recent',
        type=int,
        metavar='HOURS',
        help='Only test servers discovered in last N hours during access verification'
    )
    
    # File collection options
    collection_group = parser.add_argument_group('collection options')
    collection_group.add_argument(
        '--download',
        action='store_true',
        help='Download files (default: enumerate only)'
    )
    collection_group.add_argument(
        '--max-files',
        type=int,
        metavar='N',
        help='Maximum files to collect per share'
    )
    
    parser.set_defaults(func=execute_run_command)


def register_discover_command(subparsers):
    """Register the 'discover' command."""
    parser = subparsers.add_parser(
        'discover',
        help='Discover SMB servers and test authentication',
        description='Query Shodan and test SMB authentication methods'
    )
    
    add_common_arguments(parser)
    
    parser.add_argument(
        '--country',
        type=str,
        metavar='CODE',
        help='Country code for Shodan search (US, GB, CA, etc.). If not specified, uses countries from config.json or global scan if none configured.'
    )
    parser.add_argument(
        '--rescan-all',
        action='store_true',
        help='Force rescan of all discovered hosts'
    )
    parser.add_argument(
        '--rescan-failed',
        action='store_true',
        help='Include previously failed hosts'
    )
    
    parser.set_defaults(func=execute_discover_command)


def register_access_command(subparsers):
    """Register the 'access' command."""
    parser = subparsers.add_parser(
        'access',
        help='Verify share access on discovered servers',
        description='Test access to SMB shares on authenticated servers'
    )
    
    add_common_arguments(parser)
    
    parser.add_argument(
        '--servers',
        type=str,
        metavar='IPS',
        help='Comma-separated list of specific IPs to test'
    )
    parser.add_argument(
        '--recent',
        type=int,
        metavar='HOURS',
        help='Only test servers discovered in last N hours'
    )
    
    parser.set_defaults(func=execute_access_command)


def register_collect_command(subparsers):
    """Register the 'collect' command."""
    parser = subparsers.add_parser(
        'collect',
        help='Enumerate and collect files from accessible shares',
        description='Enumerate files on accessible shares with ransomware detection'
    )
    
    add_common_arguments(parser)
    
    parser.add_argument(
        '--download',
        action='store_true',
        help='Download files (default: enumerate only)'
    )
    parser.add_argument(
        '--max-files',
        type=int,
        metavar='N',
        help='Maximum files to collect per share'
    )
    parser.add_argument(
        '--servers',
        type=str,
        metavar='IPS',
        help='Comma-separated list of specific IPs'
    )
    
    parser.set_defaults(func=execute_collect_command)


def register_analyze_command(subparsers):
    """Register the 'analyze' command."""
    parser = subparsers.add_parser(
        'analyze',
        help='Analyze failed connections and authentication issues',
        description='Deep analysis of authentication failures and connectivity issues'
    )
    
    add_common_arguments(parser)
    
    parser.add_argument(
        '--recent',
        type=int,
        metavar='DAYS',
        help='Analyze failures from last N days (default: 7)'
    )
    
    parser.set_defaults(func=execute_analyze_command)


def register_report_command(subparsers):
    """Register the 'report' command."""
    parser = subparsers.add_parser(
        'report',
        help='Generate intelligence reports and executive summaries',
        description='Create comprehensive security assessment reports'
    )
    
    add_common_arguments(parser)
    
    parser.add_argument(
        '--executive',
        action='store_true',
        help='Generate executive summary (default)'
    )
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Include detailed technical findings'
    )
    parser.add_argument(
        '--session',
        type=str,
        metavar='ID',
        help='Report on specific scan session'
    )
    parser.add_argument(
        '--output',
        type=str,
        metavar='FILE',
        help='Save report to file'
    )
    
    parser.set_defaults(func=execute_report_command)


def register_database_command(subparsers):
    """Register the 'db' command."""
    parser = subparsers.add_parser(
        'db',
        help='Database operations and maintenance',
        description='Query, maintain, and manage the SMBSeek database'
    )
    
    add_common_arguments(parser)
    
    # Database subcommands
    db_subparsers = parser.add_subparsers(
        dest='db_action',
        title='Database Operations',
        help='Database operation to perform'
    )
    
    # Query operations
    query_parser = db_subparsers.add_parser('query', help='Query database')
    query_parser.add_argument('--summary', action='store_true', help='Show summary')
    query_parser.add_argument('--countries', action='store_true', help='Show country distribution')
    query_parser.add_argument('--all', action='store_true', help='Show all reports')
    
    # Maintenance operations
    db_subparsers.add_parser('backup', help='Create database backup')
    db_subparsers.add_parser('info', help='Show database information')
    db_subparsers.add_parser('maintenance', help='Run database maintenance')
    
    # Import operations
    import_parser = db_subparsers.add_parser('import', help='Import data')
    import_parser.add_argument('--csv', type=str, help='Import CSV file')
    import_parser.add_argument('--json', type=str, help='Import JSON file')
    
    parser.set_defaults(func=execute_database_command)


def execute_run_command(args):
    """Execute the run command (full workflow)."""
    try:
        from commands.run import WorkflowOrchestrator
        orchestrator = WorkflowOrchestrator(args)
        return orchestrator.execute()
    except ImportError as e:
        print(f"Error: Failed to import run command module: {e}")
        return 1


def execute_discover_command(args):
    """Execute the discover command."""
    try:
        from commands.discover import DiscoverCommand
        command = DiscoverCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import discover command module: {e}")
        return 1


def execute_access_command(args):
    """Execute the access command."""
    try:
        from commands.access import AccessCommand
        command = AccessCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import access command module: {e}")
        return 1


def execute_collect_command(args):
    """Execute the collect command."""
    try:
        from commands.collect import CollectCommand
        command = CollectCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import collect command module: {e}")
        return 1


def execute_analyze_command(args):
    """Execute the analyze command."""
    try:
        from commands.analyze import AnalyzeCommand
        command = AnalyzeCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import analyze command module: {e}")
        return 1


def execute_report_command(args):
    """Execute the report command."""
    try:
        from commands.report import ReportCommand
        command = ReportCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import report command module: {e}")
        return 1


def execute_database_command(args):
    """Execute the database command."""
    try:
        from commands.database import DatabaseCommand
        command = DatabaseCommand(args)
        return command.execute()
    except ImportError as e:
        print(f"Error: Failed to import database command module: {e}")
        return 1


def main():
    """Main entry point for SMBSeek unified CLI."""
    parser = create_main_parser()
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle case where no command is provided
    if not args.command:
        parser.print_help()
        print("\nError: No command specified")
        print("Use 'smbseek run --country US' for the complete workflow")
        print("Use 'smbseek --help' for all available commands")
        return 1
    
    # Validate global argument combinations
    if args.quiet and args.verbose:
        print("Error: Cannot use both --quiet and --verbose options")
        return 1
    
    try:
        # Execute the requested command
        return args.func(args)
    
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())