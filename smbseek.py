#!/usr/bin/env python3
"""
SMBSeek - Unified Security Toolkit

A defensive security toolkit for identifying and analyzing SMB servers
with weak authentication. Simplified single-command interface for
discovery and share enumeration.

Usage:
    smbseek --country US                        # Discovery + share enumeration
    smbseek --country US --verbose              # Same with detailed output
    smbseek --help                              # Help system

Author: Human-AI Collaboration
Version: 3.0.0
"""

import argparse
import sys
import os
import ipaddress
from typing import Optional

# Add current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def validate_force_hosts(value):
    """
    Validate and parse force hosts argument.

    Args:
        value: Comma-separated IP addresses string

    Returns:
        Set of validated IP address strings

    Raises:
        argparse.ArgumentTypeError: If any IP is invalid
    """
    if not value.strip():
        raise argparse.ArgumentTypeError("forced hosts cannot be empty")

    ips = set()
    for ip_str in value.split(','):
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        try:
            ipaddress.ip_address(ip_str)
            ips.add(ip_str)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{ip_str}' is not a valid IP address (hostnames not supported)")

    if not ips:
        raise argparse.ArgumentTypeError("no valid IP addresses provided")

    return ips


def detect_deprecated_usage(argv):
    """Detect and handle deprecated subcommand usage"""
    deprecated_subcommands = {'run', 'discover', 'access', 'collect', 'analyze', 'report', 'db'}
    deprecated_flags = {'--download', '--max-files', '--rescan-all', '--rescan-failed', '--recent', '--pause-between-steps'}

    warnings_issued = []

    # Check for deprecated subcommands
    if len(argv) > 1 and argv[1] in deprecated_subcommands:
        if argv[1] in {'collect', 'analyze', 'report', 'db'}:
            print(f"⚠️  DEPRECATED: '{argv[1]}' subcommand is no longer supported.")
            print("   Use: ./smbseek.py --country US")
            return None  # Exit early with code 1
        else:
            warnings_issued.append(f"subcommand '{argv[1]}' is deprecated, use flags directly")
            argv.pop(1)  # Remove subcommand, continue with flag parsing

    # Check for deprecated flags
    for flag in deprecated_flags:
        if flag in argv:
            warnings_issued.append(f"flag '{flag}' is deprecated and will be ignored")
            argv.remove(flag)

    if warnings_issued:
        for warning in warnings_issued:
            print(f"⚠️  DEPRECATED: {warning}")
        print()

    return argv


def create_main_parser() -> argparse.ArgumentParser:
    """
    Create the main argument parser for unified interface.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog='smbseek',
        description='SMBSeek - Unified SMB Security Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  smbseek --country US                        # Complete scan (discovery + share enumeration)
  smbseek --country US --verbose              # Same with detailed output
  smbseek --help                              # Show help

The tool performs two main operations:
  1. Discovery: Query Shodan and test SMB authentication
  2. Share Access: Enumerate accessible shares on authenticated hosts

Results are automatically saved to smbseek.db database.

Documentation: docs/USER_GUIDE.md
"""
    )

    # Required arguments
    parser.add_argument(
        '--country',
        type=str,
        metavar='CODE',
        help='Country code for Shodan search (US, GB, CA, etc.). If not specified, performs global scan with no country filter.'
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
        '--force-hosts',
        type=validate_force_hosts,
        action='append',
        metavar='IPS',
        help='Force scanning of specific hosts (comma-separated IPs) even if recently processed or previously failed'
    )
    parser.add_argument(
        '--risky',
        action='store_true',
        help='Enable legacy insecure SMB settings (unsigned sessions, SMB1 allowed). Default is safe mode with signing required and SMB2+/3 only.'
    )
    parser.add_argument(
        '--version',
        action='version',
        version='SMBSeek 3.0.0'
    )

    return parser


def main():
    """Main entry point for SMBSeek unified CLI."""
    # Modify argv before argparse sees it to handle deprecated usage
    cleaned_argv = detect_deprecated_usage(sys.argv[:])
    if cleaned_argv is None:
        return 1  # Exit with failure for unsupported subcommands

    parser = create_main_parser()

    # Parse arguments
    args = parser.parse_args(cleaned_argv[1:])  # Parse modified argv

    # Validate global argument combinations
    if args.quiet and args.verbose:
        print("Error: Cannot use both --quiet and --verbose options")
        return 1

    # Process force_hosts argument (combine multiple uses into single set)
    if hasattr(args, 'force_hosts') and args.force_hosts:
        force_hosts_combined = set()
        for host_set in args.force_hosts:
            force_hosts_combined.update(host_set)
        args.force_hosts = force_hosts_combined
    else:
        args.force_hosts = set()

    try:
        # Import workflow components
        from workflow import create_unified_workflow

        # Create and execute unified workflow
        workflow = create_unified_workflow(args)
        summary = workflow.run(args)

        # Import output manager for summary display
        from shared.config import load_config
        from shared.output import create_output_manager

        config = load_config(args.config)
        output = create_output_manager(
            config,
            quiet=args.quiet,
            verbose=args.verbose,
            no_colors=args.no_colors
        )

        # Display rollup summary
        output.print_rollup_summary(summary)

        return 0

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