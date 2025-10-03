#!/usr/bin/env python3
"""
SMBSeek Report Command - DEPRECATED

This command has been deprecated in SMBSeek 3.0.0.
Reporting capabilities have been removed from the main workflow.

Use the main SMBSeek command for discovery and share enumeration:
    ./smbseek.py --country US
"""

import sys


def main():
    """Main entry point for deprecated report command."""
    print("⚠️  DEPRECATED: report command is no longer supported.")
    print("   Use: ./smbseek.py --country US  (includes discovery + share enumeration)")
    print("   Reporting capabilities have been removed from the main workflow.")
    print("   Query the smbseek.db database directly for reporting needs.")
    return 0


if __name__ == '__main__':
    sys.exit(main())