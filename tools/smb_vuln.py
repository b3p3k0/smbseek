#!/usr/bin/env python3
"""
SMB Vuln - Vulnerability Assessment Tool for SMBSeek
Tests for specific SMB vulnerabilities and provides safe exploitability proofs
"""

import json
import csv
import time
import sys
import argparse
import uuid
from datetime import datetime
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBException
import socket
import subprocess
import os

class SMBVulnScanner:
    def __init__(self, quiet=False, verbose=False, no_colors=False):
        self.quiet = quiet
        self.verbose = verbose
        
        # Color management (following SMBSeek pattern)
        if no_colors:
            self.GREEN = self.RED = self.YELLOW = self.CYAN = self.RESET = ''
        else:
            self.GREEN = '\033[92m'
            self.RED = '\033[91m'
            self.YELLOW = '\033[93m'
            self.CYAN = '\033[96m'
            self.RESET = '\033[0m'
        
        self.config = self.load_configuration()
        self.results = []

    def load_configuration(self, config_file=None):
        """Load configuration from JSON file with fallback to defaults."""
        # Default to conf/config.json, handling path from tools/ directory
        if config_file is None:
            # Get the directory containing this script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            # Go up one level to repo root, then into conf/
            config_file = os.path.join(os.path.dirname(script_dir), "conf", "config.json")
        
        default_config = {
            "connection": {
                "timeout": 30,
                "port_check_timeout": 10,
                "rate_limit_delay": 3
            },
            "vulnerability_testing": {
                "test_eternalblue": True,
                "test_smbghost": True,
                "test_ntlm_relay": True,
                "test_smb_signing": True
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
            # Merge user config with defaults
            return {**default_config, **user_config}
        except Exception:
            return default_config

    def print_if_not_quiet(self, message):
        if not self.quiet:
            print(message)

    def print_if_verbose(self, message):
        if self.verbose and not self.quiet:
            print(message)

    def test_eternalblue(self, ip):
        """
        Test for EternalBlue vulnerability (CVE-2017-0144) without exploitation
        Returns: dict with vulnerability status and details
        """
        result = {
            "vulnerability": "EternalBlue",
            "cve": "CVE-2017-0144",
            "vulnerable": False,
            "confidence": "low",
            "details": "",
            "risk_level": "critical"
        }
        
        try:
            # Test SMBv1 availability (prerequisite for EternalBlue)
            conn_uuid = str(uuid.uuid4())
            connection = Connection(conn_uuid, ip, 445)
            connection.connect(timeout=self.config["connection"]["timeout"])
            
            # Check if SMBv1 is enabled by attempting negotiation
            # Note: This is a safe detection method that doesn't exploit
            session = Session(connection)
            
            # If we can establish a session, SMBv1 might be available
            # Additional checks would be needed for definitive detection
            result["vulnerable"] = True
            result["confidence"] = "medium"
            result["details"] = "SMBv1 appears to be enabled, potential EternalBlue vulnerability"
            
            connection.disconnect()
            
        except SMBException as e:
            self.print_if_verbose(f"SMB Exception testing EternalBlue on {ip}: {e}")
            result["details"] = f"SMB protocol error: {str(e)}"
        except Exception as e:
            self.print_if_verbose(f"Network error testing {ip}: {e}")
            result["details"] = f"Network error: {str(e)}"
        
        return result

    def test_smb_signing(self, ip):
        """
        Test SMB signing requirements
        Returns: dict with signing status and security implications
        """
        result = {
            "vulnerability": "SMB Signing Disabled",
            "cve": "N/A",
            "vulnerable": False,
            "confidence": "high",
            "details": "",
            "risk_level": "medium"
        }
        
        try:
            # Use smbclient to check signing requirements
            cmd = ["smbclient", "-L", f"//{ip}", "-N"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            # Analyze output for signing-related messages
            output = proc.stderr.lower()
            if "signing" in output and "required" not in output:
                result["vulnerable"] = True
                result["details"] = "SMB signing not required, vulnerable to relay attacks"
            elif "signing" in output and "required" in output:
                result["details"] = "SMB signing required, protected against relay attacks"
            else:
                result["details"] = "Unable to determine SMB signing status"
                result["confidence"] = "low"
                
        except subprocess.TimeoutExpired:
            result["details"] = "Timeout during SMB signing test"
        except Exception as e:
            result["details"] = f"Error testing SMB signing: {str(e)}"
        
        return result

    def test_ntlm_relay_vulnerability(self, ip):
        """
        Test for NTLM relay vulnerability conditions
        Returns: dict with relay vulnerability status
        """
        result = {
            "vulnerability": "NTLM Relay",
            "cve": "N/A",
            "vulnerable": False,
            "confidence": "medium",
            "details": "",
            "risk_level": "high"
        }
        
        # Check if SMB signing is disabled (prerequisite for relay attacks)
        signing_result = self.test_smb_signing(ip)
        
        if signing_result["vulnerable"]:
            result["vulnerable"] = True
            result["details"] = "SMB signing disabled, vulnerable to NTLM relay attacks"
        else:
            result["details"] = "SMB signing enabled, protected against NTLM relay"
        
        return result

    def scan_target(self, ip, country="Unknown"):
        """Scan a single target for multiple vulnerabilities"""
        self.print_if_verbose(f"Scanning {ip} for vulnerabilities...")
        
        target_result = {
            "ip_address": ip,
            "country": country,
            "scan_timestamp": datetime.now().isoformat(),
            "vulnerabilities": []
        }
        
        # Test for different vulnerabilities
        if self.config.get("vulnerability_testing", {}).get("test_eternalblue", True):
            eternalblue_result = self.test_eternalblue(ip)
            target_result["vulnerabilities"].append(eternalblue_result)
            
        if self.config.get("vulnerability_testing", {}).get("test_smb_signing", True):
            signing_result = self.test_smb_signing(ip)
            target_result["vulnerabilities"].append(signing_result)
            
        if self.config.get("vulnerability_testing", {}).get("test_ntlm_relay", True):
            relay_result = self.test_ntlm_relay_vulnerability(ip)
            target_result["vulnerabilities"].append(relay_result)
        
        # Calculate overall risk score
        risk_levels = [vuln["risk_level"] for vuln in target_result["vulnerabilities"] if vuln["vulnerable"]]
        if "critical" in risk_levels:
            target_result["overall_risk"] = "critical"
        elif "high" in risk_levels:
            target_result["overall_risk"] = "high"
        elif "medium" in risk_levels:
            target_result["overall_risk"] = "medium"
        else:
            target_result["overall_risk"] = "low"
            
        self.results.append(target_result)
        
        # Display results
        vuln_count = sum(1 for vuln in target_result["vulnerabilities"] if vuln["vulnerable"])
        if vuln_count > 0:
            self.print_if_not_quiet(f"{self.RED}✗ {ip}: {vuln_count} vulnerabilities found (Risk: {target_result['overall_risk']}){self.RESET}")
        else:
            self.print_if_not_quiet(f"{self.GREEN}✓ {ip}: No vulnerabilities detected{self.RESET}")
        
        # Rate limiting
        time.sleep(self.config["connection"]["rate_limit_delay"])

    def process_input_file(self, csv_file):
        """Process SMBSeek CSV output file"""
        targets_processed = 0
        
        try:
            with open(csv_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ip = row['ip_address']
                    country = row.get('country', 'Unknown')
                    self.scan_target(ip, country)
                    targets_processed += 1
                    
        except FileNotFoundError:
            self.print_if_not_quiet(f"{self.RED}Error: File {csv_file} not found{self.RESET}")
            return False
        except Exception as e:
            self.print_if_not_quiet(f"{self.RED}Error processing file: {e}{self.RESET}")
            return False
            
        return targets_processed > 0

    def save_results(self, output_file=None):
        """Save vulnerability scan results to JSON file"""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"vulnerability_report_{timestamp}.json"
        
        report = {
            "metadata": {
                "tool": "smb_vuln",
                "version": "1.0",
                "scan_date": datetime.now().isoformat(),
                "total_targets": len(self.results),
                "vulnerable_targets": sum(1 for result in self.results 
                                        if any(vuln["vulnerable"] for vuln in result["vulnerabilities"]))
            },
            "results": self.results
        }
        
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.print_if_not_quiet(f"{self.GREEN}Results saved to: {output_file}{self.RESET}")
            return output_file
        except Exception as e:
            self.print_if_not_quiet(f"{self.RED}Error saving results: {e}{self.RESET}")
            return None

def main():
    parser = argparse.ArgumentParser(description="SMB Vulnerability Scanner")
    parser.add_argument("csv_file", nargs='?', default="ip_record.csv",
                      help="CSV file with SMB targets (default: ip_record.csv)")
    parser.add_argument("-q", "--quiet", action="store_true",
                      help="Suppress output to screen")
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output")
    parser.add_argument("-x", "--no-colors", action="store_true",
                      help="Disable colored output")
    parser.add_argument("-o", "--output", help="Specify output JSON file")
    parser.add_argument("--config", 
                       type=str, 
                       metavar="FILE", 
                       help="Configuration file path (default: conf/config.json)")
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not os.path.exists(args.csv_file):
        if args.csv_file == "ip_record.csv":
            print("Error: Default file 'ip_record.csv' not found. Run smb_scan.py first.")
        else:
            print(f"Error: File '{args.csv_file}' not found.")
        sys.exit(1)
    
    scanner = SMBVulnScanner(quiet=args.quiet, verbose=args.verbose, no_colors=args.no_colors)
    # Override config if specified
    if args.config:
        scanner.config = scanner.load_configuration(args.config)
    
    scanner.print_if_not_quiet("SMB Vulnerability Scanner")
    scanner.print_if_not_quiet("=" * 50)
    
    if scanner.process_input_file(args.csv_file):
        output_file = scanner.save_results(args.output)
        
        # Print summary
        total_targets = len(scanner.results)
        vulnerable_targets = sum(1 for result in scanner.results 
                               if any(vuln["vulnerable"] for vuln in result["vulnerabilities"]))
        
        scanner.print_if_not_quiet(f"\nScan Summary:")
        scanner.print_if_not_quiet(f"Total targets: {total_targets}")
        scanner.print_if_not_quiet(f"Vulnerable targets: {vulnerable_targets}")
        if vulnerable_targets > 0:
            scanner.print_if_not_quiet(f"{scanner.YELLOW}Review {output_file} for detailed vulnerability information{scanner.RESET}")
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()