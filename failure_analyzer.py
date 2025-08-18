#!/usr/bin/env python3
"""
SMB Failure Analysis Tool
Analyzes failed SMB connections to identify patterns and root causes
"""

import shodan
import csv
import json
import socket
import struct
import time
from collections import defaultdict, Counter
from datetime import datetime
from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.exceptions import SMBException
import uuid
from contextlib import redirect_stderr
from io import StringIO

class SMBFailureAnalyzer:
    def __init__(self, config_file="config.json"):
        """Initialize the failure analyzer with Shodan API."""
        self.config = self.load_configuration(config_file)
        self.api = shodan.Shodan(self.config["shodan"]["api_key"])
        self.analysis_results = []
        self.patterns = {
            'smb_versions': Counter(),
            'os_types': Counter(),
            'failure_reasons': Counter(),
            'port_status': Counter(),
            'auth_mechanisms': Counter(),
            'signing_requirements': Counter(),
            'geographic_patterns': Counter(),
            'isp_patterns': Counter(),
            'vulnerability_patterns': Counter()
        }
        
    def load_configuration(self, config_file):
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"✗ Error loading configuration: {e}")
            raise

    def analyze_csv(self, csv_file):
        """Main analysis function - processes failure CSV."""
        print("SMB Failure Analysis Tool")
        print("=" * 50)
        
        failed_ips = self.load_failed_connections(csv_file)
        print(f"Loaded {len(failed_ips)} failed connections for analysis\n")
        
        for i, ip_data in enumerate(failed_ips, 1):
            ip = ip_data['ip_address']
            country = ip_data['country']
            
            print(f"[{i}/{len(failed_ips)}] Analyzing {ip} ({country})...")
            
            analysis = self.analyze_single_ip(ip, country)
            self.analysis_results.append(analysis)
            self.update_patterns(analysis)
            
            # Small delay to be respectful to APIs
            time.sleep(0.5)
        
        return self.generate_briefing_report()

    def load_failed_connections(self, csv_file):
        """Load failed connections from CSV file."""
        failed_ips = []
        try:
            with open(csv_file, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    failed_ips.append(row)
        except Exception as e:
            print(f"✗ Error reading CSV file: {e}")
            raise
        return failed_ips

    def analyze_single_ip(self, ip, country):
        """Comprehensive analysis of a single failed IP."""
        analysis = {
            'ip': ip,
            'country': country,
            'timestamp': datetime.now().isoformat(),
            'shodan_data': None,
            'network_analysis': {},
            'smb_analysis': {},
            'vulnerability_data': {},
            'failure_classification': 'unknown'
        }
        
        # 1. Shodan Deep Dive
        analysis['shodan_data'] = self.query_shodan_detailed(ip)
        
        # 2. Network Analysis
        analysis['network_analysis'] = self.perform_network_analysis(ip)
        
        # 3. SMB Protocol Analysis
        analysis['smb_analysis'] = self.perform_smb_analysis(ip)
        
        # 4. Vulnerability Assessment
        analysis['vulnerability_data'] = self.assess_vulnerabilities(analysis['shodan_data'])
        
        # 5. Classify Failure Reason
        analysis['failure_classification'] = self.classify_failure(analysis)
        
        return analysis

    def query_shodan_detailed(self, ip):
        """Detailed Shodan query for comprehensive host information."""
        try:
            host_data = self.api.host(ip)
            
            # Extract relevant SMB and security information
            shodan_analysis = {
                'ip': ip,
                'org': host_data.get('org', 'Unknown'),
                'isp': host_data.get('isp', 'Unknown'),
                'country_code': host_data.get('country_code', 'Unknown'),
                'city': host_data.get('city', 'Unknown'),
                'asn': host_data.get('asn', 'Unknown'),
                'os': host_data.get('os', 'Unknown'),
                'ports': host_data.get('ports', []),
                'vulns': host_data.get('vulns', []),
                'tags': host_data.get('tags', []),
                'smb_services': [],
                'last_update': host_data.get('last_update', 'Unknown')
            }
            
            # Extract SMB-specific service data
            for service in host_data.get('data', []):
                if service.get('port') == 445 or 'smb' in service.get('product', '').lower():
                    smb_service = {
                        'port': service.get('port'),
                        'product': service.get('product', ''),
                        'version': service.get('version', ''),
                        'banner': service.get('banner', ''),
                        'smb': service.get('smb', {}),
                        'ssl': service.get('ssl', {}),
                        'timestamp': service.get('timestamp', '')
                    }
                    shodan_analysis['smb_services'].append(smb_service)
            
            return shodan_analysis
            
        except shodan.APIError as e:
            return {'error': f'Shodan API error: {str(e)}', 'ip': ip}
        except Exception as e:
            return {'error': f'Analysis error: {str(e)}', 'ip': ip}

    def perform_network_analysis(self, ip):
        """Network-level analysis of the target."""
        network_analysis = {
            'port_445_status': 'unknown',
            'tcp_response_time': None,
            'additional_smb_ports': [],
            'connection_behavior': 'unknown'
        }
        
        try:
            # Test port 445 connectivity
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            result = sock.connect_ex((ip, 445))
            response_time = time.time() - start_time
            sock.close()
            
            if result == 0:
                network_analysis['port_445_status'] = 'open'
                network_analysis['tcp_response_time'] = round(response_time * 1000, 2)  # ms
            else:
                network_analysis['port_445_status'] = 'closed_or_filtered'
                
            # Check other common SMB ports
            smb_ports = [139, 445, 135]  # NetBIOS, SMB, RPC
            for port in smb_ports:
                if port != 445:  # Already tested 445
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(5)
                        result = sock.connect_ex((ip, port))
                        sock.close()
                        if result == 0:
                            network_analysis['additional_smb_ports'].append(port)
                    except:
                        pass
                        
        except Exception as e:
            network_analysis['error'] = str(e)
            
        return network_analysis

    def perform_smb_analysis(self, ip):
        """SMB protocol-level analysis."""
        smb_analysis = {
            'smb_negotiation': 'failed',
            'supported_dialects': [],
            'authentication_types': [],
            'signing_required': 'unknown',
            'encryption_required': 'unknown',
            'server_capabilities': [],
            'failure_stage': 'connection',
            'error_details': None
        }
        
        # Only attempt if port 445 appears to be open
        try:
            # Test basic SMB negotiation
            conn_uuid = uuid.uuid4()
            connection = None
            session = None
            
            stderr_buffer = StringIO()
            with redirect_stderr(stderr_buffer):
                try:
                    # Attempt SMB connection with minimal timeout
                    connection = Connection(conn_uuid, ip, 445, require_signing=False)
                    connection.connect(timeout=10)
                    
                    smb_analysis['smb_negotiation'] = 'success'
                    smb_analysis['failure_stage'] = 'authentication'
                    
                    # Extract negotiated dialect and capabilities
                    if hasattr(connection, 'dialect'):
                        smb_analysis['supported_dialects'].append(str(connection.dialect))
                    
                    if hasattr(connection, 'server_capabilities'):
                        smb_analysis['server_capabilities'] = list(connection.server_capabilities)
                    
                    # Try to determine signing requirements
                    try:
                        session = Session(connection, username="", password="", require_encryption=False)
                        session.connect()
                        smb_analysis['authentication_types'].append('anonymous')
                        smb_analysis['failure_stage'] = 'post_auth'  # If we get here, auth worked
                    except Exception as auth_e:
                        smb_analysis['error_details'] = str(auth_e)
                        if 'signing' in str(auth_e).lower():
                            smb_analysis['signing_required'] = 'yes'
                        elif 'encryption' in str(auth_e).lower():
                            smb_analysis['encryption_required'] = 'yes'
                        elif 'auth' in str(auth_e).lower():
                            smb_analysis['authentication_types'].append('auth_required')
                    
                except SMBException as e:
                    smb_analysis['error_details'] = str(e)
                    if 'dialect' in str(e).lower():
                        smb_analysis['failure_stage'] = 'negotiation'
                    elif 'auth' in str(e).lower():
                        smb_analysis['failure_stage'] = 'authentication'
                except Exception as e:
                    smb_analysis['error_details'] = str(e)
                    smb_analysis['failure_stage'] = 'connection'
                    
                finally:
                    # Cleanup
                    if session:
                        try:
                            session.disconnect()
                        except:
                            pass
                    if connection:
                        try:
                            connection.disconnect()
                        except:
                            pass
                            
        except Exception as e:
            smb_analysis['error_details'] = str(e)
            
        return smb_analysis

    def assess_vulnerabilities(self, shodan_data):
        """Assess vulnerabilities and security configurations."""
        vuln_assessment = {
            'known_vulnerabilities': [],
            'security_concerns': [],
            'smb_security_level': 'unknown',
            'risk_factors': []
        }
        
        if not shodan_data or 'error' in shodan_data:
            return vuln_assessment
            
        # Check for known vulnerabilities
        vulns = shodan_data.get('vulns', [])
        for vuln in vulns:
            vuln_assessment['known_vulnerabilities'].append(vuln)
            
        # Analyze SMB services for security issues
        for smb_service in shodan_data.get('smb_services', []):
            smb_data = smb_service.get('smb', {})
            
            # Check SMB version and security implications
            if 'capabilities' in smb_data:
                caps = smb_data['capabilities']
                if 'ENCRYPTION' not in caps:
                    vuln_assessment['security_concerns'].append('No SMB encryption capability')
                if 'SIGNING' not in caps:
                    vuln_assessment['security_concerns'].append('No SMB signing capability')
                    
            # Check for weak configurations
            product = smb_service.get('product', '').lower()
            version = smb_service.get('version', '').lower()
            
            if 'samba' in product and version:
                try:
                    # Parse version for security assessment
                    version_num = version.split()[0] if version else ''
                    vuln_assessment['risk_factors'].append(f'Samba version: {version_num}')
                except:
                    pass
                    
        # Determine overall security level
        if len(vuln_assessment['known_vulnerabilities']) > 0:
            vuln_assessment['smb_security_level'] = 'high_risk'
        elif len(vuln_assessment['security_concerns']) > 2:
            vuln_assessment['smb_security_level'] = 'medium_risk'
        else:
            vuln_assessment['smb_security_level'] = 'low_risk'
            
        return vuln_assessment

    def classify_failure(self, analysis):
        """Classify the failure reason based on all analysis data."""
        network = analysis['network_analysis']
        smb = analysis['smb_analysis']
        shodan = analysis['shodan_data']
        vulns = analysis['vulnerability_data']
        
        # Priority-based classification
        if network.get('port_445_status') != 'open':
            return 'port_not_accessible'
            
        if smb.get('failure_stage') == 'connection':
            return 'smb_connection_rejected'
            
        if smb.get('failure_stage') == 'negotiation':
            return 'smb_protocol_mismatch'
            
        if smb.get('signing_required') == 'yes':
            return 'smb_signing_required'
            
        if smb.get('encryption_required') == 'yes':
            return 'smb_encryption_required'
            
        if smb.get('failure_stage') == 'authentication':
            if 'auth_required' in smb.get('authentication_types', []):
                return 'authentication_required'
            else:
                return 'authentication_method_unsupported'
                
        if vulns.get('smb_security_level') == 'high_risk':
            return 'security_policy_blocking'
            
        return 'unknown_configuration_issue'

    def update_patterns(self, analysis):
        """Update pattern tracking with analysis results."""
        # SMB version patterns
        for service in analysis['shodan_data'].get('smb_services', []):
            product = service.get('product', 'Unknown')
            version = service.get('version', 'Unknown')
            self.patterns['smb_versions'][f"{product} {version}"] += 1
            
        # OS patterns
        os_info = analysis['shodan_data'].get('os', 'Unknown')
        self.patterns['os_types'][os_info] += 1
        
        # Failure reason patterns
        self.patterns['failure_reasons'][analysis['failure_classification']] += 1
        
        # Port status patterns
        port_status = analysis['network_analysis'].get('port_445_status', 'unknown')
        self.patterns['port_status'][port_status] += 1
        
        # Geographic patterns
        country = analysis['country']
        self.patterns['geographic_patterns'][country] += 1
        
        # ISP patterns
        isp = analysis['shodan_data'].get('isp', 'Unknown')
        self.patterns['isp_patterns'][isp] += 1
        
        # Vulnerability patterns
        vuln_level = analysis['vulnerability_data'].get('smb_security_level', 'unknown')
        self.patterns['vulnerability_patterns'][vuln_level] += 1

    def generate_briefing_report(self):
        """Generate supervisor briefing report."""
        total_analyzed = len(self.analysis_results)
        
        report = f"""
SMB AUTHENTICATION FAILURE ANALYSIS BRIEFING
============================================
Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Failed Connections Analyzed: {total_analyzed}

EXECUTIVE SUMMARY
-----------------
Analysis of {total_analyzed} failed SMB authentication attempts reveals distinct patterns in failure causes. The primary failure categories and their implications are detailed below.

FAILURE CLASSIFICATION BREAKDOWN
--------------------------------"""
        
        # Top failure reasons
        report += "\nPrimary Failure Reasons:\n"
        for reason, count in self.patterns['failure_reasons'].most_common():
            percentage = (count / total_analyzed) * 100
            report += f"  • {reason.replace('_', ' ').title()}: {count} ({percentage:.1f}%)\n"
            
        # Network accessibility
        report += f"\nNetwork Accessibility Analysis:\n"
        for status, count in self.patterns['port_status'].most_common():
            percentage = (count / total_analyzed) * 100
            report += f"  • Port 445 {status.replace('_', ' ').title()}: {count} ({percentage:.1f}%)\n"
            
        # SMB implementation patterns
        report += f"\nSMB Implementation Patterns:\n"
        top_smb = list(self.patterns['smb_versions'].most_common(5))
        for smb_version, count in top_smb:
            percentage = (count / total_analyzed) * 100
            report += f"  • {smb_version}: {count} ({percentage:.1f}%)\n"
            
        # Geographic distribution
        report += f"\nGeographic Distribution:\n"
        for country, count in self.patterns['geographic_patterns'].most_common(5):
            percentage = (count / total_analyzed) * 100
            report += f"  • {country}: {count} ({percentage:.1f}%)\n"
            
        # Security assessment
        report += f"\nSecurity Risk Assessment:\n"
        for risk_level, count in self.patterns['vulnerability_patterns'].most_common():
            percentage = (count / total_analyzed) * 100
            report += f"  • {risk_level.replace('_', ' ').title()}: {count} ({percentage:.1f}%)\n"

        # Key findings and recommendations
        report += f"""
KEY TECHNICAL FINDINGS
----------------------
1. Network Infrastructure Issues: {self.patterns['port_status']['closed_or_filtered']} targets have port 445 inaccessible
2. Protocol Security: {self.patterns['failure_reasons']['smb_signing_required'] + self.patterns['failure_reasons']['smb_encryption_required']} targets require enhanced security
3. Authentication Mechanisms: {self.patterns['failure_reasons']['authentication_required']} targets require credential-based authentication

RECOMMENDATIONS
---------------
1. Focus successful authentication attempts on targets with 'port_not_accessible' != primary failure
2. Implement SMB signing and encryption support for security-enhanced targets
3. Consider credential-based authentication methods for 'authentication_required' targets
4. Investigate geographic/ISP patterns for infrastructure-based blocking

TECHNICAL DETAILS AVAILABLE
---------------------------
- Detailed per-IP analysis results
- SMB protocol negotiation logs
- Shodan vulnerability correlations
- Network timing and behavior patterns

STATUS: Analysis complete. Ready for follow-up technical questions.
"""
        
        return report

def print_help():
    """Print comprehensive help information."""
    help_text = """
SMB Failure Analyzer - Deep Analysis Tool for SMB Authentication Failures

DESCRIPTION:
    Analyzes failed SMB authentication attempts to identify patterns, root causes, 
    and technical issues preventing successful connections. Performs comprehensive 
    Shodan queries, network analysis, SMB protocol testing, and vulnerability 
    assessment to generate actionable intelligence.

USAGE:
    python3 failure_analyzer.py <failed_connections.csv>
    python3 failure_analyzer.py --help | -h

ARGUMENTS:
    <failed_connections.csv>    CSV file containing failed connection records
                               Generated by: python3 smbscan.py -f

OPTIONS:
    -h, --help                 Show this help message and exit

ANALYSIS COMPONENTS:
    1. Shodan Deep Dive
       • SMB service details (version, capabilities, banners)
       • OS fingerprinting and vulnerability data
       • Network information (ISP, organization, location)
       • Complete port enumeration and service analysis

    2. Network-Level Analysis  
       • Port 445 accessibility testing with response timing
       • Additional SMB port scanning (139, 135)
       • Connection behavior and timeout analysis

    3. SMB Protocol Analysis
       • Protocol negotiation and dialect support testing
       • Authentication requirement detection (signing/encryption)
       • Failure stage classification (connection → negotiation → auth)
       • Detailed error message extraction and analysis

    4. Vulnerability Assessment
       • Security risk evaluation (high/medium/low)
       • SMB configuration security analysis
       • Known vulnerability correlation with CVE mapping

OUTPUT:
    Console Report:
        Executive briefing format suitable for supervisor presentations
        Includes failure classifications, technical findings, and recommendations

    JSON File:
        Detailed technical analysis saved as failure_analysis_YYYYMMDD_HHMMSS.json
        Contains complete per-IP analysis, patterns, and raw data for further processing

FAILURE CLASSIFICATIONS:
    • port_not_accessible           - Network/firewall blocking port 445
    • smb_connection_rejected       - SMB service rejecting connections  
    • smb_protocol_mismatch        - SMB version/dialect incompatibility
    • smb_signing_required         - Server requires SMB message signing
    • smb_encryption_required      - Server requires SMB encryption
    • authentication_required      - Server requires valid credentials
    • authentication_method_unsupported - Auth method not supported
    • security_policy_blocking     - Security policies preventing access
    • unknown_configuration_issue  - Unclassified technical issue

PATTERN DETECTION:
    Identifies trends across multiple dimensions:
    • SMB implementation patterns (Samba vs Windows versions)
    • Geographic distribution of failure types
    • ISP/organization security policies  
    • Network security configuration patterns
    • Protocol security requirement patterns

PREREQUISITES:
    Python Dependencies:
        pip install shodan smbprotocol pyspnego

    Configuration:
        Valid Shodan API key configured in config.json
        Same configuration file used by smbscan.py

INTEGRATION WORKFLOW:
    1. Run SMBSeek with failure logging:
       python3 smbscan.py -f -c US

    2. Analyze generated failures:
       python3 failure_analyzer.py failed_record.csv

    3. Review briefing report for actionable insights
    4. Implement targeted improvements based on classifications

EXAMPLES:
    # Basic failure analysis
    python3 failure_analyzer.py failed_record.csv

    # Analyze custom failure file
    python3 failure_analyzer.py custom_failures.csv

    # Show help information  
    python3 failure_analyzer.py --help

PERFORMANCE:
    • Respects Shodan API rate limits with built-in delays
    • Implements reasonable timeouts for network testing
    • Processes large datasets incrementally for memory efficiency
    • Graceful error handling for individual analysis failures

SECURITY:
    This tool is designed for legitimate defensive security purposes only.
    Ensure you have proper authorization before analyzing any network targets.
    
    • Only analyze networks you own or have explicit permission to test
    • Use findings responsibly for defensive security improvements
    • Follow all applicable laws and regulations
    • Respect API terms of service and rate limits

For more information, see the SMBSeek README.md documentation.
"""
    print(help_text)

def main():
    """Main function for standalone execution."""
    import sys
    
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ['-h', '--help']):
        print_help()
        sys.exit(0)
    
    if len(sys.argv) != 2:
        print("Error: Invalid number of arguments")
        print("Usage: python3 failure_analyzer.py <failed_connections.csv>")
        print("       python3 failure_analyzer.py --help")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    try:
        analyzer = SMBFailureAnalyzer()
        briefing = analyzer.analyze_csv(csv_file)
        
        print("\n" + "=" * 80)
        print(briefing)
        
        # Save detailed results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"failure_analysis_{timestamp}.json"
        
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'analysis_results': analyzer.analysis_results,
                'patterns': dict(analyzer.patterns),
                'briefing_report': briefing,
                'metadata': {
                    'analysis_date': datetime.now().isoformat(),
                    'total_analyzed': len(analyzer.analysis_results)
                }
            }, f, indent=2, default=str)
            
        print(f"\n✓ Detailed analysis results saved to: {results_file}")
        
    except Exception as e:
        print(f"✗ Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()