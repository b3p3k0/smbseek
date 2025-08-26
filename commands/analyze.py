"""
SMBSeek Analyze Command

Failure analysis functionality adapted for the unified CLI.
Analyzes failed connections and authentication issues.
"""

import json
import socket
import struct
import time
import sys
import os
import uuid
from collections import defaultdict, Counter
from datetime import datetime
from contextlib import redirect_stderr
from io import StringIO

# Add project paths for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.config import load_config
from shared.database import create_workflow_database
from shared.output import create_output_manager

# Check if required libraries are available
SHODAN_AVAILABLE = False
SMB_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    pass

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.exceptions import SMBException
    SMB_AVAILABLE = True
except ImportError:
    pass


class AnalyzeCommand:
    """
    SMB failure analysis command.
    
    Analyzes failed connections and authentication issues for troubleshooting.
    """
    
    def __init__(self, args):
        """
        Initialize analyze command.
        
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
        
        # Initialize Shodan API if available
        self.api = None
        if SHODAN_AVAILABLE:
            shodan_config = self.config.get_shodan_config()
            api_key = shodan_config.get('api_key')
            if api_key and api_key != 'YOUR_API_KEY_HERE':
                try:
                    self.api = shodan.Shodan(api_key)
                except Exception as e:
                    if self.args.verbose:
                        self.output.warning(f"Shodan API initialization failed: {e}")
        
        # Analysis results storage
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
    
    def execute(self) -> int:
        """
        Execute the analyze command.
        
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        try:
            self.output.header("SMB Failure Analysis")
            
            # Check dependencies
            if not SMB_AVAILABLE:
                self.output.error("SMB libraries not available. Install with: pip install smbprotocol pyspnego")
                return 1
            
            if not self.api:
                self.output.warning("Shodan API not available - analysis will be limited")
                if not SHODAN_AVAILABLE:
                    self.output.info("Install Shodan: pip install shodan")
                else:
                    self.output.info("Configure Shodan API key in config.json")
            
            # Get failed connections from database
            failed_connections = self.database.get_failed_connections()
            if not failed_connections:
                self.output.warning("No failed connections found in database")
                self.output.info("Run discovery first to generate failure data: smbseek discover --country US")
                return 0
            
            total_failures = len(failed_connections)
            self.output.info(f"Analyzing {total_failures} failed connections")
            
            # Analyze each failed connection
            for i, connection in enumerate(failed_connections, 1):
                ip = connection['ip_address']
                country = connection.get('country', 'Unknown')
                
                self.output.info(f"[{i}/{total_failures}] Analyzing {ip} ({country})...")
                
                analysis = self.analyze_single_ip(ip, country)
                self.analysis_results.append(analysis)
                self.update_patterns(analysis)
                
                # Small delay to be respectful to APIs
                time.sleep(0.5)
            
            # Generate briefing report
            briefing = self.generate_briefing_report()
            
            # Display briefing
            self.output.header("ANALYSIS BRIEFING")
            print(briefing)
            
            # Save detailed results
            self.save_detailed_results(briefing)
            
            return 0
        
        except Exception as e:
            self.output.error(f"Analysis failed: {e}")
            if self.args.verbose:
                import traceback
                traceback.print_exc()
            return 1
        finally:
            self.database.close()
    
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
        
        # 1. Shodan Deep Dive (if available)
        if self.api:
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
            
        except Exception as e:
            if self.args.verbose:
                self.output.warning(f'Shodan API error for {ip}: {str(e)}')
            return {'error': f'Shodan API error: {str(e)}', 'ip': ip}
    
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
        if analysis['shodan_data'] and 'error' not in analysis['shodan_data']:
            for service in analysis['shodan_data'].get('smb_services', []):
                product = service.get('product', 'Unknown')
                version = service.get('version', 'Unknown')
                self.patterns['smb_versions'][f"{product} {version}"] += 1
                
            # OS patterns
            os_info = analysis['shodan_data'].get('os', 'Unknown')
            self.patterns['os_types'][os_info] += 1
            
            # ISP patterns
            isp = analysis['shodan_data'].get('isp', 'Unknown')
            self.patterns['isp_patterns'][isp] += 1
        
        # Failure reason patterns
        self.patterns['failure_reasons'][analysis['failure_classification']] += 1
        
        # Port status patterns
        port_status = analysis['network_analysis'].get('port_445_status', 'unknown')
        self.patterns['port_status'][port_status] += 1
        
        # Geographic patterns
        country = analysis['country']
        self.patterns['geographic_patterns'][country] += 1
        
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
        port_blocked = self.patterns['port_status'].get('closed_or_filtered', 0)
        signing_required = self.patterns['failure_reasons'].get('smb_signing_required', 0)
        encryption_required = self.patterns['failure_reasons'].get('smb_encryption_required', 0)
        auth_required = self.patterns['failure_reasons'].get('authentication_required', 0)
        
        report += f"""
KEY TECHNICAL FINDINGS
----------------------
1. Network Infrastructure Issues: {port_blocked} targets have port 445 inaccessible
2. Protocol Security: {signing_required + encryption_required} targets require enhanced security
3. Authentication Mechanisms: {auth_required} targets require credential-based authentication

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
- Shodan vulnerability correlations (if API available)
- Network timing and behavior patterns

STATUS: Analysis complete. Ready for follow-up technical questions.
"""
        
        return report
    
    def save_detailed_results(self, briefing):
        """Save detailed analysis results to JSON file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_file = f"failure_analysis_{timestamp}.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'analysis_results': self.analysis_results,
                    'patterns': {k: dict(v) for k, v in self.patterns.items()},
                    'briefing_report': briefing,
                    'metadata': {
                        'analysis_date': datetime.now().isoformat(),
                        'total_analyzed': len(self.analysis_results),
                        'shodan_api_available': self.api is not None,
                        'smb_libraries_available': SMB_AVAILABLE
                    }
                }, f, indent=2, default=str)
                
            self.output.success(f"Detailed analysis results saved to: {results_file}")
            
        except Exception as e:
            self.output.error(f"Failed to save detailed results: {e}")