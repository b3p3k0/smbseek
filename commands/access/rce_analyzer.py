from typing import Dict, Any


def analyze_rce_vulnerabilities(op, target_result: Dict[str, Any]) -> None:
    """
    Perform RCE vulnerability analysis on target host.
    """
    try:
        from shared.rce_scanner import scan_rce_indicators

        ip = target_result.get('ip_address', 'unknown')
        op.output.print_if_verbose(f"Performing RCE analysis for {ip}")

        host_context = {
            'ip_address': ip,
            'country': target_result.get('country', 'unknown'),
            'auth_method': target_result.get('auth_method', ''),
            'shares_found': target_result.get('shares_found', []),
            'accessible_shares': target_result.get('accessible_shares', []),
            'share_details': target_result.get('share_details', []),
            'timestamp': target_result.get('timestamp', '')
        }

        rce_result = scan_rce_indicators(host_context)
        target_result['rce_analysis'] = rce_result

        score = rce_result.get('score', 0)
        level = rce_result.get('level', 'unknown')
        status = rce_result.get('status', 'analyzed')

        if status == 'insufficient-data':
            op.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - Limited data available")
        elif op.output.verbose:
            matched_count = len(rce_result.get('matched_rules', []))
            if matched_count > 0:
                op.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - {matched_count} potential vulnerabilities detected")
                for rule in rce_result.get('matched_rules', [])[:2]:
                    rule_name = rule.get('name', 'Unknown')
                    rule_score = rule.get('score', 0)
                    op.output.print_if_verbose(f"  - {rule_name}: {rule_score} points")
            else:
                op.output.print_if_verbose(f"RCE Analysis: {score}/100 ({level}) - No specific vulnerabilities detected")
        else:
            op.output.info(f"RCE Analysis: {score}/100 ({level})")

    except ImportError:
        op.output.error("RCE scanner not available - missing dependencies")
        target_result['rce_analysis'] = {
            'score': 0,
            'level': 'error',
            'status': 'scanner-unavailable',
            'error': 'RCE scanner dependencies not found'
        }
    except Exception as e:
        op.output.error(f"RCE analysis failed for {target_result.get('ip_address', 'unknown')}: {str(e)}")
        target_result['rce_analysis'] = {
            'score': 0,
            'level': 'error',
            'status': 'analysis-failed',
            'error': str(e)
        }
