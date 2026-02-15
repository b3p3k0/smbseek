from typing import Dict, Any


def analyze_rce_vulnerabilities(op, target_result: Dict[str, Any]) -> None:
    """Perform RCE vulnerability analysis using op's existing config/database."""
    ip = target_result.get('ip_address', 'unknown')

    try:
        # Acquire shared probe runner from operation (created once per scan)
        probe_runner = getattr(op, '_probe_runner', None)
        if probe_runner is None and op.check_rce:
            from shared.rce_scanner.probes import SafeProbeRunner
            legacy_mode = getattr(op, 'legacy_mode', False)
            probe_runner = SafeProbeRunner(op.config, legacy_mode=legacy_mode)

        # Reset probe budget for this host
        if probe_runner:
            probe_runner.reset_for_host(ip)

        host_context = _build_host_context(target_result)

        # Run safe-active probes to enrich context
        if probe_runner:
            host_context = _run_safe_probes(probe_runner, ip, host_context)

        from shared.rce_scanner import scan_rce_indicators
        rce_result = scan_rce_indicators(host_context)
        target_result['rce_analysis'] = rce_result

        # Persist status using existing database handle
        _persist_rce_status(op.database, ip, rce_result)

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
        op.output.error(f"RCE analysis failed for {ip}: {str(e)}")
        target_result['rce_analysis'] = {
            'score': 0,
            'level': 'error',
            'status': 'analysis-failed',
            'error': str(e)
        }


def _build_host_context(target_result: Dict[str, Any]) -> Dict[str, Any]:
    """Build host context from access results."""
    return {
        'ip_address': target_result.get('ip_address', 'unknown'),
        'country': target_result.get('country', 'unknown'),
        'auth_method': target_result.get('auth_method', ''),
        'shares_found': target_result.get('shares_found', []),
        'accessible_shares': target_result.get('accessible_shares', []),
        'share_details': target_result.get('share_details', []),
        'timestamp': target_result.get('timestamp', '')
    }


def _run_safe_probes(probe_runner, ip: str, host_context: Dict[str, Any]) -> Dict[str, Any]:
    """Run negotiate and optional MS17-010 probes; update host_context."""
    negotiate_result = probe_runner.run_negotiate_probe(ip)
    if negotiate_result.get('error') is None:
        host_context['smb_dialect'] = negotiate_result.get('smb_dialect')
        host_context['signing_required'] = negotiate_result.get('signing_required', False)
        host_context['compression_algos'] = negotiate_result.get('compression_algos', [])
        host_context['smb1_possible'] = negotiate_result.get('smb1_possible', False)

    # Legacy-only MS17-010 check (respects probe budget)
    if probe_runner.legacy_mode:
        ms17_result = probe_runner.run_ms17_010_probe(ip)
        if ms17_result.get('status') is not None:
            host_context['ms17_010_status'] = ms17_result.get('status')
        if ms17_result.get('verdict'):
            host_context['ms17_010_verdict'] = ms17_result.get('verdict').value if hasattr(ms17_result.get('verdict'), 'value') else ms17_result.get('verdict')

    return host_context


def _persist_rce_status(database, ip: str, rce_result: Dict[str, Any]) -> None:
    """Persist RCE status using the workflow's existing database handle."""
    import json
    rce_status = rce_result.get('rce_status', 'not_run')

    verdict_summary = json.dumps({
        'verdict': rce_result.get('verdict'),
        'score': rce_result.get('score'),
        'findings': rce_result.get('findings', [])[:5],
        'not_assessable_reasons': rce_result.get('not_assessable_reasons', []),
        'timestamp': rce_result.get('timestamp')
    })

    try:
        database.upsert_rce_status(ip, rce_status, verdict_summary)
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f\"Failed to persist RCE status: {e}\")
