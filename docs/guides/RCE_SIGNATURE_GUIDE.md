# RCE Signature Guide

This guide explains how to manage and update RCE vulnerability signatures for SMBSeek's defensive security analysis.

## RCE Matching at a Glance

SMBSeek already needs to peek at each server just enough to list shares and note basic SMB behavior. The RCE matcher simply reuses those observations to estimate risk—no packets beyond what we were already sending, no exploit attempts, and no guesses based on internet rumor. Every alert references a real CVE (e.g., EternalBlue, ZeroLogon) and comes with a human-readable sentence so busy responders know why a host deserves extra attention.

Put differently, we look at the same clues a seasoned responder would jot down in a notebook: Which shared folders are visible? Does the server still speak the decade-old SMB1 dialect? Can we see system roles like `NETLOGON`/`SYSVOL` that suggest it is a domain controller? When those puzzle pieces line up with well-known attack stories, we flag the host. No code is run on the target—we’re matching “looks like” patterns the way a doctor matches symptoms to a diagnosis.

Key promises:
- **Passive only.** We never poke a system harder than the normal probe.
- **Named findings.** Results cite the CVE family that triggered the heuristic.
- **Actionable scores.** Analysts see “RCE Analysis: 60/100 (medium)” instead of rummaging through logs.

### Limitations & Risks

- **Telemetry dependent.** If a probe cannot authenticate or enumerate shares, the engine simply reports “insufficient data.” Lack of coverage is a feature, but it also means low-visibility hosts will never receive a meaningful score.
- **Heuristics ≠ proof.** A matched signature signals “configuration looks like CVE-XXXX” — it is not confirmation that the exploit is still feasible or that compromise occurred. All reports intentionally stay at “low confidence.”
- **Manual signature upkeep.** Because every rule is hand-authored, coverage only grows when an analyst adds a new YAML file. Expect a lag between emerging CVEs and signature availability.
- **Context modifiers mirror attacker bias.** Bonuses for anonymous access, SMB1, or admin shares assume the environment behaves like typical Windows networks. Highly customized deployments may need bespoke modifiers to avoid false positives/negatives.
- **Local-only insight.** The scanner never calls out to external feeds. If your inventory lacks Shodan data or OS hints, the engine cannot infer them on its own.

## How the Engine Works (and Why You Can Trust It)

```
Probe / Access data
  (shares, SMB dialects, auth hints)
        │
        ▼
+-----------------+
| Fact Collector  |  → normalized signals + missing-telemetry log
+-----------------+
        │
        ▼
+-----------------+
| Signature Engine|  → YAML rules check those signals
+-----------------+
        │
        ▼
+-----------------+
| Scoring Model   |  → additive score + context modifiers
+-----------------+
        │
        ▼
+-----------------+
| Reporter        |  → GUI summary + cached report
+-----------------+
```

1. **Deterministic inputs.** `FactCollector` converts whatever telemetry we gathered into canonical signals like `supports_smb1`, `has_netlogon_share`, `host.os_detection`, etc. Because every signature consumes the same schema, adding a new rule cannot silently change existing results.
2. **Schema-enforced rules.** YAML files must pass `SignatureValidator` before loading. Missing sections, malformed CVE IDs, or out-of-range weights are rejected up front, so the engine never runs half-baked heuristics.
3. **Additive scoring with transparent modifiers.** `RCEScorer` just sums rule weights and contextual bonuses (admin share access, anonymous auth, SMB1). There is no ML model: identical inputs always produce identical scores, capped at 100.
4. **Human-auditable evidence.** `RCEReporter` records which rules matched, the evidence strings they produced, and the normalized facts consulted. Analysts can follow the breadcrumbs from “ZeroLogon flagged” straight to “NETLOGON + SYSVOL observed, IPC$ accessible.”
5. **Safe failure modes.** Missing telemetry results in an “insufficient-data” verdict instead of speculation. If the scanner or a dependency is unavailable, the GUI says so rather than returning stale data.

With those guarantees in place, the rest of this document focuses on how to author and maintain the YAML signatures that fuel the engine.

## Overview

SMBSeek includes a signature-based RCE (Remote Code Execution) vulnerability detection system that analyzes SMB enumeration results for known security issues. The system uses YAML-based signature files that describe vulnerability patterns and scoring heuristics.

## Signature Schema

RCE signatures are stored in `signatures/rce_smb/` as YAML files. Each signature follows this structure:

### Required Sections

#### Metadata
```yaml
metadata:
  cve_ids:
    - CVE-YYYY-NNNN  # List of related CVE identifiers
  name: "Vulnerability Name"  # Human-readable name
  severity: high  # One of: low, medium, high, critical
  description: >-
    Multi-line description of the vulnerability
    and its impact on SMB services.
```

#### Heuristic
```yaml
heuristic:
  required_signals: 2  # Minimum conditions that must match
  base_weight: 45  # Base score contribution (0-100)
  risk_band: high  # One of: low, minimal, medium, moderate, high
  conditions:
    - signal: smb.negotiation.supports_smb1
      expectation: true
      rationale: Vulnerability requires SMB1 dialects.
  boosters:  # Optional score modifiers
    - description: Anonymous access enabled increases exploit risk.
      weight: 10
```

### Optional Sections

#### Telemetry
Documents data sources and needed enhancements:
```yaml
telemetry:
  existing_sources:
    - smb_negotiation  # Available data sources
    - access_runner
  needed_enhancements:
    - ms17_010_check  # Future data collection needs
```

#### References
External documentation links:
```yaml
references:
  - label: Microsoft Security Bulletin
    url: https://docs.microsoft.com/...
  - label: MITRE CVE
    url: https://cve.mitre.org/...
```

#### Notes
Implementation and reporting guidance:
```yaml
notes:
  remediation_summary: Apply patches and disable SMB1.
  reporting_tip: Highlight high severity due to exploit availability.
```

## Signal Types

The RCE scanner recognizes these signal types in conditions:

### SMB Protocol Signals
- `smb.negotiation.supports_smb1` - Boolean: SMB1 dialect support
- `smb.negotiation.supports_smb2` - Boolean: SMB2 dialect support
- `smb.negotiation.supports_smb3` - Boolean: SMB3 dialect support
- `smb.negotiation.signing_required` - Boolean: SMB signing enforcement
- `smb.negotiation.encryption_supported` - Boolean: SMB encryption available

### Host Information Signals
- `host.os_detection` - String: Detected operating system
- `host.shares_accessible` - Boolean: Any shares accessible
- `host.admin_shares_accessible` - Boolean: Administrative shares accessible
- `host.anonymous_access` - Boolean: Anonymous/guest access allowed
- `host.shodan_ports` - List: Open ports from Shodan data
- `host.shodan_vulns` - List: Known vulnerabilities from Shodan

### Authentication Signals
- `host.auth_method` - String: Authentication method used
- `host.username` - String: Username from auth method
- `host.has_password` - Boolean: Password provided in auth

## Expectation Types

Condition expectations can be:
- **Boolean**: `true` or `false`
- **String**: Direct string match or substring search
- **Special values**:
  - `"missing"` - Signal is empty/null
  - `"present"` - Signal has any value

## Scoring Model

The RCE scanner uses an additive scoring model:
1. **Base Score**: Each matched signature contributes its `base_weight`
2. **Boosters**: Applied when signature-specific conditions are met
3. **Context Modifiers**: Applied based on host facts:
   - Administrative access: +10
   - Anonymous access: +8
   - Multiple accessible shares (>3): +5
   - Known vulnerabilities from Shodan: +5 per vuln (max +15)
   - SMB1 support: +12 (legacy protocol risk)
   - SMB signing required: -3 (security feature)
   - SMB encryption supported: -3 (security feature)
4. **Final Score**: Sum capped at 100

Risk levels:
- **Low**: 0-24
- **Medium**: 25-59
- **High**: 60-84
- **Critical**: 85-100

All results are marked as "low confidence" during the initial implementation phase.

## Adding New Signatures

To add a new RCE signature:

1. Create a new YAML file in `signatures/rce_smb/` named `CVE-YYYY-NNNN.yaml`
2. Follow the schema structure above
3. Test the signature loads without validation errors
4. Restart SMBSeek to pick up the new signature

### Example: Creating a New Signature

```yaml
# signatures/rce_smb/CVE-2023-1234.yaml
metadata:
  cve_ids:
    - CVE-2023-1234
  name: Example SMB Vulnerability
  severity: medium
  description: >-
    Example vulnerability affecting SMB2/3 implementations
    that allows remote code execution.

heuristic:
  required_signals: 2
  base_weight: 30
  risk_band: medium
  conditions:
    - signal: smb.negotiation.supports_smb2
      expectation: true
      rationale: Vulnerability affects SMB2 implementations.
    - signal: host.os_detection
      expectation: windows
      rationale: Windows-specific vulnerability.

telemetry:
  existing_sources:
    - smb_negotiation
    - os_detection
  needed_enhancements:
    - version_detection

references:
  - label: MITRE CVE
    url: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-1234
```

## Manual Update Process

1. **Research**: Identify new SMB-related RCE vulnerabilities
2. **Document**: Create signature YAML following the schema
3. **Validate**: Test signature loads without errors
4. **Deploy**: Place file in `signatures/rce_smb/` directory
5. **Verify**: Check SMBSeek recognizes the new signature

## Validation Rules

The signature validator enforces:
- Required sections: `metadata`, `heuristic`
- Required metadata fields: `cve_ids`, `name`, `severity`, `description`
- Required heuristic fields: `required_signals`, `base_weight`, `risk_band`, `conditions`
- Valid severity values: `low`, `medium`, `high`, `critical`
- Valid risk_band values: `low`, `minimal`, `medium`, `moderate`, `high`
- Numeric constraints: `base_weight` (0-100), `required_signals` (≥1), booster `weight` (≥0)
- CVE ID format: Must start with `CVE-`
- URL format: Must use `http://` or `https://`

## Troubleshooting

### Signature Won't Load
- Check YAML syntax with a YAML validator
- Verify all required fields are present
- Ensure CVE IDs start with `CVE-`
- Check that risk_band uses valid values

### Scanner Returns No Results
- Verify signatures are loading (check logs)
- Confirm signal names match available data
- Test with simplified conditions
- Check expectation format matches signal type

### Low Scores Despite Vulnerabilities
- Review context modifiers (may need more host facts)
- Consider adjusting base_weight values
- Add relevant boosters for the vulnerability
- Ensure required_signals threshold is appropriate

## Security Considerations

- **Manual Updates Only**: No automatic signature downloads to prevent supply chain attacks
- **Defensive Focus**: Signatures identify vulnerabilities, not exploitation techniques
- **Low Confidence**: All results explicitly marked as preliminary analysis
- **Read-Only**: No active vulnerability testing or exploitation

## Future Enhancements

Planned improvements to the signature system:
- Confidence scoring based on telemetry quality
- Time-based signature aging
- CVE severity correlation
- Signature performance metrics
- Community signature sharing (with validation)

For questions or issues with signature management, consult the SMBSeek documentation or project maintainers.
