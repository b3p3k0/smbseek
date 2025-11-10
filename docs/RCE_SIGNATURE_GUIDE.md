# RCE Signature Guide

This guide explains how to manage and update RCE vulnerability signatures for SMBSeek's defensive security analysis.

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