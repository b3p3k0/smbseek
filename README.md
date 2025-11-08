# SMBSeek - Unified SMB Security Toolkit

**A defensive security toolkit for identifying SMB servers with weak authentication**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/username/smbseek)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Quick Start

```bash
# Create virtual environment
python3 -m venv smbseek_env     # You can name this anything you like
source smbseek_env/bin/activate # Linux/macOS
# OR: smbseek_env\Scripts\activate # Windows

# Install dependencies
pip install -r requirements.txt

# Configure API key (see Configuration section)
cp conf/config.json.example conf/config.json
# Edit conf/config.json with your Shodan API key

# Run global security assessment (discovery + share enumeration)
./smbseek.py

# Or scan specific country
./smbseek.py --country US
```

<details>
<summary><strong>New to Python virtual environments?</strong></summary>

A virtual environment is an isolated Python environment that keeps this project's dependencies separate from your system Python. This prevents conflicts and makes the project easier to manage.

**Quick explanation:**
- `python3 -m venv smbseek_env` creates a new virtual environment
- `source smbseek_env/bin/activate` activates it (you'll see the name in your prompt)
- Always activate the environment before running SMBSeek commands
- Use `deactivate` to exit the virtual environment when done

</details>

## Prerequisites

### System Requirements
- **Python 3.8+** (recommended: Python 3.10+)
- **smbclient** (required for full functionality, but tool works without it)
- **Valid Shodan API key** (free account available)

### SMB Background
SMBSeek identifies SMB (Server Message Block) servers with weak authentication. For technical background on SMB protocols and security considerations, see the [official Samba documentation](https://www.samba.org/samba/docs/).

### Installing smbclient

SMBSeek uses smbclient for share enumeration and provides fallback functionality if not available:

```bash
# Ubuntu/Debian
sudo apt install smbclient

# CentOS/RHEL/Fedora
sudo dnf install samba-client

# macOS (via Homebrew)
brew install samba
```

## Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd smbseek
```

2. **Create and activate virtual environment:**
```bash
python3 -m venv smbseek_env
source smbseek_env/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Configure SMBSeek:**
```bash
cp conf/config.json.example conf/config.json
```

## Configuration

### API Key Setup

1. Sign up for a free Shodan account at [shodan.io](https://shodan.io)
2. Copy your API key from your account dashboard
3. Edit `conf/config.json` and add your API key:

```json
{
  "shodan": {
    "api_key": "your_api_key_here"
  }
}
```

### Configuration Options

SMBSeek uses `conf/config.json` for all settings. Key configuration sections:

**Connection Settings:**
- `timeout`: SMB connection timeout in seconds (default: 30)
- `rate_limit_delay`: Delay between connections to avoid aggressive scanning (default: 1)
- `share_access_delay`: Delay between share access tests (default: 1)

**Workflow Settings:**
- `rescan_after_days`: How often to rescan previously discovered hosts (default: 90)
- `access_recent_hours`: Only test recently discovered hosts during access verification (default: 2)

**Security Settings:**
- `ransomware_indicators`: Filename patterns that indicate malware infection
- `exclusion_file`: Path to organization exclusion list

**Database Settings:**
- `path`: Database file location (default: smbseek.db)
- `backup_enabled`: Automatic backup creation (default: true)

See `conf/config.json.example` for complete configuration options with detailed explanations.

## Basic Usage

### Unified Workflow

SMBSeek 3.0+ uses a simplified single-command interface that performs discovery and share enumeration in one operation:

```bash
# Global scan for vulnerable SMB servers (recommended)
./smbseek.py

# Scan specific country
./smbseek.py --country US

# Global scan with verbose output
./smbseek.py --verbose

# Quiet mode (minimal output)
./smbseek.py --quiet
```

### Country-Specific Scanning

SMBSeek performs global scans by default. For country-specific scans, use the `--country` flag with ISO 3166-1 alpha-2 country codes (e.g., US, GB, CA, DE, JP). Multiple countries can be specified with comma separation:

```bash
./smbseek.py --country US,GB,CA    # Scan multiple countries
./smbseek.py --country DE          # Scan Germany only
```

## String-Based Searching

Target SMB banners that contain specific phrases or keywords using the `--string` flag (repeatable). SMBSeek automatically validates, de-duplicates, and quotes each value before inserting it into the Shodan query.

```bash
./smbseek.py --string Documents                     # Search for a single keyword (quoted in Shodan as "Documents")
./smbseek.py --string Documents --string "My Docs"  # Match hosts containing either Documents or "My Docs"
./smbseek.py --string "Finance Reports" --country US --verbose
```

**How it works:**
- Every `--string` argument becomes a quoted phrase in the Shodan query (multi-word values do not require manual quoting beyond shell requirements).
- All CLI-provided strings are combined using logical OR by default. You can change this behavior via `conf/config.json` (`string_combination`: `"AND"` or `"OR"`).
- Default strings can also be defined in `shodan.query_components.string_filters`; CLI values are appended to that list.
- Inputs longer than 100 characters or containing unsafe punctuation are rejected with a helpful error so you know exactly what to fix.
- Verbose mode displays how string filters are applied (`-v`/`--verbose`).

## Migration from 2.x

**⚠️ BREAKING CHANGES in SMBSeek 3.0.0**

The multi-command CLI has been replaced by a single streamlined entry point. Legacy subcommands now emit deprecation warnings before forwarding to the unified workflow.

**Old (deprecated):**
```bash
./smbseek.py run --country US       # ⚠️ Deprecated, forwards to unified workflow
./smbseek.py discover --country US  # ⚠️ Deprecated, forwards to unified workflow
./smbseek.py collect --download     # ❌ Removed
./smbseek.py report --executive     # ❌ Removed
```

**New (3.0+):**
```bash
./smbseek.py --country US           # ✅ Unified discovery + share enumeration
```

**What's Changed:**
- **Single workflow** – discovery and share access run sequentially in one command
- **File collection removed** – rely on third-party tooling if you need downloads
- **Reporting removed** – query `smbseek.db` or `tools/db_query.py` for insights
- **Database subcommands removed** – use `tools/db_*.py` scripts directly

## Database Operations

SMBSeek stores all results in a SQLite database (`smbseek.db`). Use the `tools/` scripts for analysis and maintenance:

```bash
# Summary statistics
python tools/db_query.py --summary

# Country distribution (from global scan results)
python tools/db_query.py --countries

# Database health / backups
python tools/db_maintenance.py --info
python tools/db_maintenance.py --backup

# Import historical data
python tools/db_import.py --csv legacy_results.csv
```

## Architecture Overview

SMBSeek 3.0 uses a streamlined single-command interface with modular backend components:

```
smbseek.py                    # Main CLI entry point (single command)
├── workflow.py              # Unified workflow orchestration
├── commands/                 # Backend operation modules
│   ├── discover.py          # Shodan queries + SMB authentication
│   ├── access.py            # Share enumeration and access testing
│   ├── run.py               # Legacy workflow (backward compatibility)
│   ├── collect.py           # Deprecated (stub)
│   ├── analyze.py           # Deprecated (stub)
│   ├── report.py            # Deprecated (stub)
│   └── database.py          # Deprecated (stub)
├── shared/                  # Common utilities and configuration
├── tools/                   # Database maintenance and query tools
└── conf/                    # Configuration files
```

### Database Schema

Core tables store discovery and access results:
- **smb_servers**: Server metadata (IP, country, authentication method, last seen)
- **scan_sessions**: Unified workflow executions
- **share_access**: Share accessibility findings per session
- **failure_logs**: Connection failures for later analysis
- **vulnerabilities** / **file_manifests**: Legacy tables retained for backward compatibility

## Troubleshooting

### Common Issues

**"SMB libraries not available" error:**
```bash
# Ensure virtual environment is activated
source smbseek_env/bin/activate
pip install -r requirements.txt
```

**Shodan API errors:**
- Verify API key in `conf/config.json`
- Check Shodan account quota and limits
- Ensure internet connectivity

**smbclient not found:**
- Install smbclient package (see Prerequisites section)
- SMBSeek provides fallback functionality if unavailable

**Permission denied errors:**
- Ensure database file (`smbseek.db`) is writable
- Check file permissions in project directory

### Connectivity Pre-Checks (Removed)

Early 2025 builds briefly performed a TCP 445 “connectivity pre-check” to reorder hosts before authentication. We removed that logic in November 2025 because it doubled pre-scan time without improving accuracy—modern guidance already recommends blocking SMB over untrusted networks, so second-pass warmups add noise without new signal. SMBSeek now authenticates targets immediately in the order provided, which shortens overall scan duration while still honoring per-host timeout and throttling controls.

### Getting Help

```bash
# General help
./smbseek.py --help

# Verbose output for debugging
./smbseek.py --verbose

# Database tools help
python tools/db_query.py --help
python tools/db_maintenance.py --help
```

## Related Projects

### xsmbseek - GUI Interface

[xsmbseek](https://github.com/b3p3k0/xsmbseek) provides a graphical user interface for SMBSeek, making it easier to visualize and interact with scan results. It offers:

- Interactive GUI for SMBSeek operations
- Visual representation of discovered SMB servers
- Simplified workflow for users who prefer graphical tools
- Real-time monitoring of scan progress

Check out the [xsmbseek repository](https://github.com/b3p3k0/xsmbseek) for installation and usage instructions.

## Development

### AI-Driven Development

SMBSeek represents a successful AI-human collaboration where Claude (Anthropic's AI assistant) handled complete technical implementation while humans provided domain expertise, testing, and strategic direction.

**Key Success Factors:**
- Trust and autonomy in AI technical implementation
- Iterative feedback loops with real-world testing
- Comprehensive documentation as a core deliverable
- Hybrid approaches combining Python libraries with external tools

### Contributing

1. Fork the repository
2. Create a feature branch
3. Test thoroughly against real SMB servers
4. Submit a pull request

## Operational Safety

SMBSeek 3.0+ implements **compatibility-by-default** to maximize discovery while providing optional security hardening for untrusted environments.

### Default Compatibility Mode

**Default Behavior (Legacy Compatible):**
- **Unsigned SMB sessions allowed** - Compatible with legacy/insecure servers
- **SMB1 protocol enabled** - Can connect to very old Windows systems
- **Maximum compatibility** - Works with all SMB protocol versions
- **Legacy system support** - Connects to older Windows and Samba implementations

```bash
# Default compatibility mode - maximum SMB server support
./smbseek.py --country US
```

### Enhanced Security Mode

**Cautious Mode (--cautious flag required):**
- **Signed SMB sessions required** - Rejects unsigned/insecure connections
- **SMB2+/3 protocols only** - Blocks legacy SMB1 connections
- **Modern security flags** - Uses latest smbclient hardening options
- **Enhanced authentication validation** - Stricter connection requirements

```bash
# Enhanced security mode - use for untrusted environments
./smbseek.py --country US --cautious
```

### When to Use Each Mode

**Use Default Mode when:**
- Performing comprehensive security assessments
- Scanning internal corporate networks
- Working with mixed legacy/modern infrastructure
- Prioritizing maximum compatibility and discovery

**Use Cautious Mode (--cautious) when:**
- Scanning unknown or untrusted networks
- Working from disposable/isolated environments
- Prioritizing security over maximum compatibility
- You need to enforce modern SMB security standards

### Operational Hygiene

**Network Isolation:**
- Use VPN connections to trusted networks when possible
- Deploy from disposable virtual machines for unknown network scanning
- Avoid running from privileged network segments or production systems
- Consider network segmentation to isolate scanning activities

**Environment Management:**
- **Use dedicated scanning VMs** that can be wiped after assessment
- **Limit credential exposure** - avoid running with domain administrator privileges
- **Monitor for detection** - scanning may trigger security alerts in target environments
- **Coordinate with defenders** - notify SOC teams of authorized scanning activities

**Data Handling:**
- Review database contents (`smbseek.db`) before copying to persistent storage
- Use `--quiet` mode in automated deployments to reduce log exposure
- Consider encrypted storage for assessment results containing sensitive findings
- Implement secure deletion procedures for temporary scanning environments

### Expected Behavior Differences

**Cautious Mode May Skip:**
- Very old Windows 2000/XP systems that only support SMB1
- Legacy Samba configurations with signing disabled
- Industrial control systems using outdated SMB implementations
- Network attached storage (NAS) devices with basic SMB support

**This trade-off is beneficial for high-security environments** because:
- Such systems indicate significant security debt requiring separate remediation
- Honeypots commonly masquerade as vulnerable legacy systems
- Modern infrastructure should support signed SMB2+/3 connections
- Security-focused scanning prioritizes current threats over legacy edge cases

### Mode Selection Examples

Use default mode for comprehensive discovery, cautious mode for secure environments:

```bash
# Default comprehensive global scan
./smbseek.py --verbose

# Enhanced security scan for untrusted networks
./smbseek.py --cautious --force-hosts 192.168.1.100,192.168.1.200

# Targeted security scan for specific country
./smbseek.py --country US --cautious --verbose
```

### Smbclient Compatibility

SMBSeek automatically detects smbclient version capabilities and falls back gracefully:

- **Modern Samba (4.11+):** Uses `--client-protection=sign` and advanced options
- **Legacy Samba:** Falls back to `--option=client signing=required` syntax
- **Missing smbclient:** Provides degraded functionality with clear warnings
- **Unsupported flags:** Automatically retries with compatible option syntax

## Security Considerations

### Intended Use
- Security auditing of owned networks
- Vulnerability assessment by authorized security professionals
- Educational purposes in controlled environments

### Built-in Safeguards
- **Safe-by-default SMB security** with optional legacy compatibility
- Organization exclusion lists to avoid scanning infrastructure providers
- Rate limiting to prevent aggressive scanning behavior
- Read-only operations (no modification of target systems)
- Country-based filtering to limit scan scope

## Legal and Ethical Use

**Important:** Only scan networks you own or have explicit written permission to test. This tool is designed for legitimate defensive security purposes only.

- Respect all applicable laws and regulations
- Use findings responsibly for defensive purposes
- Follow responsible disclosure practices
- Maintain ethical scanning practices with appropriate rate limits

## License

This project is licensed under the terms specified in the LICENSE file.

## Disclaimer

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.
