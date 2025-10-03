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

# Run complete security assessment (discovery + share enumeration)
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
# Scan United States for vulnerable SMB servers
./smbseek.py --country US

# Scan with verbose output
./smbseek.py --country US --verbose

# Scan globally (uses configuration defaults)
./smbseek.py

# Quiet mode (minimal output)
./smbseek.py --country US --quiet
```

### Available Countries

SMBSeek supports country-specific scanning using two-letter country codes:
- `US` - United States
- `GB` - United Kingdom
- `CA` - Canada
- `IE` - Ireland
- `AU` - Australia
- `NZ` - New Zealand
- `ZA` - South Africa

Or scan globally by omitting the `--country` parameter.

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

# Country distribution
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

### Getting Help

```bash
# General help
./smbseek.py --help

# Verbose output for debugging
./smbseek.py --country US --verbose

# Database tools help
python tools/db_query.py --help
python tools/db_maintenance.py --help
```

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

## Security Considerations

### Intended Use
- Security auditing of owned networks
- Vulnerability assessment by authorized security professionals
- Educational purposes in controlled environments

### Built-in Safeguards
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
