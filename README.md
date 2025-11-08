# SMBSeek - Unified SMB Security Toolkit

**A defensive security toolkit for identifying SMB servers with weak authentication**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/username/smbseek)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Quick Start

```bash
# Create virtual environment
python3 -m venv venv            # You can name this anything you like
source venv/bin/activate        # Linux/macOS
# OR: venv\Scripts\activate      # Windows

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
- `python3 -m venv venv` creates a new virtual environment
- `source venv/bin/activate` activates it (you'll see the name in your prompt)
- Always activate the environment before running SMBSeek commands
- Use `deactivate` to exit the virtual environment when done

</details>

## Prerequisites

### System Requirements
- **Python 3.8+** (recommended: Python 3.10+)
- **smbclient** (required for full functionality, but tool works without it)
- **Valid Shodan API key** (paid membership required)

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
python3 -m venv venv
source venv/bin/activate
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

1. Sign up for a Shodan membership at [shodan.io](https://shodan.io) (paid membership required for API access)
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

> **Security note:** Cautious mode (SMB signing + SMB2/SMB3) is now enabled automatically. Use `--legacy` only when you must talk to SMB1 or unsigned targets, and expect reduced protections when you do.

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
source venv/bin/activate
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
./smbseek.py --verbose

# Database tools help
python tools/db_query.py --help
python tools/db_maintenance.py --help
```

## Graphical User Interface

SMBSeek includes a graphical interface for users who prefer visual interaction with scan results and configuration.

### Launching the GUI

```bash
# Activate your virtual environment first
source venv/bin/activate

# Launch the GUI
./xsmbseek
```

### Key Features

The GUI provides an intuitive interface for SMBSeek operations:

**Server List Management:**
- View all discovered SMB servers with detailed information
- Filter and sort servers by country, authentication method, or accessibility
- Real-time status updates during scanning operations
- Server detail view with share enumeration results

**Advanced Scanning:**
- Configure country-specific or global scans
- Set custom Shodan result limits and filters
- Control rescan behavior for existing hosts
- Override API keys per-scan without editing configuration files

**Probe Functionality:**
- Deep enumeration of accessible shares
- Ransomware indicator detection
- Directory structure exploration
- Cached results for quick access

**Configuration Management:**
- Visual configuration editor
- Settings persistence across sessions
- Real-time validation of inputs

### Sandbox Share Browsing (Linux)
- When Podman or Docker is installed, the Server Details window shows a **Sandbox Shares** button that lists shares via `smbclient` running inside a throwaway container.
- The host OS never opens the remote share; all enumeration happens inside the sandbox and the output is streamed back into the GUI.
- If a supported container runtime is not detected, the button stays disabled so operators know they are outside the sandboxed path.

See `docs/XSMBSEEK_USER_GUIDE.md` for comprehensive GUI documentation.

## Development

### AI-Human Collaboration

This project demonstrates effective AI-human partnership in software development. AI agents handled technical implementation and documentation while humans provided domain expertise, real-world testing, and strategic guidance.

**Core Collaboration Principles:**
- **Clear role separation**: AI owns implementation consistency; humans validate against reality
- **Documentation as code**: Architecture notes, changelogs, and inline docs updated with every change
- **Iterative validation**: Rapid prototyping followed by real-world testing and refinement
- **Configuration-driven design**: Sensible defaults with comprehensive customization options

See `docs/AI_AGENT_FIELD_GUIDE.md` and `docs/COLLAB.md` for detailed collaboration patterns and best practices.

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
- Cautious mode (SMB signing + SMB2/SMB3 dialects) enabled by default; use `--legacy` only when you explicitly need SMB1/unsigned access
- GUI extractions are quarantined under `~/.smbseek/quarantine/<purpose>/<timestamp>` so analysts can inspect artifacts before promoting them
- Optional Linux sandbox for share browsing keeps risky enumeration inside Podman/Docker containers

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
