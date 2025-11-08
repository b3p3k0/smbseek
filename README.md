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
./smbseek

# Or scan specific country
./smbseek --country US
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
./smbseek

# Scan specific country
./smbseek --country US

# Global scan with verbose output
./smbseek --verbose

# Quiet mode (minimal output)
./smbseek --quiet
```

> **Security note:** Cautious mode (SMB signing + SMB2/SMB3) is now enabled automatically. Use `--legacy` only when you must talk to SMB1 or unsigned targets, and expect reduced protections when you do.

### Country-Specific Scanning

SMBSeek performs global scans by default. For country-specific scans, use the `--country` flag with ISO 3166-1 alpha-2 country codes (e.g., US, GB, CA, DE, JP). Multiple countries can be specified with comma separation:

```bash
./smbseek --country US,GB,CA    # Scan multiple countries
./smbseek --country DE          # Scan Germany only
```

## String-Based Searching

Target SMB banners that contain specific phrases or keywords using the `--string` flag (repeatable). SMBSeek automatically validates, de-duplicates, and quotes each value before inserting it into the Shodan query.

```bash
./smbseek --string Documents                     # Search for a single keyword (quoted in Shodan as "Documents")
./smbseek --string Documents --string "My Docs"  # Match hosts containing either Documents or "My Docs"
./smbseek --string "Finance Reports" --country US --verbose
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
repo root
├── smbseek               # CLI launcher (entry point for unified workflow)
├── gui/
│   ├── xsmbseek          # GUI launcher (xSMBSeek)
│   ├── components/       # Tkinter windows, dialogs, and widgets
│   └── utils/            # GUI helpers (backend interface, sandbox, extract, etc.)
├── commands/             # Discovery + access operation modules used by the CLI
├── shared/               # Configuration, database, output, and utility helpers
├── tools/                # Database maintenance scripts and reporting utilities
├── conf/                 # Configuration files and examples
├── docs/                 # Project documentation (guides, changelog, etc.)
└── tests/                # Unit/integration tests for CLI and GUI features
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
./smbseek --help

# Verbose output for debugging
./smbseek --verbose

# Database tools help
python tools/db_query.py --help
python tools/db_maintenance.py --help
```

## Graphical User Interface

xSMBSeek (the graphical companion now bundled in this repository) provides a full GUI for the same backend data, so CLI and GUI users share one codebase. The original xsmbseek repository remains publicly archived for historical reference, but all active development lives here.

### Launching the GUI

```bash
# Activate your virtual environment first
source venv/bin/activate

# Launch the GUI (xSMBSeek)
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

**Controlled Extraction:**

- Launch per-host file collection runs with configurable limits for file size, total bytes, runtime, and count
- Results are automatically quarantined under `~/.smbseek/quarantine/<purpose>/<timestamp>` alongside JSON audit logs
- Analysts review and promote quarantined artifacts manually, keeping risky files out of trusted folders by default

### Sandbox Share Browsing (Linux)

- When Podman or Docker is installed, the Server Details window shows a **Sandbox Shares** button that lists shares via `smbclient` running inside a throwaway container.
- The host OS never opens the remote share; all enumeration happens inside the sandbox and the output is streamed back into the GUI.
- If a supported container runtime is not detected, the button stays disabled so operators know they are outside the sandboxed path.

#### macOS and Windows (experimental)

We have not validated the sandbox workflow on macOS or Windows yet, but the tools listed below may work in theory. Feedback and PRs are very welcome—treat these as starting points, not official support.

- **macOS (theoretical)**: install [Colima](https://github.com/abiosoft/colima) or Podman Desktop, then run `colima start --network-address`. Pull the same `docker.io/library/alpine:latest` image and verify `podman run --rm --network host alpine:latest sh -c "apk add --no-cache samba-client && smbclient --help"` succeeds. Finally, start xsmbseek from a terminal that inherits the Colima/Podman environment so the sandbox button can detect the CLI.
- **Windows (theoretical)**: enable WSL2, install Ubuntu from the Store, and inside that distro install Podman (`sudo apt install podman`). In PowerShell, set `PODMAN_HOST` to your WSL distribution (e.g., `wsl -d Ubuntu podman info`). Pull `docker.io/library/alpine:latest` inside WSL, then launch xsmbseek from the same shell so the detection logic can find `podman.exe` on PATH.

<details>
<summary><strong>Setting up the sandbox runtime (Ubuntu, Fedora, Arch)</strong></summary>

Pick the distro you care about, paste the block, and you’ll have Podman plus the lightweight Alpine image we use for `smbclient` inside the sandbox. You can swap in Docker if you prefer, but Podman stays rootless by default.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y podman
podman info >/dev/null && podman pull docker.io/library/alpine:latest

# Fedora / RHEL
sudo dnf install -y podman
podman info >/dev/null && podman pull docker.io/library/alpine:latest

# Arch / Manjaro
sudo pacman -Sy --noconfirm podman
podman info >/dev/null && podman pull docker.io/library/alpine:latest
```

Verification tip: run `podman run --rm --network host alpine:latest sh -c "apk add --no-cache samba-client && smbclient --help"`. Once that succeeds, relaunch xsmbseek and the **Sandbox Shares** button should enable itself automatically.

</details>

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
