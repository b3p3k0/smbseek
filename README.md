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

### System Package Dependencies (non-pip)

SMBSeek ships its Python libraries via `requirements.txt`, but a handful of host packages still need to come from your distro package manager:

| Package | Why it matters |
| --- | --- |
| `python3`, `python3-venv` | Core interpreter plus the stdlib `venv` module that creates the isolated environment used in every quick-start command. |
| `python3-pip` | Ensures `pip install -r requirements.txt` is available even on minimal images. |
| `python3-tk` | Provides the Tk bindings that power the `xsmbseek` GUI; without it the launcher errors with `ModuleNotFoundError: tkinter`. |
| `smbclient` | Enables native share enumeration and access testing; the CLI falls back to reduced functionality if it is missing. |

##### Ubuntu 24.04 LTS / Debian-based

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip python3-tk smbclient
```

##### RHEL 9 / Fedora / AlmaLinux / Rocky

```bash
sudo dnf install -y python3 python3-pip python3-tkinter samba-client
```

##### openSUSE Leap / Tumbleweed

```bash
sudo zypper install -y python3 python3-pip python3-tk samba-client
```

##### Arch / Manjaro

```bash
sudo pacman -Syu --needed python python-pip tk samba
```

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
git clone https://github.com/b3p3k0/smbseek
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

1. Sign up for a Shodan membership at [shodan.io](https://shodan.io) (one-time paid membership required for API access)
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

**File Browser Settings (GUI):**

- `file_browser.allow_smb1`: Allow SMB1 targets (default: true)
- `file_browser.connect_timeout_seconds` / `request_timeout_seconds`: Network timeouts
- `file_browser.max_entries_per_dir`, `max_depth`, `max_path_length`: Safety limits for listing
- `file_browser.quarantine_root`: Where downloads are staged (default: `~/.smbseek/quarantine`)

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
```

## RCE Vulnerability Analysis

SMBSeek includes optional RCE (Remote Code Execution) vulnerability analysis that identifies known SMB-related security issues using signature-based detection. This defensive feature analyzes enumeration results for vulnerability indicators without performing active exploitation.

### CLI Usage

Enable RCE analysis during share access testing:

```bash
./smbseek --country US --check-rce               # Include RCE analysis in scan
./smbseek --country US --check-rce --verbose     # RCE analysis with detailed output
```

**How it works:**
- Analyzes SMB enumeration data against known vulnerability signatures
- Scores potential RCE risks from 0-100 with confidence levels
- Reports matched vulnerability signatures (CVE references included)
- All results marked as "low confidence" during initial implementation
- No active exploitation or vulnerability testing performed

**Sample output:**
```
RCE Analysis: 45/100 (medium, low confidence)
  Matched Signatures: 1
    - EternalBlue: 45 points (high severity)
  Evidence: 2 indicators
    - Condition met: Vulnerability requires SMB1 dialects
    - Condition met: Host lacks MS17-010 patch
```

### GUI Usage

1. Open the scan dialog in SMBSeek GUI
2. Check "Check for RCE vulnerabilities during share access testing"
3. Run your scan normally
4. RCE analysis results appear in probe details alongside share enumeration

### Signature Management

RCE signatures are stored in `signatures/rce_smb/` as YAML files. The system includes signatures for major SMB vulnerabilities:

- **EternalBlue** (CVE-2017-0144) - MS17-010 SMB1 vulnerability
- **SMBGhost** (CVE-2020-0796) - SMB3 compression vulnerability
- **ZeroLogon** (CVE-2020-1472) - Netlogon privilege escalation
- **PrintNightmare** (CVE-2021-34527) - Print Spooler RCE
- **PetitPotam** (CVE-2021-36942) - NTLM relay vulnerability

See [`docs/guides/RCE_SIGNATURE_GUIDE.md`](docs/guides/RCE_SIGNATURE_GUIDE.md) for detailed signature management instructions.

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
│   └── utils/            # GUI helpers (backend interface, probe, extract, etc.)
├── commands/             # Discovery + access operation modules used by the CLI
├── shared/               # Configuration, database, output, and utility helpers
├── tools/                # Database maintenance scripts and reporting utilities
├── conf/                 # Configuration files and examples
├── docs/                 # Project documentation
│   ├── guides/           # User-facing guides (CLI, GUI, extract, file browser, RCE)
│   ├── operations/       # Migration and ops runbooks
│   ├── dev/              # Dev notes, collaboration, integration guides, roadmap
│   ├── release/          # Changelog and release notes
│   └── archive/          # Deprecated references
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
- Toggle security mode (Cautious by default, Legacy when you explicitly need SMB1/unsigned access)

**Probe Functionality:**

- Deep enumeration of accessible shares
- Ransomware indicator detection
- Directory structure exploration
- Cached results for quick access

**Configuration Management:**

- Visual configuration editor
- Settings persistence across sessions
- Real-time validation of inputs

**Read-only File Browser:**

- Browse accessible shares directly in the GUI (no previews/execution)
- SMB1/2/3 compatible with configurable timeouts and listing caps
- Single action: download selected file to quarantine (`~/.smbseek/quarantine/<timestamp>/<host>/<share>/`)

**Controlled Extraction:**

- Launch per-host file collection runs with configurable limits for file size, total bytes, runtime, and count
- Results are automatically quarantined under `~/.smbseek/quarantine/<purpose>/<timestamp>` alongside JSON audit logs
- Analysts review and promote quarantined artifacts manually, keeping risky files out of trusted folders by default
- See [`docs/guides/EXTRACT_WORKFLOW_GUIDE.md`](docs/guides/EXTRACT_WORKFLOW_GUIDE.md) for architecture details, safeguards, and troubleshooting advice.

See `docs/guides/XSMBSEEK_USER_GUIDE.md` for comprehensive GUI documentation.

## Development

### AI-Human Collaboration

This project demonstrates effective AI-human partnership in software development. AI agents handled technical implementation and documentation while humans provided domain expertise, real-world testing, and strategic guidance.

**Core Collaboration Principles:**

- **Clear role separation**: AI owns implementation consistency; humans validate against reality
- **Documentation as code**: Architecture notes, changelogs, and inline docs updated with every change
- **Iterative validation**: Rapid prototyping followed by real-world testing and refinement
- **Configuration-driven design**: Sensible defaults with comprehensive customization options

See `docs/dev/AI_AGENT_FIELD_GUIDE.md` and `docs/dev/COLLAB.md` for detailed collaboration patterns and best practices.

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

## Legal and Ethical Use

**Important:** Only scan networks you own or have explicit written permission to test. This tool is designed for legitimate defensive security purposes only.

- Respect all applicable laws and regulations
- Use findings responsibly for defensive purposes
- Follow responsible disclosure practices
- Maintain ethical scanning practices with appropriate rate limits

## Wordlists for Pry

- Download a wordlist such as `rockyou.txt` from the awesome-wordlists collection: https://github.com/gmelodie/awesome-wordlists
- Set `pry.wordlist_path` in `conf/config.json` (default points to `conf/wordlists/rockyou.txt` if you place it there) or override in GUI settings.

## Credits

- Pry password audit is inspired by the mmcbrute project (BSD-3-Clause) by Corey Gilks; SMB authentication brute logic references that work. Repository: https://github.com/gcarq/mmcbrute (license copy in `licenses/mmcbrute-BSD-3-Clause.txt`).
- Recommended wordlists come from the awesome-wordlists collection (Apache-2.0). Source: https://github.com/gmelodie/awesome-wordlists (license copy in `licenses/awesome-wordlists-APACHE-2.0.txt`).

## License

This project is licensed under the terms specified in the LICENSE file.
Third-party components referenced by Pry include licenses stored in `licenses/`.

## Disclaimer

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.
