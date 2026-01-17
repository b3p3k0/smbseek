# SMBSeek

**A GUI toolkit for identifying and assessing SMB servers with weak authentication**

SMBSeek helps security teams discover SMB servers accessible without credentials or with guest access, then assess what data exposure that represents. The xSMBSeek GUI handles everything from Shodan-based discovery through password auditing and file extraction, with safety guardrails built in.

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/b3p3k0/smbseek)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Quick Start

Get the GUI running:

```bash
python3 -m venv venv
source venv/bin/activate         # venv\Scripts\activate on Windows
pip install -r requirements.txt
cp conf/config.json.example conf/config.json
# Edit conf/config.json to add your Shodan API key
./xsmbseek
```

**System requirements:** Install `python3-tk` and `smbclient` via your package manager before running the above commands.

**For password auditing:** Download [SecLists](https://github.com/danielmiessler/SecLists) and set `pry.wordlist_path` in your config to point at your wordlist.

---

## What You Can Do

### Dashboard

- Launch scans filtered by country or run global searches
- Open the Server List to work with discovered hosts
- Edit configuration through the built-in config editor

### Server List

- **Probe** hosts to enumerate shares and detect ransomware indicators
- **Browse** shares read-only to explore directory structures
- **Extract** files with hard limits on count, size, and runtime (quarantined output)
- **Pry** tests weak passwords against a single host/share/user combination

### Browse Mode

- Read-only navigation through SMB shares
- Download individual files or entire folders into quarantine
- No modification of remote systems
- Built-in file browser with configurable download limits

### Extract Mode

- Bounded file collection with configurable limits
- Automatic quarantine of all collected files
- Size, count, and time constraints prevent runaway operations

### Pry Mode

- Username + wordlist password audit
- Optional username-as-password testing
- Lockout-safe defaults (configurable delays and attempt limits)
- Real-time progress updates
- This is currently implemented as a novelty; better options probably exist

All operations respect rate limits, enforce cautious SMB settings (SMB2+/signing), and provide clear feedback on what's happening.

---

## Prerequisites

- **Python 3.8+** (Python 3.10+ recommended)
- **System packages:**
  - `python3-tk` (Tkinter GUI library)
  - `smbclient` (for share access testing)
  - `python3-venv` and `python3-pip`
- **Shodan API key** (requires paid Shodan membership - get one at [shodan.io](https://shodan.io))

### Installing System Packages

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3-tk smbclient python3-venv python3-pip
```

**Fedora/RHEL:**
```bash
sudo dnf install python3-tkinter samba-client python3-virtualenv python3-pip
```

**Arch Linux:**
```bash
sudo pacman -S tk smbclient python-virtualenv python-pip
```

---

## Installation

1. **Clone the repository:**

```bash
git clone https://github.com/b3p3k0/smbseek
cd smbseek
```

1. **Create virtual environment:**

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

1. **Install dependencies:**

```bash
pip install -r requirements.txt
```

1. **Set up configuration:**

```bash
cp conf/config.json.example conf/config.json
```

Edit `conf/config.json` and add your Shodan API key to the `shodan.api_key` field.

1. **Verify installation:**

```bash
./xsmbseek
```

The GUI should launch. If you see errors about missing modules, check that your virtual environment is activated and dependencies installed correctly.

---

## Configuration

SMBSeek reads all settings from `conf/config.json`. Key sections for GUI users:

### Shodan API Key

Required for discovery operations:

```json
{
  "shodan": {
    "api_key": "your_api_key_here"
  }
}
```

Get your API key from [shodan.io](https://shodan.io) after signing up for a paid membership.

### Pry (Password Audit) Settings

```json
{
  "pry": {
    "wordlist_path": "conf/wordlists/rockyou.txt",
    "user_as_pass": true,
    "stop_on_lockout": true,
    "attempt_delay": 1.0,
    "max_attempts": 0
  }
}
```

- `wordlist_path`: Path to password wordlist file
- `user_as_pass`: Try username as password before wordlist
- `stop_on_lockout`: Halt on lockout detection (recommended)
- `attempt_delay`: Seconds between authentication attempts
- `max_attempts`: 0 = unlimited, otherwise stops after N attempts

### File Collection Limits

```json
{
  "file_collection": {
    "max_files_per_target": 3,
    "max_total_size_mb": 500,
    "download_delay_seconds": 2,
    "max_directory_depth": 3,
    "enumeration_timeout_seconds": 120
  }
}
```

These limits prevent runaway extraction operations. All collected files go to quarantine directories under `~/.smbseek/quarantine/`.

### File Browser Settings

```json
{
  "file_browser": {
    "max_entries_per_dir": 5000,
    "max_depth": 12,
    "download_chunk_mb": 4,
    "quarantine_root": "~/.smbseek/quarantine",
    "max_batch_files": 50,
    "folder_download": {
      "max_depth": 5,
      "max_files": 200,
      "max_total_mb": 500
    }
  }
}
```

These settings control the built-in file browser behavior for individual file and folder downloads.

### Connection Settings

```json
{
  "connection": {
    "timeout": 15,
    "rate_limit_delay": 1,
    "share_access_delay": 2
  }
}
```

Rate limiting helps avoid aggressive scanning behavior. Adjust delays if you encounter timeout issues.

See `conf/config.json.example` for full configuration reference with inline documentation.

---

## Wordlists for Password Audit

The Pry feature requires a wordlist. We recommend [SecLists](https://github.com/danielmiessler/SecLists):

```bash
# Download SecLists
git clone https://github.com/danielmiessler/SecLists.git

# Configure SMBSeek to use rockyou.txt
# Edit conf/config.json:
{
  "pry": {
    "wordlist_path": "/path/to/SecLists/Passwords/Leaked-Databases/rockyou.txt"
  }
}
```

You can use any text file with one password per line. The GUI will check if the configured path exists when launching Pry operations.

---

## GUI Features

### Dashboard Window

The main dashboard provides:
- Scan configuration and launch controls
- Server List access button
- Configuration editor button
- About/help links

Configure country filters, Shodan result limits, and other scan parameters before launching discovery operations.

### Server List Window

The server list shows all discovered SMB hosts with columns for:
- IP address
- Country
- Authentication method (anonymous, guest, or auth required)
- Last seen timestamp
- Accessible/denied share counts

**Operations available:**
- **Probe:** Deep share enumeration with ransomware detection
- **Browse:** Read-only share exploration
- **Extract:** Bounded file collection
- **Pry:** Password audit against specific credentials

Right-click hosts to access operations menu. Select multiple hosts for batch probe operations.

### Share Details

After probing, the details window shows:
- Share names and types
- Accessibility status (accessible vs denied)
- Ransomware indicator detection results
- Share-specific operations (browse, extract, pry)

Use the accessible vs denied counts to prioritize which hosts need password auditing.

### Configuration Editor

Built-in editor for common settings:
- Shodan API key
- Pry wordlist path and behavior
- Connection timeouts and delays
- File collection limits

Changes persist to `conf/config.json` automatically.

For complete GUI documentation, see [docs/guides/XSMBSEEK_USER_GUIDE.md](docs/guides/XSMBSEEK_USER_GUIDE.md).

---

## Command-Line Tools

SMBSeek includes CLI tools for scripting and automation. The GUI uses these same backend components.

**Basic CLI usage:**
```bash
./smbseek --country US              # Discover US-based SMB servers
./smbseek --country US,GB,CA        # Multiple countries
./smbseek --verbose                 # Detailed output
./smbseek --string "Finance"        # Search for specific keywords in SMB banners
```

The CLI performs discovery (Shodan queries + SMB auth testing) and share access verification in a unified workflow. Results persist to SQLite database (`smbseek.db`) for later analysis.

The GUI automatically runs database migrations on startup. CLI users can run migrations manually via `python tools/db_manager.py` if needed.

For detailed CLI documentation and flag reference, see [docs/guides/USER_GUIDE.md](docs/guides/USER_GUIDE.md) and [docs/operations/](docs/operations/).

---

## Architecture

SMBSeek uses a modular architecture with shared backend components:

```text
smbseek (CLI entry point)
├── shared/
│   ├── workflow.py          # Orchestrates discovery → access → database
│   ├── database.py          # SQLite session tracking and queries
│   ├── config.py            # Configuration management
│   └── rce_scanner/         # Vulnerability signature scanning
├── commands/
│   ├── discover.py          # Shodan query + SMB authentication testing
│   └── access.py            # Share enumeration and accessibility checks
├── gui/
│   ├── xsmbseek             # GUI entry point
│   ├── components/          # Tkinter windows and dialogs
│   └── utils/               # GUI-specific utilities
├── tools/                   # Database maintenance and query scripts
└── conf/                    # Configuration files and examples
```

### Database Schema

SMBSeek uses SQLite to track all operations:

- **scan_sessions:** Discovery workflow executions with timestamps and status
- **smb_servers:** Server registry (IP, country, auth method, first/last seen)
- **share_access:** Share enumeration results (accessibility, permissions, probe status)
- **failure_logs:** Connection failures for intelligent re-scanning

The database persists state across GUI and CLI sessions. Full schema definition in `tools/db_schema.sql`.

---

## Troubleshooting

### GUI Launch Failures

#### Error: `ModuleNotFoundError: tkinter`

Tkinter missing from Python installation:

```bash
# Ubuntu/Debian
sudo apt install python3-tk

# Fedora/RHEL
sudo dnf install python3-tkinter

# Verify installation
python3 -c "import tkinter; print('tkinter OK')"
```

#### Error: GUI displays incorrectly or crashes

Virtual machine or headless environment may need virtual display:

```bash
# Install xvfb
sudo apt install xvfb

# Run with virtual display
xvfb-run -a ./xsmbseek
```

### Pry Operation Issues

#### Error: `Wordlist file not found`

Download wordlist and update config:

```bash
git clone https://github.com/danielmiessler/SecLists.git
# Edit conf/config.json and set pry.wordlist_path
```

#### Timeouts during password attempts

Increase delays in `conf/config.json`:

```json
{
  "pry": {
    "attempt_delay": 2.0
  },
  "connection": {
    "share_access_delay": 3
  }
}
```

### Connection Problems

#### Error: `smbclient: command not found`

```bash
# Ubuntu/Debian
sudo apt install smbclient

# Fedora/RHEL
sudo dnf install samba-client
```

SMBSeek will fall back to Python SMB libraries if smbclient is unavailable.

#### Error: `Database is locked`

Another SMBSeek process may be running:

```bash
ps aux | grep smbseek
# Kill hung processes if found
kill <PID>
```

### Getting Help

- Check verbose output: `./smbseek --verbose` or enable verbose in GUI config
- Review log files in `~/.smbseek/logs/` (if logging enabled)
- Verify configuration: `python -c "from shared.config import load_config; import json; print(json.dumps(load_config(), indent=2))"`
- Report issues with full error messages and SMBSeek version

---

## Security and Legal

### Intended Use

SMBSeek is designed for:
- Authorized security assessments of owned networks
- Vulnerability assessment by security professionals with explicit permission
- Educational purposes in controlled lab environments
- Defensive security operations

### Built-in Safeguards

SMBSeek includes several safety features:

- **Cautious defaults:** SMB2+/SMB3 with signing enabled (use `--legacy` only when necessary)
- **Lockout protection:** Pry mode can halt on lockout detection to prevent account locks
- **File quarantine:** All extracted and browsed files isolated under `~/.smbseek/quarantine/`
- **Rate limiting:** Configurable delays between connections and operations
- **Bounded operations:** Hard limits on file collection size, count, and runtime
- **Read-only browsing:** File browser never writes to remote shares

### Legal Requirements

**You are responsible for ensuring your use of this tool is legal and authorized.**

- Only scan networks you own or have explicit written permission to assess
- Respect all applicable laws and regulations in your jurisdiction
- Follow responsible disclosure practices if you discover vulnerabilities
- Use findings solely for defensive security purposes

### Disclaimer

This software is provided for educational and authorized defensive security purposes only. The authors provide no warranty of any kind, express or implied. Users assume all responsibility and risk for their use of this tool. Unauthorized access to computer systems is illegal in most jurisdictions.

---

## Credits and License

### Attribution

- **Pry password audit logic** derived from [mmcbrute](https://github.com/giMini/mmcbrute) (BSD-3-Clause)
- **Default wordlists** from [SecLists](https://github.com/danielmiessler/SecLists) (MIT)

See individual license files in `licenses/` directory:
- `licenses/mmcbrute-BSD-3-Clause.txt`
- `licenses/seclists-MIT.txt`

### License

SMBSeek is licensed under the MIT License. See the `LICENSE` file for full terms.

Third-party components retain their original licenses as documented in the `licenses/` directory.
