# SMBSeek - Unified SMB Security Toolkit

**A defensive security toolkit for identifying and analyzing SMB servers with weak authentication**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/username/smbseek)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## 🚀 Quick Start

```bash
# Install dependencies and configure API key
pip install -r requirements.txt

# Run complete security assessment workflow
./smbseek.py run --country US
```

## 🎯 What SMBSeek Does

SMBSeek helps security professionals identify exposed SMB servers with weak authentication through:

### ✅ Unified CLI Interface
- **Single Command Workflow**: `smbseek run --country US` 
- **Individual Operations**: `smbseek discover`, `smbseek access`, etc.
- **Database Integration**: Intelligent host filtering and historical tracking
- **Progress Indication**: Real-time feedback during long operations

### ✅ Smart & Respectful Scanning
- **Rate Limited**: Configurable delays prevent aggressive behavior
- **Exclusion Lists**: Built-in filters for ISPs and cloud providers  
- **Time-Based Rescanning**: Avoid redundant testing of recent targets
- **Read-Only Operations**: No modification of target systems

## 🏗️ Architecture

```
smbseek.py (Unified CLI Entry Point)
├── run         # Complete workflow orchestration
├── discover    # Shodan querying + SMB authentication testing
├── access      # Share enumeration and access verification  
├── collect     # File enumeration with ransomware detection
├── analyze     # Failure analysis and pattern recognition
├── report      # Intelligence reporting and summaries
└── db          # Database operations and maintenance
```

**Legacy Tools**: Individual scripts in `tools/` directory still supported for advanced users.

## Overview

SMBSeek helps security professionals identify SMB servers that allow anonymous or guest access by:
- Querying Shodan's database for SMB servers with disabled authentication
- Testing multiple authentication methods (anonymous, guest/blank, guest/guest)
- Filtering results by country and excluding known infrastructure providers
- Storing findings in SQLite database for advanced analysis and querying

## Features

- **Shodan Integration**: Leverages Shodan's extensive database of internet-connected devices
- **Multi-Country Support**: Target specific countries or scan globally
- **Smart Filtering**: Built-in exclusion lists for ISPs, hosting providers, and cloud services
- **Multiple Auth Methods**: Tests anonymous and guest authentication methods
- **SMB Share Enumeration**: Lists available shares on successfully authenticated servers
- **Fallback Support**: Uses both smbprotocol library and smbclient for compatibility
- **Rate Limiting**: Built-in delays to prevent aggressive scanning
- **Ransomware Detection**: Automatic detection of compromised hosts during file scanning
- **Progress Indicators**: Real-time feedback during network operations
- **Database Storage**: Results stored in SQLite database with advanced querying capabilities

## Prerequisites

### Python Dependencies

Install required Python packages:

```bash
pip install -r requirements.txt
```

### System Requirements

- Python 3.6+
- smbclient (recommended, for share enumeration and fallback support)
- Valid Shodan API key

### Shodan API Key

1. Sign up for a Shodan account at https://shodan.io
2. Obtain your API key from your account dashboard
3. Update the API key in `conf/config.json`:

```json
{
  "shodan": {
    "api_key": "your_actual_api_key_here"
  }
}
```

## Quick Start

### Basic Usage

```bash
# Scan all default countries (US, GB, CA, IE, AU, NZ, ZA)
python3 tools/smb_scan.py

# Scan only United States
python3 tools/smb_scan.py -c US

# Scan multiple countries
python3 tools/smb_scan.py -a FR,DE,IT

# Quiet mode
python3 tools/smb_scan.py -q

# Verbose mode (shows detailed authentication testing)
python3 tools/smb_scan.py -v

# Enable failure logging (stored in database)
python3 tools/smb_scan.py -f
```

### Complete Workflow

```bash
# 1. Discover vulnerable SMB servers
python3 tools/smb_scan.py -c US

# 2. Query your results
python3 tools/db_query.py --summary

# 3. View detailed statistics
python3 tools/db_query.py --all

# 4. Generate reports
python3 tools/db_maintenance.py --export

# 5. Backup your data
python3 tools/db_maintenance.py --backup
```

## Command Line Options

### Main Scanner (tools/smb_scan.py)

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Suppress output to screen (useful for scripting) |
| `-v, --vox` | Enable verbose output showing detailed authentication testing steps |
| `-c, --country CODE` | Search only the specified country (two-letter code) |
| `-a, --additional-country CODES` | Comma-separated list of additional countries |
| `-t, --terra` | Search globally without country filters |
| `-x, --nyx` | Disable colored output |
| `-f, --log-failures` | Log failed connection attempts to database |
| `--db-path PATH` | Specify database file path (default: smbseek.db) |

### Database Query Tool (tools/db_query.py)

| Option | Description |
|--------|-------------|
| `--summary` | Show server summary with statistics |
| `--vulnerabilities` | Display vulnerability breakdown |
| `--countries` | Show country distribution of servers |
| `--shares` | Display most common share names |
| `--all` | Show all available reports |

### Database Maintenance Tool (db_maintenance.py)

| Option | Description |
|--------|-------------|
| `--backup` | Create database backup |
| `--maintenance` | Run routine database maintenance |
| `--export` | Export database tables to CSV files |
| `--info` | Display database information and statistics |
| `--cleanup DAYS` | Remove data older than specified days |

## Database Storage

### Default Behavior

SMBSeek stores all scan results in a SQLite database (`smbseek.db`) that grows with each scan. This enables powerful querying across multiple scans and historical analysis.

### Database Schema

Results are stored in structured tables:

- **`smb_servers`**: Core server information (IP, country, authentication method)
- **`scan_sessions`**: Track individual scanning operations
- **`share_access`**: Details about accessible SMB shares
- **`vulnerabilities`**: Security findings and assessments
- **`failure_logs`**: Connection failures for analysis

### Querying Your Data

```bash
# View recent discoveries
python3 tools/db_query.py --summary

# See geographic distribution
python3 tools/db_query.py --countries

# Export to CSV for external analysis
python3 tools/db_maintenance.py --export
```

## Configuration

SMBSeek uses a JSON configuration file (`conf/config.json`) to manage all settings. The configuration file is automatically loaded on startup with fallback to defaults if not found.

### Basic Configuration

```json
{
  "shodan": {
    "api_key": "your_shodan_api_key_here"
  },
  "connection": {
    "timeout": 30,
    "port_check_timeout": 10,
    "rate_limit_delay": 3,
    "share_access_delay": 7
  },
  "files": {
    "default_exclusion_file": "conf/exclusion_list.txt"
  },
  "security": {
    "ransomware_indicators": [
      "!want_to_cry.txt",
      "0XXX_DECRYPTION_README.TXT"
    ]
  },
  "database": {
    "enabled": true,
    "path": "smbseek.db",
    "backup_enabled": true,
    "backup_interval_hours": 24,
    "max_backup_files": 30
  }
}
```

### Configuration Sections

#### Connection Settings
- `timeout`: SMB connection timeout in seconds (default: 30)
- `port_check_timeout`: Port 445 availability check timeout in seconds (default: 10)
- `rate_limit_delay`: Delay between connection attempts in seconds (default: 3)
- `share_access_delay`: Delay between share access tests in seconds (default: 7)

#### Security Settings
- `ransomware_indicators`: List of filename patterns that indicate ransomware/malware infection (case-insensitive matching)

#### Database Settings
- `enabled`: Enable database storage (default: true)
- `path`: Database file location (default: smbseek.db)
- `backup_enabled`: Automatic backup creation (default: true)
- `backup_interval_hours`: Hours between automatic backups (default: 24)
- `max_backup_files`: Maximum number of backup files to retain (default: 30)

### Organization Exclusions

The tool uses `conf/exclusion_list.txt` to exclude known ISPs, hosting providers, and cloud services. This prevents scanning infrastructure that typically has SMB services on routers rather than vulnerable endpoints.

## Authentication Methods

The tool tests three authentication methods in order:

1. **Anonymous**: Empty username and password
2. **Guest/Blank**: Username "guest" with empty password
3. **Guest/Guest**: Username "guest" with password "guest"

If the primary smbprotocol library fails, the tool falls back to using the system's smbclient command.

## Tool Details

### Database Query System

The database query tool (`tools/db_query.py`) provides comprehensive analysis of your scan data:

- Server summaries with accessibility statistics
- Geographic distribution analysis
- Vulnerability assessment reports
- Historical scanning trends

Usage:
```bash
python3 db_query.py --all
```

### Database Maintenance System

The maintenance tool (`db_maintenance.py`) manages your SQLite database:

- Automated backup creation with configurable retention
- Database optimization and cleanup operations
- Data export capabilities for external analysis
- Health monitoring and integrity checking

Usage:
```bash
python3 tools/db_maintenance.py --maintenance
```

### Data Import System

The import tool (`tools/db_import.py`) migrates existing data files to the database:

- **Legacy Support**: Imports existing CSV and JSON scan results
- **Batch Processing**: Handles multiple files from different scan sessions
- **Data Validation**: Ensures data integrity during import process
- **Progress Tracking**: Provides detailed import statistics

Usage:
```bash
# Import all supported files from current directory
python3 tools/db_import.py --all

# Import specific legacy files
python3 tools/db_import.py --csv legacy_results.csv

# Import from specific directory
python3 tools/db_import.py --directory /path/to/old/data
```

#### Ransomware Detection Features

- **Automatic Scanning**: Checks filenames against known ransomware indicators during enumeration
- **Immediate Stop**: Halts all scanning on a host when malware indicators are detected
- **Configurable Patterns**: Ransomware indicators defined in `conf/config.json` for easy updates
- **Case-Insensitive Matching**: Detects variations in filename casing

Default detection patterns:
- `!want_to_cry.txt` (WannaCry ransomware)
- `0XXX_DECRYPTION_README.TXT` (Common ransom note pattern)

## System Requirements

### smbclient Installation

Most Linux distributions include `smbclient` in their package repositories:

```bash
# Ubuntu/Debian
sudo apt install smbclient

# CentOS/RHEL/Fedora
sudo yum install samba-client
# or
sudo dnf install samba-client

# macOS (via Homebrew)
brew install samba
```

If `smbclient` is not available, SMBSeek will display a warning and continue scanning with reduced functionality.

## Security Considerations

### Intended Use

This tool is designed for legitimate security purposes:
- Security auditing of owned networks
- Vulnerability assessment by authorized security professionals
- Educational purposes in controlled environments

### Built-in Safeguards

- Organization exclusion lists to avoid scanning infrastructure providers
- Rate limiting to prevent aggressive scanning behavior
- Timeout mechanisms to prevent hanging connections
- Country-based filtering to limit scan scope

### Legal and Ethical Use

- Only scan networks you own or have explicit permission to test
- Respect rate limits and avoid aggressive scanning
- Follow all applicable laws and regulations
- Use findings responsibly for defensive purposes

## Development

### AI-Driven Development

SMBSeek represents a significant milestone in AI-assisted software development: every single line of code, documentation, configuration file, and architectural decision was written entirely by Claude (Anthropic's AI assistant) through conversational programming with human guidance and testing.

The collaboration succeeded through a unique division of responsibilities:

**Human Role**: Problem definition, domain expertise, real-world testing, quality assurance, strategic direction

**AI Role**: Complete technical implementation, architecture, documentation, debugging, consistency maintenance

### What Made This Partnership Work

1. **Trust and Autonomy**: The human partner trusted the AI to handle full technical implementation while providing essential real-world context
2. **Iterative Feedback Loops**: Rapid development cycles with immediate real-world testing and feedback
3. **Real-World Validation**: Testing against actual SMB servers revealed crucial compatibility issues that pure logic couldn't predict
4. **Comprehensive Documentation**: Documentation was treated as a core deliverable, not an afterthought

### Technical Insights

- **Hybrid approaches work**: Combining Python libraries with external tools (like `smbclient`) often yields better compatibility than pure-Python solutions
- **Configuration-driven design**: Making everything configurable through JSON files dramatically improves usability
- **Error handling is crucial**: Network tools need extensive exception handling for real-world reliability

This project demonstrates that the future of programming isn't human vs. AI—it's human + AI, each contributing their unique strengths to create better software faster.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the terms specified in the LICENSE file.

## Disclaimer

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations. The authors are not responsible for any misuse of this tool.
