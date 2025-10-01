# SMBSeek - Unified SMB Security Toolkit

**A defensive security toolkit for identifying and analyzing SMB servers with weak authentication**

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/username/smbseek)
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

# Run complete security assessment
./smbseek.py run --country US
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

### Primary Workflow

The `run` command executes the complete SMB security assessment workflow:

```bash
# Scan United States for vulnerable SMB servers
./smbseek.py run --country US

# Scan with verbose output
./smbseek.py run --country US --verbose

# Interactive mode with review points between steps
./smbseek.py run --country US --pause-between-steps

# Force rescan of all previously discovered hosts
./smbseek.py run --country US --rescan-all
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

## Advanced Usage

### Individual Commands

For specific tasks, use individual subcommands:

```bash
# Discovery and authentication testing only
./smbseek.py discover --country US

# Share access verification on previously discovered hosts
./smbseek.py access --recent 24

# File enumeration and collection
./smbseek.py collect --download --max-files 5

# Generate intelligence reports
./smbseek.py report --executive --output report.txt

# Analyze authentication failures
./smbseek.py analyze --recent 7
```

### Workflow Customization

```bash
# Test only servers discovered in last 6 hours
./smbseek.py run --country US --recent 6

# Download files during collection phase
./smbseek.py run --country US --download --max-files 3

# Include previously failed hosts in rescan
./smbseek.py run --country US --rescan-failed
```

## Database Operations

SMBSeek stores all results in a SQLite database for analysis and reporting:

### Query Operations
```bash
# View summary statistics
./smbseek.py db query --summary

# Show geographic distribution
./smbseek.py db query --countries

# Display all available reports
./smbseek.py db query --all
```

### Maintenance Operations
```bash
# Create database backup
./smbseek.py db backup

# Show database information
./smbseek.py db info

# Run database maintenance
./smbseek.py db maintenance
```

### Import Operations
```bash
# Import legacy CSV data
./smbseek.py db import --csv legacy_results.csv

# Import JSON data
./smbseek.py db import --json scan_results.json
```

## Architecture Overview

SMBSeek 2.0 uses a unified CLI architecture with modular backend components:

```
smbseek.py                    # Main CLI entry point
├── commands/                 # Individual subcommand implementations
│   ├── run.py               # Complete workflow orchestration
│   ├── discover.py          # Shodan queries + SMB authentication
│   ├── access.py            # Share enumeration and access testing
│   ├── collect.py           # File discovery with ransomware detection
│   ├── analyze.py           # Failure analysis and pattern recognition
│   ├── report.py            # Intelligence reporting and summaries
│   └── database.py          # Database operations and queries
├── shared/                  # Common utilities and configuration
├── tools/                   # Database maintenance and query tools
└── conf/                    # Configuration files
```

### Database Schema

Core tables store comprehensive scan results:
- **smb_servers**: Server information (IP, country, authentication method)
- **scan_sessions**: Individual scanning operation tracking
- **share_access**: SMB share accessibility results
- **vulnerabilities**: Security findings and assessments
- **failure_logs**: Connection failures for analysis

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

# Command-specific help
./smbseek.py run --help
./smbseek.py discover --help

# Verbose output for debugging
./smbseek.py run --country US --verbose
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