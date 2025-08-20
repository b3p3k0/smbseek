# SMBSeek

A defensive security toolkit that uses the Shodan API to identify and analyze SMB servers with weak authentication for security auditing purposes.

## Tool Suite

SMBSeek consists of five complementary tools:

- **`smb_scan.py`**: Primary scanner for discovering SMB servers with weak authentication
- **`failure_analyzer.py`**: Deep analysis tool for understanding authentication failures  
- **`smb_peep.py`**: Share access verification tool for testing read accessibility
- **`smb_snag.py`**: File collection tool for downloading samples from accessible shares with ransomware detection
- **`smb_vuln.py`**: Vulnerability assessment tool for testing specific CVEs

## Overview

SMBSeek helps security professionals identify SMB servers that allow anonymous or guest access by:
- Querying Shodan's database for SMB servers with disabled authentication
- Testing multiple authentication methods (anonymous, guest/blank, guest/guest)
- Filtering results by country and excluding known infrastructure providers
- Outputting findings to CSV format for further analysis

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
- **CSV Output**: Results saved in structured format for analysis

## Prerequisites

### Python Dependencies

Install required Python packages:

```bash
pip install shodan smbprotocol pyspnego
```

### System Requirements

- Python 3.6+
- smbclient (recommended, for share enumeration and fallback support)
- Valid Shodan API key

### Shodan API Key

1. Sign up for a Shodan account at https://shodan.io
2. Obtain your API key from your account dashboard
3. Update the API key in `config.json`:

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
python3 smb_scan.py

# Scan only United States
python3 smb_scan.py -c US

# Scan multiple countries
python3 smb_scan.py -a FR,DE,IT

# Quiet mode with custom output file
python3 smb_scan.py -q -o my_results.csv

# Verbose mode (shows detailed authentication testing)
python3 smb_scan.py -v

# Enable failure logging for later analysis
python3 smb_scan.py -f
```

### Complete Workflow

```bash
# 1. Discover vulnerable SMB servers with failure logging
python3 smb_scan.py -f -c US

# 2. Analyze failures (optional)
python3 failure_analyzer.py failed_record.csv

# 3. Test share accessibility
python3 smb_peep.py ip_record.csv

# 4. Generate file manifest from accessible shares
python3 smb_snag.py share_access_*.json

# 5. Download files if needed (optional)
python3 smb_snag.py -d share_access_*.json
```

## Command Line Options

### Main Scanner (smb_scan.py)

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Suppress output to screen (useful for scripting) |
| `-v, --vox` | Enable verbose output showing detailed authentication testing steps |
| `-c, --country CODE` | Search only the specified country (two-letter code) |
| `-a, --additional-country CODES` | Comma-separated list of additional countries |
| `-t, --terra` | Search globally without country filters |
| `-x, --nyx` | Disable colored output |
| `-f, --log-failures` | Log failed connection attempts to separate CSV file |
| `-o, --output FILE` | Specify output CSV file (overrides default behavior) |
| `-n, --new-file` | Create new timestamped file instead of appending to default |

### Share Access Tool (smb_peep.py)

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Suppress output to screen |
| `-v, --verbose` | Enable verbose output showing detailed share testing |
| `-o, --output FILE` | Specify output JSON file (default: timestamped) |
| `-x, --no-colors` | Disable colored output |

### File Collection Tool (smb_snag.py)

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Suppress output to screen |
| `-v, --verbose` | Enable verbose output showing detailed enumeration progress |
| `-d, --download-files` | Download files (generates manifest only by default) |
| `-a, --auto-download` | Skip confirmation prompt when downloading files |
| `-m, --manager-friendly` | Generate human-readable report |
| `-x, --no-colors` | Disable colored output |

## Output Format

### Default Behavior

By default, SMBSeek appends results to a single file (`smb_scan_results.csv`) to consolidate findings from multiple scan sessions.

### CSV Columns

Results include the following columns:

- `ip_address`: Target IP address
- `country`: Country location
- `auth_method`: Successful authentication method
- `shares`: Available SMB shares (first 5 non-administrative shares)
- `timestamp`: When the connection was discovered (ISO format)

Example output:
```csv
ip_address,country,auth_method,shares,timestamp
192.168.1.100,United States,Anonymous,"Movies, Music, Documents",2025-01-15T14:30:45
10.0.0.50,Canada,Guest/Blank,"Data, Backup, (and more)",2025-01-15T14:31:02
```

## Configuration

SMBSeek uses a JSON configuration file (`config.json`) to manage all settings. The configuration file is automatically loaded on startup with fallback to defaults if not found.

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
    "default_exclusion_file": "exclusion_list.txt"
  },
  "security": {
    "ransomware_indicators": [
      "!want_to_cry.txt",
      "0XXX_DECRYPTION_README.TXT"
    ]
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

### Organization Exclusions

The tool uses `exclusion_list.txt` to exclude known ISPs, hosting providers, and cloud services. This prevents scanning infrastructure that typically has SMB services on routers rather than vulnerable endpoints.

## Authentication Methods

The tool tests three authentication methods in order:

1. **Anonymous**: Empty username and password
2. **Guest/Blank**: Username "guest" with empty password
3. **Guest/Guest**: Username "guest" with password "guest"

If the primary smbprotocol library fails, the tool falls back to using the system's smbclient command.

## Tool Details

### SMB Failure Analyzer

The failure analyzer (`failure_analyzer.py`) investigates why SMB authentication attempts fail and provides comprehensive analysis including:

- Shodan deep dive with SMB service details and OS fingerprinting
- Network-level analysis with port accessibility testing
- SMB protocol analysis with authentication requirements
- Vulnerability assessment with risk classification

Usage:
```bash
python3 failure_analyzer.py failed_record.csv
```

### SMB Share Access Verifier

SMB Peep (`smb_peep.py`) validates read accessibility of SMB shares from servers with successful authentication:

- Re-enumerates shares using original successful authentication method
- Tests actual SMB share accessibility using smbprotocol
- Provides detailed error information for inaccessible shares
- **READ ONLY**: No write operations are ever attempted

Usage:
```bash
python3 smb_peep.py ip_record.csv
```

### SMB File Collection Tool

SMB Snag (`smb_snag.py`) downloads file samples from SMB shares with verified read access:

- **Ransomware Detection**: Automatically scans for malware indicators during enumeration
- **Security Stop**: Immediately halts scanning if ransomware/malware indicators detected
- Applies configurable file extension filters
- Scans directories recursively with configurable depth limits
- **READ ONLY**: No write operations or file modifications ever attempted

Usage:
```bash
# Generate file manifest only (default)
python3 smb_snag.py share_access_results.json

# Generate manifest and download files
python3 smb_snag.py -d share_access_results.json

# Generate human-readable report
python3 smb_snag.py -m share_access_results.json
```

#### Ransomware Detection Features

- **Automatic Scanning**: Checks filenames against known ransomware indicators during enumeration
- **Immediate Stop**: Halts all scanning on a host when malware indicators are detected
- **Configurable Patterns**: Ransomware indicators defined in `config.json` for easy updates
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