# SMBSeek

A defensive security tool that uses the Shodan API to identify SMB servers with weak authentication for security auditing purposes.

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
  },
  ...
}
```

## Usage

### Basic Examples

```bash
# Scan all default countries (US, GB, CA, IE, AU, NZ, ZA)
python3 smbscan.py

# Scan only United States
python3 smbscan.py -c US

# Scan multiple specific countries
python3 smbscan.py -a FR,DE,IT

# Global scan (no country filter)
python3 smbscan.py -t

# Create new timestamped file instead of appending
python3 smbscan.py -n

# Quiet mode with custom output file
python3 smbscan.py -q -o my_results.csv

# Verbose mode (shows detailed authentication testing)
python3 smbscan.py -v

# Use custom name for consolidated results file
python3 smbscan.py -r project_scan_results.csv

# Disable colored output
python3 smbscan.py -x
```

### Advanced Options

```bash
# Use custom exclusion file
python3 smbscan.py --exclude-file custom_exclusions.txt

# Add additional organizations to exclude
python3 smbscan.py --additional-excludes "My ISP,Another Org"

# Skip default exclusions entirely
python3 smbscan.py --no-default-excludes

# Combine multiple options
python3 smbscan.py -c GB -q -o uk_scan.csv -x
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-q, --quiet` | Suppress output to screen (useful for scripting) |
| `-v, --vox` | Enable verbose output showing detailed authentication testing steps |
| `-c, --country CODE` | Search only the specified country (two-letter code) |
| `-a, --additional-country CODES` | Comma-separated list of additional countries |
| `-t, --terra` | Search globally without country filters |
| `-x, --nyx` | Disable colored output |
| `-o, --output FILE` | Specify output CSV file (overrides default behavior) |
| `-n, --new-file` | Create new timestamped file instead of appending to default |
| `-r, --record-name NAME` | Specify name for consolidated results file |
| `--exclude-file FILE` | Load organization exclusions from file |
| `--additional-excludes ORGS` | Additional organizations to exclude |
| `--no-default-excludes` | Skip loading default organization exclusions |

## Output Format

### Default Behavior (Consolidated Results)

By default, SMBSeek appends results to a single file (`smb_scan_results.csv`) to consolidate findings from multiple scan sessions. This makes it easier to track discoveries over time.

### CSV Columns

Results include the following columns:

- `ip_address`: Target IP address
- `country`: Country location
- `auth_method`: Successful authentication method
- `shares`: Available SMB shares (first 5 non-administrative shares)
- `timestamp`: When the connection was discovered (ISO format)

### Output File Options

1. **Default (Append Mode)**: Results appended to `smb_scan_results.csv`
2. **Custom Consolidated File**: Use `-r filename.csv` to specify different consolidated file
3. **New Timestamped File**: Use `-n` to create `smb_scan_results_YYYYMMDD_HHMMSS.csv`
4. **Specific Output File**: Use `-o filename.csv` to override all default behavior

### Header Compatibility

When appending to existing files, SMBSeek checks for header compatibility. If the existing file has different columns (e.g., from an older version), it will:
- Display a yellow warning message
- Create a new file with format `smb_scan_results_YYYYMMDD.csv`
- Inform you of the new file path

Example output:
```csv
ip_address,country,auth_method,shares,timestamp
192.168.1.100,United States,Anonymous,"Movies, Music, Documents",2025-01-15T14:30:45
10.0.0.50,Canada,Guest/Blank,"Data, Backup, (and more)",2025-01-15T14:31:02
```

## Configuration

SMBSeek uses a JSON configuration file (`config.json`) to manage all settings. The configuration file is automatically loaded on startup with fallback to defaults if not found.

### Configuration File Structure

```json
{
  "shodan": {
    "api_key": "your_shodan_api_key_here"
  },
  "connection": {
    "timeout": 30,
    "port_check_timeout": 10,
    "rate_limit_delay": 3
  },
  "files": {
    "default_exclusion_file": "exclusion_list.txt"
  },
  "countries": {
    "US": "United States",
    "GB": "United Kingdom",
    "CA": "Canada",
    "IE": "Ireland",
    "AU": "Australia",
    "NZ": "New Zealand",
    "ZA": "South Africa"
  }
}
```

### Configuration Sections

#### Shodan Settings
- `api_key`: Your Shodan API key (required)

#### Connection Settings
- `timeout`: SMB connection timeout in seconds (default: 30)
- `port_check_timeout`: Port 445 availability check timeout in seconds (default: 10)
- `rate_limit_delay`: Delay between connection attempts in seconds (default: 3)

#### File Settings
- `default_exclusion_file`: Path to organization exclusion file (default: "exclusion_list.txt")

#### Default Countries
- Defines the default set of countries to scan when no specific countries are specified
- Maps country codes to full country names for display purposes

### Organization Exclusions

The tool uses `exclusion_list.txt` to exclude known ISPs, hosting providers, and cloud services. This prevents scanning infrastructure that typically has SMB services on routers rather than vulnerable endpoints.

To customize exclusions:
1. Edit `exclusion_list.txt`
2. Add one organization name per line
3. Use exact names as they appear in Shodan results
4. Lines starting with `#` are treated as comments

## Authentication Methods

The tool tests three authentication methods in order:

1. **Anonymous**: Empty username and password
2. **Guest/Blank**: Username "guest" with empty password
3. **Guest/Guest**: Username "guest" with password "guest"

If the primary smbprotocol library fails, the tool falls back to using the system's smbclient command.

## SMB Share Enumeration

### Overview

When SMBSeek successfully authenticates to an SMB server, it automatically attempts to enumerate available shares to provide additional context about the target system. This feature helps security professionals understand what data might be exposed through weak authentication.

### Share Listing Behavior

- **Automatic enumeration**: Shares are listed immediately after successful authentication
- **Filtered results**: Only the first 5 non-administrative shares are displayed
- **Administrative share exclusion**: Shares ending with `$` (like `IPC$`, `ADMIN$`, `C$`) are filtered out
- **Overflow indicator**: Shows "(and more)" when more than 5 shares exist
- **Graceful degradation**: If share enumeration fails, the scan continues without share data

### Implementation Details

SMBSeek uses the system's `smbclient` command for share enumeration rather than pure Python implementation. This design choice was made for several important reasons:

#### Why smbclient Instead of Pure Python?

1. **Library Limitations**: The `smbprotocol` Python library lacks built-in share enumeration functionality, and this has been a long-standing gap confirmed by GitHub issues from 2021-2024.

2. **Complex Protocol Requirements**: Share listing requires low-level DCE/RPC calls using the `NetShareEnum` function via the `srvsvc` named pipe, which involves:
   - Manual construction of binary RPC packets
   - Complex parsing of SMB protocol responses
   - Handling different SMB dialect negotiations

3. **Reliability and Compatibility**: The `smbclient` tool provides:
   - Battle-tested share enumeration across diverse SMB implementations
   - Consistent output format that's reliable to parse
   - Built-in error handling and timeout management
   - Proven compatibility with Windows, Samba, and cloud SMB services

4. **Maintainability**: Using `smbclient` keeps the codebase focused on its core purpose rather than implementing a full SMB protocol handler.

5. **Architectural Consistency**: SMBSeek already uses `smbclient` as a fallback authentication method, so this maintains consistency.

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

If `smbclient` is not available, SMBSeek will display a warning and continue scanning with authentication testing only:

```
⚠ smbclient unavailable; scan will continue with less features.
```

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

SMBSeek was "vibe coded" by Claude (Anthropic's AI assistant) in close collaboration with human direction and testing. This project represents an interesting example of human-AI pair programming, where complex cybersecurity tooling was iteratively designed, implemented, and refined through natural language conversations. 

The development process involved real-world testing, debugging sessions, security considerations, and feature enhancements - all guided through conversational programming. From initial concept to production-ready tool, every line of code, documentation, and architectural decision emerged from this collaborative approach.

Special thanks to Claude for the meticulous attention to code quality, security best practices, error handling, and comprehensive documentation throughout the development process.

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
