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
- **Fallback Support**: Uses both smbprotocol library and smbclient for compatibility
- **Rate Limiting**: Built-in delays to prevent aggressive scanning
- **CSV Output**: Results saved in structured format for analysis

## Prerequisites

### Python Dependencies

Install required Python packages:

```bash
pip install shodan smbprotocol spnego
```

### System Requirements

- Python 3.6+
- smbclient (optional, for fallback support)
- Valid Shodan API key

### Shodan API Key

1. Sign up for a Shodan account at https://shodan.io
2. Obtain your API key from your account dashboard
3. Replace the placeholder API key in `smbscan.py`:

```python
SHODAN_API_KEY = "your_actual_api_key_here"
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

# Quiet mode with custom output file
python3 smbscan.py -q -o my_results.csv

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
| `-c, --country CODE` | Search only the specified country (two-letter code) |
| `-a, --additional-country CODES` | Comma-separated list of additional countries |
| `-t, --terra` | Search globally without country filters |
| `-x, --nyx` | Disable colored output |
| `-o, --output FILE` | Specify output CSV file |
| `--exclude-file FILE` | Load organization exclusions from file |
| `--additional-excludes ORGS` | Additional organizations to exclude |
| `--no-default-excludes` | Skip loading default organization exclusions |

## Output Format

Results are saved to timestamped CSV files with the following columns:

- `ip_address`: Target IP address
- `country`: Country location
- `auth_method`: Successful authentication method

Example output:
```csv
ip_address,country,auth_method
192.168.1.100,United States,Anonymous
10.0.0.50,Canada,Guest/Blank
```

## Configuration

### Organization Exclusions

The tool uses `exclusion_list.txt` to exclude known ISPs, hosting providers, and cloud services. This prevents scanning infrastructure that typically has SMB services on routers rather than vulnerable endpoints.

To customize exclusions:
1. Edit `exclusion_list.txt`
2. Add one organization name per line
3. Use exact names as they appear in Shodan results
4. Lines starting with `#` are treated as comments

### Timeout Settings

Default timeouts can be modified in the configuration section:

```python
CONNECTION_TIMEOUT = 30  # seconds
PORT_CHECK_TIMEOUT = 10  # seconds for port check
RATE_LIMIT_DELAY = 3     # seconds between connection attempts
```

## Authentication Methods

The tool tests three authentication methods in order:

1. **Anonymous**: Empty username and password
2. **Guest/Blank**: Username "guest" with empty password
3. **Guest/Guest**: Username "guest" with password "guest"

If the primary smbprotocol library fails, the tool falls back to using the system's smbclient command.

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
