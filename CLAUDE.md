# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SMBSeek is a Python-based defensive security tool that uses the Shodan API to identify SMB servers with weak authentication for security auditing purposes. The tool scans for vulnerable SMB hosts that allow anonymous or guest access, helping security professionals identify potential security weaknesses in their networks.

## Core Dependencies

The project requires these key Python packages:
- `shodan` - For querying the Shodan API to find SMB servers
- `smbprotocol` - Primary library for SMB connections and authentication testing
- `spnego` - For SPNEGO authentication protocol support

Standard library dependencies include: `csv`, `time`, `sys`, `argparse`, `uuid`, `socket`, `threading`, `subprocess`, `datetime`

## Main Components

### SMBScanner Class (`smbscan.py:48-402`)
- Core class that handles all scanning functionality
- Manages Shodan API connections and SMB authentication testing
- Implements rate limiting and connection timeouts
- Handles both smbprotocol and smbclient fallback methods

### Key Methods
- `search_smb_servers()` - Queries Shodan API with country filters and organization exclusions
- `test_smb_connection()` - Tests SMB authentication using smbprotocol library
- `test_smb_alternative()` - Fallback method using system smbclient command
- `scan_target()` - Orchestrates the complete scan of a single IP address

### Authentication Methods Tested
1. Anonymous access (empty username/password)
2. Guest with blank password
3. Guest with "guest" password

## Configuration

### API Key Configuration
- Shodan API key is configured in `SHODAN_API_KEY` constant (`smbscan.py:24`)
- Must be replaced with a valid key before use

### Exclusion Lists
- Organization exclusions loaded from `exclusion_list.txt`
- Prevents scanning of ISPs, hosting providers, and cloud services
- Can be customized via command line arguments

### Default Settings
- Connection timeout: 30 seconds
- Port check timeout: 10 seconds  
- Rate limit delay: 3 seconds between attempts
- Default target countries: US, GB, CA, IE, AU, NZ, ZA

## Running the Tool

### Basic Usage
```bash
python3 smbscan.py                    # Scan default countries
python3 smbscan.py -c US              # Scan only United States
python3 smbscan.py -q -o results.csv  # Quiet mode with custom output
python3 smbscan.py -t                 # Global scan (no country filter)
```

### Command Line Options
- `-q, --quiet` - Suppress screen output
- `-c, --country CODE` - Single country scan
- `-a, --additional-country CODES` - Add additional countries
- `-t, --terra` - Global scan without country filters
- `-x, --nyx` - Disable colored output
- `-o, --output FILE` - Custom output CSV file
- `--exclude-file FILE` - Custom exclusion file
- `--additional-excludes ORGS` - Additional organizations to exclude
- `--no-default-excludes` - Skip default exclusions

## Output

Results are saved to timestamped CSV files with format:
- `ip_address` - Target IP
- `country` - Country location
- `auth_method` - Successful authentication method

## Security Considerations

This is a defensive security tool intended for:
- Security auditing of owned networks
- Vulnerability assessment by authorized security professionals
- Educational purposes in controlled environments

The tool includes built-in safeguards:
- Organization exclusion lists to avoid scanning infrastructure providers
- Rate limiting to prevent aggressive scanning
- Timeout mechanisms to prevent hanging connections