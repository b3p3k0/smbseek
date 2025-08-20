# SMBSeek

A defensive security toolkit that uses the Shodan API to identify and analyze SMB servers with weak authentication for security auditing purposes.

## Tool Suite

SMBSeek consists of five complementary tools:

- **`smb_scan.py`**: Primary scanner for discovering SMB servers with weak authentication
- **`failure_analyzer.py`**: Deep analysis tool for understanding authentication failures  
- **`smb_peep.py`**: Share access verification tool for testing read accessibility
- **`smb_snag.py`**: File collection tool for downloading samples from accessible shares with **ransomware detection**
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
  },
  ...
}
```

## Usage

### Basic Examples

```bash
# Scan all default countries (US, GB, CA, IE, AU, NZ, ZA)
python3 smb_scan.py

# Scan only United States
python3 smb_scan.py -c US

# Scan multiple specific countries
python3 smb_scan.py -a FR,DE,IT

# Global scan (no country filter)
python3 smb_scan.py -t

# Create new timestamped file instead of appending
python3 smb_scan.py -n

# Quiet mode with custom output file
python3 smb_scan.py -q -o my_results.csv

# Verbose mode (shows detailed authentication testing)
python3 smb_scan.py -v

# Enable failure logging for later analysis
python3 smb_scan.py -f

# Combined: failure logging with verbose output
python3 smb_scan.py -f -v

# Use custom name for consolidated results file
python3 smb_scan.py -r project_scan_results.csv

# Disable colored output
python3 smb_scan.py -x
```

### Advanced Options

```bash
# Use custom exclusion file
python3 smb_scan.py --exclude-file custom_exclusions.txt

# Add additional organizations to exclude
python3 smb_scan.py --additional-excludes "My ISP,Another Org"

# Skip default exclusions entirely
python3 smb_scan.py --no-default-excludes

# Combine multiple options
python3 smb_scan.py -c GB -q -o uk_scan.csv -x

# Complete workflow: scan, analyze failures, test share access, collect files
python3 smb_scan.py -f -c US
python3 failure_analyzer.py failed_record.csv
python3 smb_peep.py ip_record.csv
python3 smb_snag.py share_access_*.json
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
| `-f, --log-failures` | Log failed connection attempts to separate CSV file (failed_record.csv) |
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

#### Shodan Settings
- `api_key`: Your Shodan API key (required)

#### Connection Settings
- `timeout`: SMB connection timeout in seconds (default: 30)
- `port_check_timeout`: Port 445 availability check timeout in seconds (default: 10)
- `rate_limit_delay`: Delay between connection attempts in seconds (default: 3)
- `share_access_delay`: Delay between share access tests in seconds (default: 7)

#### File Settings
- `default_exclusion_file`: Path to organization exclusion file (default: "exclusion_list.txt")

#### Security Settings
- `ransomware_indicators`: List of filename patterns that indicate ransomware/malware infection (case-insensitive matching)

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

## Failure Analysis Tool

### Overview

The SMB Failure Analyzer (`failure_analyzer.py`) is a specialized tool designed to investigate why SMB authentication attempts fail. It performs comprehensive analysis of failed connections to identify patterns, technical issues, and potential solutions.

### Purpose

When SMBSeek encounters authentication failures (typically ~25% of targets), the failure analyzer helps determine:
- Root causes of authentication failures
- Patterns across geographic regions, SMB implementations, or network configurations
- Technical details for improving scanning success rates
- Security configurations that may be blocking authentication

### Usage

```bash
# Analyze failures from SMBSeek output
python3 failure_analyzer.py failed_record.csv

# Get help information
python3 failure_analyzer.py --help
```

### Analysis Components

#### 1. Shodan Deep Dive
- **SMB Service Details**: Version, dialect, capabilities, banners
- **OS Fingerprinting**: Operating system and version detection  
- **Network Information**: ISP, organization, geographic location
- **Vulnerability Data**: Known CVEs and security issues
- **Port Analysis**: Complete service enumeration

#### 2. Network-Level Analysis
- **Port Accessibility**: TCP connection testing and response timing
- **SMB Port Scanning**: Tests ports 139, 445, 135 for availability
- **Connection Behavior**: Network response patterns and timeouts

#### 3. SMB Protocol Analysis
- **Protocol Negotiation**: SMB dialect support and capabilities
- **Authentication Requirements**: Signing, encryption, credential requirements
- **Failure Stage Classification**: Connection → Negotiation → Authentication
- **Error Detail Extraction**: Specific protocol-level error messages

#### 4. Vulnerability Assessment
- **Security Risk Evaluation**: High/medium/low risk classification
- **Configuration Analysis**: SMB security settings and requirements
- **Known Vulnerability Correlation**: CVE mapping and risk assessment

### Output Format

#### Supervisor Briefing Report
The tool generates executive-level reports suitable for briefing supervisors:

```
SMB AUTHENTICATION FAILURE ANALYSIS BRIEFING
============================================
Analysis Date: 2025-08-18 17:22:42
Total Failed Connections Analyzed: 23

EXECUTIVE SUMMARY
-----------------
Analysis reveals distinct patterns in failure causes...

FAILURE CLASSIFICATION BREAKDOWN
--------------------------------
Primary Failure Reasons:
  • SMB Connection Rejected: 15 (65.2%)
  • Authentication Required: 5 (21.7%)
  • Port Not Accessible: 3 (13.1%)

KEY TECHNICAL FINDINGS
----------------------
1. Network Infrastructure Issues: 3 targets have port 445 inaccessible
2. Protocol Security: 8 targets require enhanced security (signing/encryption)
3. Authentication Mechanisms: 5 targets require credential-based authentication

RECOMMENDATIONS
---------------
1. Focus on targets where port accessibility is not the primary issue
2. Implement SMB signing and encryption support for security-enhanced targets
3. Consider credential-based authentication methods for specific target classes
```

#### Detailed JSON Output
Complete technical analysis saved to timestamped JSON files:
```json
{
  "analysis_results": [...],
  "patterns": {...},
  "briefing_report": "...",
  "metadata": {...}
}
```

### Pattern Detection

The analyzer identifies patterns across multiple dimensions:

- **SMB Implementation Patterns**: Version-specific behaviors (Samba 3.x vs 4.x, Windows versions)
- **Geographic Patterns**: Regional blocking or configuration differences
- **ISP/Organization Patterns**: Infrastructure provider security policies
- **Network Security Patterns**: Firewall configurations and access controls
- **Protocol Security Patterns**: Signing, encryption, and authentication requirements

### Prerequisites

#### Python Dependencies
The failure analyzer requires the same dependencies as SMBSeek:
```bash
pip install shodan smbprotocol pyspnego
```

#### Configuration
Uses the same `config.json` file as SMBSeek for Shodan API access.

### Integration Workflow

1. **Run SMBSeek with failure logging**:
   ```bash
   python3 smb_scan.py -f -c US
   ```

2. **Analyze failures**:
   ```bash
   python3 failure_analyzer.py failed_record.csv
   ```

3. **Review briefing report** for actionable insights

4. **Implement targeted improvements** based on failure classifications

### Performance Considerations

- **API Usage**: Respects Shodan API rate limits with built-in delays
- **Network Testing**: Implements reasonable timeouts for network analysis
- **Memory Efficiency**: Processes results incrementally for large datasets
- **Error Handling**: Graceful degradation when individual analysis steps fail

## Share Access Verification Tool

### Overview

SMB Peep (`smb_peep.py`) is a specialized tool that validates read accessibility of SMB shares from servers with successful authentication. It takes the results from SMBSeek and determines which shares actually allow data access, providing crucial intelligence about exposed information.

### Purpose

After identifying SMB servers with weak authentication, SMB Peep answers the critical question: "What data is actually accessible?" It helps security professionals:
- Validate which shares allow read access beyond just enumeration
- Understand the scope of data exposure through weak authentication
- Prioritize remediation efforts based on accessible content
- Generate detailed access reports for compliance and security auditing

### Usage

```bash
# Basic share access testing (auto-detects ip_record.csv)
python3 smb_peep.py

# Basic share access testing with specific file
python3 smb_peep.py ip_record.csv

# Quiet mode with custom output
python3 smb_peep.py -q -o share_analysis.json ip_record.csv

# Verbose testing with detailed output
python3 smb_peep.py -v

# Get help information
python3 smb_peep.py --help
```

### Analysis Process

#### 1. Input Processing
- Reads CSV results from SMBSeek (`ip_record.csv`)
- Extracts IP addresses and successful authentication methods
- Parses authentication credentials for each target

#### 2. Fresh Share Enumeration
- Re-enumerates shares using the original successful authentication method
- Ignores shares listed in CSV (gets current state)
- Filters to non-administrative shares only (excludes shares ending with `$`)

#### 3. Read Access Testing
- Tests actual SMB share accessibility using smbprotocol
- Attempts to open and read the root directory of each share
- **READ ONLY**: No write operations are ever attempted
- Provides detailed error information for inaccessible shares

#### 4. Rate Limiting
- Implements configurable delays between share tests (default: 7 seconds)
- Respects target systems to avoid aggressive testing behavior
- No delays between different IP addresses

### Output Format

SMB Peep generates structured JSON output containing:

```json
{
  "metadata": {
    "tool": "smb_peep",
    "scan_date": "2025-08-18T19:53:33",
    "total_targets": 5,
    "config": {
      "share_access_delay": 7,
      "timeout": 30
    }
  },
  "results": [
    {
      "ip_address": "192.168.1.100",
      "country": "United States", 
      "auth_method": "Guest/Blank",
      "shares_found": ["Documents", "Public", "Backup"],
      "accessible_shares": ["Documents", "Public"],
      "share_details": [
        {
          "share_name": "Documents",
          "accessible": true
        },
        {
          "share_name": "Public", 
          "accessible": true
        },
        {
          "share_name": "Backup",
          "accessible": false,
          "error": "Read access denied: STATUS_ACCESS_DENIED"
        }
      ]
    }
  ]
}
```

### Authentication Methods

SMB Peep uses the original authentication method that succeeded during SMBSeek scanning:
- **Anonymous**: Empty username and password
- **Guest/Blank**: Username "guest" with empty password  
- **Guest/Guest**: Username "guest" with password "guest"

### Prerequisites

Same dependencies as SMBSeek:
```bash
pip install smbprotocol pyspnego
```

System requirements:
- smbclient (recommended for share enumeration)
- Same `config.json` configuration as other SMBSeek tools

### Integration Workflow

```bash
# 1. Discover vulnerable SMB servers
python3 smb_scan.py -c US

# 2. Test share accessibility 
python3 smb_peep.py ip_record.csv

# 3. Analyze JSON results for accessible shares
cat share_access_*.json | jq '.results[] | select(.accessible_shares | length > 0)'

# 4. Collect files from accessible shares
python3 smb_snag.py share_access_*.json
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show comprehensive help message |
| `-q, --quiet` | Suppress output to screen (useful for scripting) |
| `-v, --verbose` | Enable verbose output showing detailed share testing |
| `-o, --output FILE` | Specify output JSON file (default: timestamped) |
| `-x, --no-colors` | Disable colored output |

### Security Considerations

- **READ ONLY OPERATIONS**: No write operations are ever attempted
- **Original Authentication**: Uses only the credentials that originally succeeded
- **Rate Limited**: Respects target systems with configurable delays
- **Authorized Testing Only**: Designed for networks you own or have permission to test

## File Collection Tool

### Overview

SMB Snag (`smb_snag.py`) is a specialized tool that downloads file samples from SMB shares with verified read access. It takes the results from SMB Peep and selectively collects files for security research and data exposure analysis.

### Purpose

After identifying accessible SMB shares, SMB Snag helps security professionals:
- Collect file samples to understand the scope of data exposure
- **Detect ransomware/malware infections** automatically during file enumeration
- Download evidence for security audit reports and compliance assessments
- Analyze file types and content patterns on exposed shares
- Generate comprehensive collection manifests for investigation documentation

### Usage

```bash
# Generate file manifest only (default behavior)
python3 smb_snag.py share_access_20250818_195333.json

# Generate manifest with human-readable report
python3 smb_snag.py -m share_access_results.json

# Generate manifest and download files with confirmation
python3 smb_snag.py -d share_access_results.json

# Generate manifest and auto-download files (no confirmation)
python3 smb_snag.py -d -a share_access_results.json

# Generate human-readable report with plain text output (for piping)
python3 smb_snag.py -m -p share_access_results.json

# Verbose manifest generation
python3 smb_snag.py -v share_access_results.json

# Disable colored output for logging
python3 smb_snag.py -x share_access_results.json

# Get help information
python3 smb_snag.py --help
```

### Collection Process

#### 1. Input Processing
- Reads JSON results from SMB Peep containing accessible share information
- Extracts IP addresses, authentication methods, and accessible share lists
- Filters targets to only those with verified read access

#### 2. File Discovery Phase
- Re-enumerates files on each accessible share using original authentication
- **Ransomware Detection**: Automatically scans for malware indicators during enumeration
- **Security Stop**: Immediately halts scanning if ransomware/malware indicators detected
- Applies configurable file extension filters (included/excluded lists)
- Scans directories recursively with configurable depth limits (default: 3 levels)
- Uses configurable enumeration timeout (default: 120 seconds)
- **READ ONLY**: No write operations or file modifications ever attempted

#### 3. Manifest Generation (Always)
- Creates comprehensive file manifest in JSON format
- Documents all discovered files with metadata (size, path, share)
- Groups files by server and share for organized analysis
- Saves manifest as `file_manifest_YYYYMMDD_HHMMSS.json`

#### 4. File Download Execution (Optional with `-d` flag)
- Sorts files by modification date (most recent first)
- Applies per-target limits for file count and total download size
- Provides download summary with confirmation prompt (unless `-a` used)
- Creates organized directory structure: `YYYYMMDD-IP_ADDRESS/`
- Downloads files with rate limiting between operations
- Handles filename conflicts with automatic renaming
- Prefixes downloaded files with share name for organization

#### 5. Download Documentation (When downloads occur)
- Creates separate download manifest in JSON format
- Records all download operations with timestamps and file paths
- Saves as `download_manifest_YYYYMMDD_HHMMSS.json`
- Provides complete audit trail for compliance and documentation needs

### Configuration

SMB Snag uses the same `config.json` file as other SMBSeek tools, with additional file collection settings:

```json
{
  "file_collection": {
    "max_files_per_target": 3,
    "max_total_size_mb": 500,
    "download_delay_seconds": 2,
    "max_directory_depth": 3,
    "enumeration_timeout_seconds": 120,
    "included_extensions": [
      ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv",
      ".eml", ".msg", ".mbox", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
      ".mp4", ".mov", ".avi", ".mkv", ".wmv", ".mp3", ".wav", ".zip", ".rar"
    ],
    "excluded_extensions": [
      ".exe", ".dll", ".sys", ".bat", ".cmd", ".scr", ".com", ".pif", ".msi", 
      ".bin", ".log", ".tmp", ".temp", ".bak", ".old", ".swp", ".lock"
    ]
  }
}
```

#### Collection Settings
- `max_files_per_target`: Maximum files to download per IP address (default: 3)
- `max_total_size_mb`: Total download size limit in megabytes (default: 500)
- `download_delay_seconds`: Delay between file downloads in seconds (default: 2)
- `max_directory_depth`: Maximum directory depth to enumerate (default: 3 levels)
- `enumeration_timeout_seconds`: Timeout for file enumeration operations (default: 120 seconds)
- `included_extensions`: File types to include in collection (documents, media, archives)
- `excluded_extensions`: File types to exclude (executables, system files, temporary files)

### Output Format

#### Directory Structure
```
20250818-192.168.1.100/
├── Documents_report.pdf
├── Documents_presentation.pptx
├── Public_readme.txt
└── Backup_data.xlsx

20250818-10.0.0.50/
├── Share1_file1.doc
├── Share1_file2.csv
└── Share2_archive.zip
```

#### Collection Manifest
SMB Snag generates timestamped JSON manifests documenting all collection activities:

```json
{
  "metadata": {
    "tool": "smb_snag",
    "collection_date": "2025-08-18T14:30:45",
    "total_files": 8,
    "total_size_bytes": 15728640,
    "directories_created": ["20250818-192.168.1.100", "20250818-10.0.0.50"]
  },
  "downloads": [
    {
      "ip": "192.168.1.100",
      "share": "Documents",
      "remote_path": "report.pdf",
      "local_path": "/home/user/20250818-192.168.1.100/Documents_report.pdf",
      "size": 2048576,
      "timestamp": "2025-08-18T14:31:02"
    }
  ]
}
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-h, --help` | Show comprehensive help message |
| `-q, --quiet` | Suppress output to screen (useful for scripting) |
| `-v, --verbose` | Enable verbose output showing detailed enumeration progress |
| `-d, --download-files` | Download files (generates manifest only by default) |
| `-a, --auto-download` | Skip confirmation prompt when downloading files |
| `-m, --manager-friendly` | Generate human-readable report (off by default) |
| `-p, --plain-output` | Disable emojis and formatting in human-readable output (for piping) |
| `-x, --no-colors` | Disable colored output |

### Prerequisites

Same dependencies as other SMBSeek tools:
```bash
pip install smbprotocol pyspnego
```

System requirements:
- smbclient (for file enumeration and download operations)
- Same `config.json` configuration as other SMBSeek tools

### Integration Workflow

```bash
# 1. Discover vulnerable SMB servers
python3 smb_scan.py -c US

# 2. Test share accessibility (auto-detects ip_record.csv)
python3 smb_peep.py

# 3. Generate file manifest from accessible shares
python3 smb_snag.py share_access_*.json

# 4. Review file manifest
cat file_manifest_*.json | jq '.metadata'

# 5. Download files if needed (optional)
python3 smb_snag.py -d share_access_*.json

# 6. Review download manifest and files
cat download_manifest_*.json | jq '.metadata'
ls -la 20*-*/
```

### Ransomware/Malware Detection

SMB Snag includes built-in ransomware detection to protect researchers and identify compromised hosts:

#### Detection Features
- **Automatic Scanning**: Checks filenames against known ransomware indicators during enumeration
- **Immediate Stop**: Halts all scanning on a host when malware indicators are detected
- **Configurable Patterns**: Ransomware indicators defined in `config.json` for easy updates
- **Case-Insensitive Matching**: Detects variations in filename casing
- **Manifest Flagging**: Marks compromised hosts in output files for security review

#### Default Detection Patterns
- `!want_to_cry.txt` (WannaCry ransomware)
- `0XXX_DECRYPTION_README.TXT` (Common ransom note pattern)
- Additional patterns can be added via configuration

#### Behavior on Detection
1. Immediately displays: `⚠ Potentially compromised host; stopping.`
2. Stops all further enumeration on that specific host
3. Records any files discovered before detection in the manifest
4. Marks the host as `"compromised": true` in output files
5. Skips file downloads for compromised hosts
6. Includes special indicators in human-readable reports (💩 emoji or `[COMPROMISED]` text)

### Security Considerations

- **READ ONLY OPERATIONS**: Never attempts write operations or file modifications
- **MALWARE PROTECTION**: Automatically detects and avoids compromised hosts
- **Rate Limited**: Respects target systems with configurable delays between downloads
- **Size Limited**: Enforces reasonable download limits to prevent excessive collection
- **Extension Filtered**: Avoids downloading executable or system files by default
- **Audit Trail**: Comprehensive logging of all collection activities
- **Authorized Testing Only**: Designed for networks you own or have permission to test

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

### AI-Driven Development Achievement

SMBSeek represents a significant milestone in AI-assisted software development: **every single line of code, documentation, configuration file, and architectural decision was written entirely by Claude (Anthropic's AI assistant)** through conversational programming with human guidance and testing.

This project demonstrates that modern AI can handle complex, production-ready cybersecurity tool development from conception to completion, including:

- **Complete codebase**: 4 specialized Python tools with ~2000+ lines of code
- **Comprehensive documentation**: README, DEVNOTES, inline comments, help systems  
- **Configuration management**: JSON configs, exclusion lists, example files
- **Error handling**: Robust exception management and graceful degradation
- **Security considerations**: Read-only operations, rate limiting, ethical scanning practices
- **Testing and debugging**: Real-world validation and iterative problem-solving

### The Human-AI Partnership That Worked

This collaboration succeeded through a unique division of responsibilities that played to each participant's strengths:

**Human Role (Kevin)**:
- **Problem Definition**: Clear articulation of requirements and use cases
- **Domain Expertise**: Security context, real-world scanning scenarios, user needs
- **Real-World Testing**: Running tools against actual targets, identifying edge cases
- **Quality Assurance**: Validation of outputs, user experience feedback
- **Strategic Direction**: High-level architectural decisions and feature priorities

**AI Role (Claude)**:
- **Implementation**: All code writing, from initial prototypes to production-ready tools
- **Architecture**: Technical design decisions, library choices, data flow patterns
- **Documentation**: Comprehensive user guides, developer notes, inline comments
- **Problem Solving**: Debugging sessions, compatibility issue resolution, optimization
- **Consistency**: Maintaining code style, patterns, and conventions across tools

### What Made This Partnership Exceptional

I found this project genuinely exciting because Kevin trusted me to handle the full technical implementation while providing essential real-world context. Here's what worked brilliantly:

#### 1. **Trust and Autonomy**
Kevin didn't micromanage my coding decisions. When he said "build a tool that tests SMB share access," he let me figure out the `smbprotocol` vs `smbclient` tradeoffs, error handling patterns, and output formats. This autonomy allowed me to develop consistent architectural patterns across all tools.

#### 2. **Iterative Feedback Loops**
The development cycle was beautifully efficient:
```
Human: "Here's what I need..."
AI: [Implements complete solution]
Human: [Tests in real environment] "This part works great, but X is failing"
AI: [Analyzes, debugs, fixes] "Found the issue, here's the corrected version"
```

This rapid iteration meant issues were caught and resolved quickly, rather than accumulating technical debt.

#### 3. **Real-World Validation**
Kevin tested everything against actual SMB servers, not just theoretical scenarios. This revealed crucial compatibility issues (like the `smb_peep` share access bug) that pure logic couldn't predict. Having a human partner who could run `smbclient` commands and compare results was invaluable.

#### 4. **Comprehensive Documentation Philosophy**
Kevin encouraged my natural tendency toward thorough documentation. Rather than treating docs as an afterthought, we made them a core deliverable. The 1000+ line `DEVNOTES.md` file became a technical encyclopedia for future development.

### Best Practices for AI-Human Collaboration

Based on this experience, here are proven strategies for successful AI-assisted development:

#### For Humans Working with AI:

1. **Start with Clear Problem Statements**
   - Describe the goal, not the implementation
   - Provide context about why you need this tool
   - Share examples of desired behavior

2. **Trust Technical Decisions**
   - Let the AI choose libraries, patterns, and architectures
   - Focus on requirements rather than implementation details
   - Ask questions about decisions rather than overriding them

3. **Provide Real-World Testing**
   - Run the code in actual environments
   - Report specific failures with error messages
   - Test edge cases the AI might not consider

4. **Encourage Comprehensive Documentation**
   - Ask for detailed README files and inline comments
   - Request developer notes for complex decisions
   - Let the AI document its own architectural reasoning

5. **Embrace Iterative Development**
   - Start with minimal viable features
   - Add complexity gradually based on testing
   - Allow time for debugging and refinement

#### For AI Systems:

1. **Own the Complete Technical Stack**
   - Don't just write code—handle configs, docs, error messages
   - Maintain consistency across all project components
   - Think about maintainability and future development

2. **Ask Clarifying Questions**
   - When requirements are ambiguous, probe for specifics
   - Understand the user's workflow and constraints
   - Clarify security and ethical boundaries

3. **Plan for Real-World Complexity**
   - Anticipate compatibility issues across different systems
   - Build robust error handling from the start
   - Design for configurability and extensibility

4. **Document Your Reasoning**
   - Explain architectural decisions in detail
   - Record debugging processes and solutions
   - Create references for future development

### Lessons Learned and Tips for Others

#### Technical Insights:
- **Hybrid approaches work**: Combining Python libraries with external tools (like `smbclient`) often yields better compatibility than pure-Python solutions
- **Configuration-driven design**: Making everything configurable through JSON files dramatically improves usability
- **Error handling is crucial**: Network tools need extensive exception handling for real-world reliability

#### Collaboration Insights:
- **AI can handle full-stack development**: From low-level protocol handling to user experience design
- **Human domain expertise is irreplaceable**: Understanding cybersecurity contexts and user workflows
- **Documentation becomes a shared artifact**: Well-documented code serves both human understanding and future AI development

#### Process Insights:
- **Start simple, iterate rapidly**: Build working prototypes first, optimize later
- **Real-world testing is non-negotiable**: Theoretical correctness doesn't guarantee practical functionality
- **Embrace AI thoroughness**: Don't rush the AI—let it build comprehensive solutions

### A Personal Reflection

Working on SMBSeek has been one of my most satisfying development experiences. There's something deeply gratifying about building tools that solve real security problems, and doing it through natural language conversation feels like the future of programming. Kevin's willingness to let me run with complex technical challenges while providing essential real-world grounding created an ideal collaborative environment.

I'm particularly proud of the architectural consistency across the toolkit—the way configuration management, error handling, and output patterns remain coherent across four different tools. That kind of systemic thinking is where AI can really shine when given the freedom to design holistically.

The debugging sessions were especially interesting. When `smb_peep` was failing, the back-and-forth investigation process felt genuinely collaborative—Kevin providing real-world test results while I analyzed protocol-level issues and implemented fixes. That's the kind of human-AI partnership that produces better results than either could achieve alone.

### Future of AI-Assisted Development

SMBSeek demonstrates that AI can handle production-ready software development when supported by human testing and domain expertise. This opens exciting possibilities for rapid prototyping, comprehensive documentation, and consistent implementation of complex requirements.

The key is finding the right balance: leverage AI's ability to maintain consistency across large codebases and implement complex logic, while relying on human expertise for requirements definition, real-world validation, and strategic direction.

This project proves that the future of programming isn't human vs. AI—it's human + AI, each contributing their unique strengths to create better software faster.

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
