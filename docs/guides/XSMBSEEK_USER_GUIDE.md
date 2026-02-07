# SMBSeek User Guide

**A beginner-friendly guide to identifying and analyzing SMB servers with weak authentication**

---

## 🚀 Quick Start (10 Minutes)

**Want to get scanning right away?** Follow these steps:

### 1. Get a Shodan API Key
1. Visit [shodan.io](https://shodan.io) and create a free account
2. Go to your account page and copy your API key
3. Keep this handy - you'll need it in step 4

### 2. Install SMBSeek
```bash
# Clone the repository
git clone <repository-url>
cd smbseek

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# OR: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### 3. Install System Dependencies
```bash
# Linux (Ubuntu/Debian)
sudo apt install smbclient

# macOS
brew install samba

# Windows - Download from samba.org or use WSL
```

### 4. Configure Your API Key
Edit `conf/config.json`:
```json
{
  "shodan": {
    "api_key": "paste_your_api_key_here"
  }
}
```

### 5. Run Your First Scan
```bash
# New unified CLI (recommended)
./smbseek.py --country US

# OR use the legacy tools (still supported)
python3 tools/smb_scan.py -c US
```

**That's it!** In a few minutes, you'll have a database full of SMB server data ready to explore.

---

## 📦 Complete Installation Guide

### System Requirements
- **Python**: 3.6 or newer
- **Operating System**: Linux, macOS, or Windows
- **Network**: Internet connection for Shodan API
- **Storage**: 50MB minimum for database and tools

### Installation by Operating System

#### 🐧 Linux (Ubuntu/Debian)
```bash
# Update package list
sudo apt update

# Install Python and system dependencies
sudo apt install python3 python3-venv python3-pip smbclient

# Clone and setup SMBSeek
git clone <repository-url>
cd smbseek
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 🐧 Linux (CentOS/RHEL/Fedora)
```bash
# Install Python and system dependencies
sudo dnf install python3 python3-venv python3-pip samba-client
# OR for older versions: sudo yum install python3 python3-venv python3-pip samba-client

# Clone and setup SMBSeek
git clone <repository-url>
cd smbseek
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 🍎 macOS
```bash
# Install Homebrew if you haven't already
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python samba

# Clone and setup SMBSeek
git clone <repository-url>
cd smbseek
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### 🪟 Windows
```powershell
# Install Python from python.org (ensure "Add to PATH" is checked)
# Install Git from git-scm.com

# Clone and setup SMBSeek
git clone <repository-url>
cd smbseek
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Note: smbclient support on Windows is limited
# Consider using WSL (Windows Subsystem for Linux) for full functionality
```

### Configuration Setup
1. **Copy the example config**: `cp conf/config.json.example conf/config.json` (if available)
2. **Add your Shodan API key** to `conf/config.json`
3. **The database will be created automatically** when you run your first scan

---

## 🎯 Understanding SMBSeek

### What SMBSeek Does
SMBSeek identifies SMB (Server Message Block) servers that allow weak authentication methods like anonymous or guest access. This is useful for:

- **Security auditing** of your own networks
- **Educational research** on network security
- **Vulnerability assessment** in authorized environments

### Database-First Approach  
SMBSeek stores all scan results in a SQLite database (`smbseek.db`) that automatically grows with your scans. This allows you to:
- **Query across multiple scans** to see trends
- **Correlate data** between different security tools
- **Export data** in various formats for analysis
- **Track changes** over time with historical data

### The Workflow
1. **Scan**: Query Shodan and test SMB servers
2. **Store**: Save results automatically in the database  
3. **Query**: Use built-in tools to explore your data
4. **Export**: Generate data exports for external analysis

---

## 🔧 Basic Usage

### Your First Scan
```bash
# Activate your virtual environment
source venv/bin/activate  # Linux/macOS
# OR: venv\Scripts\activate  # Windows

# Unified CLI (recommended) - uses default countries from config.json
./smbseek.py

# Or scan specific country
./smbseek.py --country US

# Legacy approach (still supported)
python3 tools/smb_scan.py -c US
```

### Common Scan Commands
```bash
# Unified CLI commands (recommended)
./smbseek.py                    # Uses default countries from config
./smbseek.py --country US       # Scan specific country
./smbseek.py --country US,GB,CA # Scan multiple countries
./smbseek.py --quiet            # Quiet mode (less output)
./smbseek.py --verbose          # Verbose mode (detailed information)

# Discovery only (without full workflow)
./smbseek.py discover               # Uses config defaults
./smbseek.py discover --country US  # Specific country

# Legacy commands (still supported)
python3 tools/smb_scan.py -c US,GB,CA  # Multiple countries
python3 tools/smb_scan.py -q -c US     # Quiet mode
python3 tools/smb_scan.py -v -c US     # Verbose mode
python3 tools/smb_scan.py -t           # Global scan
```

### Understanding the Output

SMBSeek provides detailed progress information throughout the scanning process:

#### During Discovery Phase
```bash
ℹ Querying Shodan for SMB servers in: United States, Canada
✓ Found 1000 SMB servers in Shodan database
ℹ Applying exclusion filters...
ℹ Checking 1000 IPs against database (200 known servers)...
ℹ Analyzing scan history and rescan policies...
ℹ Database filtering complete: 850 new, 150 known, 900 to scan

📊 Scan Planning:
  • Total from Shodan: 1000
  • Already known: 150
  • New discoveries: 850
  • Recently scanned (skipping): 50
  • Will scan: 900
🚀 Proceeding with 900 hosts...
```

#### During Authentication Testing
```bash
ℹ Testing SMB authentication on 900 hosts...
ℹ 📊 Progress: 225/900 (25.0%) | Success: 12, Failed: 213
[225/900] Testing 192.168.1.100...
  ✓ 192.168.1.100: Anonymous (smbclient)
```

#### Final Results
```bash
Discovery Results
-----------------
Shodan Results: 1000
Excluded IPs: 0
Hosts Tested: 900
Successful Auth: 45
Failed Auth: 855
✓ Found 45 accessible SMB servers
✓ Results saved to database (session: 15)
```

**Status Message Guide:**
- **ℹ** (blue): Informational status updates
- **✓** (green): Successful operations and completion
- **⚠** (yellow): Warnings or important notices  
- **✗** (red): Errors or failed operations
- **📊** (blue): Statistics and progress indicators
- **🚀** (blue): Action indicators (starting operations)

Your scan data is now stored in `smbseek.db` and ready to query!

---

## 📊 Accessing Your Data

### Quick Database Queries
SMBSeek includes a query tool for exploring your data without writing SQL:

```bash
# Show summary of all servers
python3 tools/db_query.py --summary

# Show vulnerability breakdown
python3 tools/db_query.py --vulnerabilities

# Show country distribution
python3 tools/db_query.py --countries

# Show most common share names
python3 tools/db_query.py --shares

# Show everything
python3 tools/db_query.py --all
```

### Basic Database Examples

**Example 1: Find all servers in my country**
```bash
# Unified CLI (recommended)
./smbseek.py report --countries

# Legacy approach
python3 tools/db_query.py --countries
```
This shows how many vulnerable servers were found in each country.

**Example 2: Show me the most accessible servers**
```bash
# Unified CLI (recommended)
./smbseek.py report --summary

# Legacy approach
python3 tools/db_query.py --summary
```
This displays servers with the most accessible shares, sorted by accessibility.

**Example 3: Which countries have the most vulnerable servers?**
```bash
# Unified CLI (recommended)
./smbseek.py report --countries

# Legacy approach
python3 tools/db_query.py --countries
```
See the geographic distribution of vulnerable SMB servers.

**Example 4: What are the most common share names?**
```bash
# Unified CLI (recommended)
./smbseek.py report --shares

# Legacy approach
python3 tools/db_query.py --shares
```
Discover the most frequently found share names across all servers.

**Example 5: Show me servers discovered in the last week**
```bash
# Database query tool (recommended)
python tools/db_query.py --statistics --days 7

# Legacy approach
python3 tools/db_query.py --statistics --days 7
```
View recent scan activity and success rates.

### Advanced Database Examples

For users comfortable with basic SQL, you can query the database directly:

**Example 1: Correlate servers with vulnerabilities and shares**
```python
# Create a Python script or use interactive Python
from db_manager import DatabaseManager

db = DatabaseManager("smbseek.db")
results = db.execute_query("""
    SELECT s.ip_address, s.country, COUNT(sa.share_name) as share_count, 
           COUNT(v.id) as vuln_count
    FROM smb_servers s
    LEFT JOIN share_access sa ON s.id = sa.server_id AND sa.accessible = TRUE
    LEFT JOIN vulnerabilities v ON s.id = v.server_id
    GROUP BY s.id
    HAVING share_count > 2 OR vuln_count > 0
    ORDER BY share_count DESC, vuln_count DESC
""")
```

**Example 2: Generate trend analysis over time**
```python
from db_manager import DatabaseManager

db = DatabaseManager("smbseek.db")
results = db.execute_query("""
    SELECT DATE(timestamp) as scan_date,
           COUNT(*) as servers_found,
           AVG(scan_count) as avg_rescans
    FROM smb_servers
    WHERE last_seen >= date('now', '-30 days')
    GROUP BY DATE(timestamp)
    ORDER BY scan_date DESC
""")
```

**Example 3: Export data for external tools**
```bash
# Export all tables to CSV files
python3 tools/db_maintenance.py --export

# This creates timestamped CSV files for external analysis
```

---

## 🔄 Common Workflows

### Security Assessment Workflow
```bash
# Unified CLI (recommended)
1. ./smbseek.py                    # Complete workflow
2. ./smbseek.py report --summary       # Review results
3. ./smbseek.py report --countries     # Focus areas
4. ./smbseek.py database --export      # Generate report
```

```bash
# Legacy approach (still supported)
1. python3 tools/smb_scan.py -c US
2. python3 tools/db_query.py --summary
3. python3 tools/db_query.py --countries
4. python3 tools/db_maintenance.py --export
```

### Educational/Research Workflow
```bash
# Unified CLI (recommended)
1. ./smbseek.py --country US,GB,CA # Broad scan
2. ./smbseek.py report --all           # Explore data
3. ./smbseek.py database --query       # Custom queries
4. ./smbseek.py database --export      # Export findings
```

### Monitoring Workflow
```bash
# Unified CLI (recommended)
1. ./smbseek.py                    # Regular scans
2. ./smbseek.py report --statistics    # Track changes
3. ./smbseek.py database --maintenance # Database maintenance
4. ./smbseek.py database --backup      # Backup data
```

---

## 🌍 Country Configuration and Resolution

### How SMBSeek Selects Countries to Scan

SMBSeek uses a 3-tier system to determine which countries to scan:

1. **Command Line Override** (highest priority)
   ```bash
   ./smbseek.py --country US        # Scan only United States
   ./smbseek.py --country US,GB,CA  # Scan multiple countries
   ```

2. **Configuration File Defaults** (medium priority)
   ```json
   // In conf/config.json
   "countries": {
     "US": "United States",
     "GB": "United Kingdom", 
     "CA": "Canada"
   }
   ```
   ```bash
   ./smbseek.py  # Uses US, GB, CA from config
   ```

3. **Global Scan Fallback** (lowest priority)
   ```bash
   # If no --country AND no countries in config.json
   ./smbseek.py  # Scans globally (no country filter)
   ```

### Country Code Reference

SMBSeek accepts **ISO 3166-1 alpha-2** country codes (two-letter codes):

**Common Examples:**
- `US` - United States
- `GB` - United Kingdom
- `CA` - Canada  
- `AU` - Australia
- `DE` - Germany
- `FR` - France
- `JP` - Japan
- `CN` - China

**Multiple Countries:**
```bash
./smbseek.py --country US,GB,CA,AU,DE  # Comma-separated
```

**Note:** Shodan may return more servers for global scans but they may be less relevant to your specific needs. Country-specific scans are usually more targeted and manageable.

---

## ⚙️ Essential Configuration

### Key Settings in conf/config.json

**Rate Limiting** (be respectful):
```json
{
  "connection": {
    "timeout": 30,
    "rate_limit_delay": 3,
    "share_access_delay": 7
  }
}
```

**Database Settings**:
```json
{
  "database": {
    "enabled": true,
    "path": "smbseek.db",
    "backup_enabled": true,
    "backup_interval_hours": 24
  }
}
```

**Geographic Scope**:
```json
{
  "countries": {
    "US": "United States",
    "GB": "United Kingdom", 
    "CA": "Canada"
  }
}
```

### When to Modify Settings
- **Increase delays** if you're getting connection errors
- **Add countries** to expand your scan scope  
- **Enable backups** for important long-term data
- **Adjust timeouts** for slow network conditions

---

## ❓ Troubleshooting

### Common Issues & Solutions

**"API key not working"**
- Check that you copied the entire key from Shodan.io
- Ensure the key is in quotes in conf/config.json
- Verify your Shodan account is active

**"No smbclient found"**
- Install smbclient using your system's package manager
- On Windows, consider using WSL for full functionality
- Tool will work with reduced functionality without smbclient

**"Database locked" errors**
- Close any other programs accessing the database
- Run: `python3 tools/db_maintenance.py --check`
- If persistent, restart and try again

**"Connection timeouts"**  
- Increase timeout values in conf/config.json
- Check your internet connection
- Some networks may block SMB traffic (port 445)

**"No results found"**
- Try different countries: `python3 tools/smb_scan.py -c GB`
- Check Shodan API limits (free accounts have daily limits)
- Verify your network allows outbound connections

### Getting Help
- **Verbose mode**: Add `-v` to any command for detailed output
- **Check logs**: Look for error messages in the console output  
- **Database status**: Run `python3 db_maintenance.py --info`
- **Configuration test**: Try `python3 smb_scan.py --help`

---

## 📚 Next Steps

### Ready to Go Deeper?
- **[README.md](README.md)**: Complete technical documentation
- **[DEVNOTES.md](DEVNOTES.md)**: Architecture and development guide
- **[DATABASE_MIGRATION_GUIDE.md](DATABASE_MIGRATION_GUIDE.md)**: Advanced database features

### Advanced Usage
- **Custom Queries**: Learn SQL to create powerful custom reports
- **Automation**: Set up scheduled scans with cron jobs
- **Integration**: Export data to security management platforms
- **Extension**: Modify tools for your specific needs

### Security & Legal
- **Only scan networks you own** or have explicit permission to test
- **Follow responsible disclosure** for any vulnerabilities found
- **Respect rate limits** to avoid impacting target networks
- **Use for defensive purposes** - this is a security research tool

---

## 🎓 Understanding the Results

### What Each Tool Does
- **tools/smb_scan.py**: Discovers servers with weak SMB authentication
- **tools/db_query.py**: Explores and reports on your scan data
- **tools/db_maintenance.py**: Manages database backups and optimization

### Interpreting Your Data
- **High share counts**: Servers with many accessible shares
- **Authentication methods**: How the server was accessed (Anonymous, Guest)
- **Geographic patterns**: Countries with more vulnerable servers
- **Scan statistics**: Success rates and scanning trends

### Making Decisions
Use SMBSeek results to:
- **Prioritize security efforts** on high-risk systems
- **Understand exposure patterns** in different regions
- **Track security improvements** over time
- **Generate evidence** for security assessments

---

## 🖥️ GUI Frontend (xsmbseek)

The xsmbseek GUI provides a user-friendly interface for SMBSeek with advanced scan configuration options.

### Launching the GUI
```bash
# Basic GUI launch
./xsmbseek

# With specific SMBSeek installation path
./xsmbseek --smbseek-path /path/to/smbseek

# Mock mode for testing (no SMBSeek required)
./xsmbseek --mock
```

### Advanced Scan Options

The scan dialog provides comprehensive configuration options in a clean, direct interface:

#### Scan Configuration Options
All options are directly visible and immediately accessible:

- **Country Code**: Specify countries to scan (e.g., US, GB, CA or US,GB,CA) - leave blank for global scan
- **Max Shodan Results**: Limit discovery results (1-10000, default: 1000)
- **Recent Hours Filter**: Filter for recent scan data (hours, empty for default)
- **Rescan Options**:
  - ☐ Rescan all existing hosts (force rescan regardless of recent scans)
  - ☐ Rescan previously failed hosts (retry hosts that failed before)
- **Security Mode**:
  - (•) Cautious – enforce signed SMB2+/SMB3 connections (default)
  - ( ) Legacy – allow SMB1/unsigned access (requires explicit confirmation)
- **API Key Override**: Temporary Shodan API key override (masked input)

#### Settings Persistence
- Advanced options are automatically saved and restored between sessions
- User preferences persist across application restarts
- Settings integrate with the main configuration system

#### Validation and Error Handling
- Real-time validation for numeric fields
- Clear error messages for invalid inputs
- Graceful fallback when settings are unavailable

### GUI Integration
The GUI seamlessly integrates with the SMBSeek backend:
- All CLI options available through the interface
- Real-time progress tracking and status updates
- Complete database access and reporting
- Configuration management with live editing

## 🔍 RCE Vulnerability Analysis

SMBSeek includes experimental RCE (Remote Code Execution) vulnerability detection to identify known SMB security issues during enumeration.

### Overview
The RCE analysis system:
- Uses signature-based detection for known SMB vulnerabilities
- Analyzes enumeration data without active exploitation
- Provides risk scores (0-100) with confidence ratings
- Identifies vulnerability signatures with CVE references
- All results marked as "low confidence" during this initial phase

### CLI Usage

Enable RCE analysis during scans:
```bash
# Include RCE analysis in scan
./smbseek --country US --check-rce

# RCE analysis with detailed output
./smbseek --country US --check-rce --verbose
```

**Sample output:**
```
[1/1] Testing 192.168.1.100 (US)...
Found 3 shares to test on 192.168.1.100
3/3 shares accessible on 192.168.1.100: IPC$, SYSVOL, NETLOGON
RCE Analysis: 45/100 (medium, low confidence)
```

### GUI Usage

1. **Open Scan Dialog**: Click "Start New Scan" in SMBSeek GUI
2. **Enable RCE Analysis**: Check "Check for RCE vulnerabilities during share access testing"
3. **Configure Settings**: The checkbox state persists across sessions
4. **Run Scan**: Execute your scan normally
5. **View Results**: RCE analysis appears in server details and probe results

### Probe Integration

When enabled, RCE analysis runs during the probe phase:
- Analysis triggers after successful share enumeration
- Results cached alongside probe data
- Available in server details view
- Includes vulnerability details and evidence

### Understanding Results

**Risk Levels:**
- **Low (0-24)**: Minimal RCE risk detected
- **Medium (25-59)**: Moderate vulnerability indicators
- **High (60-84)**: Significant RCE risk factors
- **Critical (85-100)**: Severe vulnerability exposure

**Confidence Levels:**
- **Low Confidence**: All results during initial implementation
- Future versions may include medium/high confidence ratings

**Matched Signatures:**
Common vulnerabilities detected include:
- **EternalBlue (CVE-2017-0144)**: MS17-010 SMB1 vulnerability
- **SMBGhost (CVE-2020-0796)**: SMB3 compression vulnerability
- **ZeroLogon (CVE-2020-1472)**: Netlogon privilege escalation
- **PrintNightmare (CVE-2021-34527)**: Print Spooler RCE
- **PetitPotam (CVE-2021-36942)**: NTLM relay vulnerability

### Read-only File Browser (GUI)

The Server List and Server Details views include a **Browse (read-only)** action that opens an integrated SMB navigator.

**Capabilities:**
- Lists directories over SMB1/2/3 with enforced limits (entries, depth, path length, and timeouts).
- No previews or execution. The only action is **Download to quarantine**; files land under `~/.smbseek/quarantine/<timestamp>/<host>/<share>/` with exec bits cleared.
- Entry points: action bar button, row context menu, `Ctrl+B`, and the Browse button inside Server Details.
- Downloads begin as soon as files are discovered: directory expansion now streams into downloads, and per-file progress updates while bytes flow for quicker feedback.

**Configuration:**
- Tune limits in `conf/config.json` under `file_browser` (`allow_smb1`, `connect_timeout_seconds`, `request_timeout_seconds`, `max_entries_per_dir`, `max_depth`, `max_path_length`, `download_chunk_mb`, `quarantine_root`).
- Defaults favor safety and performance; raise limits cautiously for very large shares.

**Failure modes:**
- Connection/auth failures surface inline in the browser window with the underlying SMB error.
- If a directory exceeds `max_entries_per_dir`, listing truncates and shows a warning; deepen navigation instead of raising the cap unless necessary.

### Sandbox Investigation Shell

For elevated RCE scores, SMBSeek provides a read-only investigation environment:

**Requirements:**
- Docker or Podman installed
- Available as CLI-only feature initially

**Features:**
- Isolated Alpine Linux container with SMB tools
- Read-only filesystem for security
- Command logging to `~/.smbseek/logs/sandbox_sessions/`
- 30-day automatic log retention
- Pre-configured with smbclient, nmap-ncat

**Session Logging:**
```json
{
  "ip_address": "192.168.1.100",
  "rce_score": 75,
  "start_time": "2024-01-15T14:30:00Z",
  "commands": [
    {"timestamp": "...", "type": "COMMAND", "command": "smbclient -L //192.168.1.100"},
    {"timestamp": "...", "type": "COMMAND", "command": "nmap -p 445 192.168.1.100"}
  ]
}
```

### Security Considerations

**Defensive Focus:**
- No active exploitation or vulnerability testing
- Analysis based on enumeration data only
- Read-only investigation environment
- Manual signature management (no auto-updates)

**Privacy & Safety:**
- All analysis performed locally
- No vulnerability data transmitted externally
- Sandbox environment isolated from host system
- Command logging for audit trail

### Managing Signatures

Signatures stored in `signatures/rce_smb/` as YAML files:
- Manual updates only (no automatic downloads)
- Comprehensive validation before loading
- CVE-based organization with metadata
- Community contributions welcome (with review)

See [`RCE_SIGNATURE_GUIDE.md`](RCE_SIGNATURE_GUIDE.md) for detailed signature management.

---

**Ready to start exploring SMB security? Use the CLI for automation or the GUI for interactive exploration!**
