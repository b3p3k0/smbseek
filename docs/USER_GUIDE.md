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

# Create virtual environment (you can name this anything)
python3 -m venv smbseek_env
source smbseek_env/bin/activate  # Linux/macOS
# OR: smbseek_env\Scripts\activate  # Windows

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
```bash
# Copy example configuration
cp conf/config.json.example conf/config.json

# Edit conf/config.json and add your API key:
```
```json
{
  "shodan": {
    "api_key": "paste_your_api_key_here"
  }
}
```

### 5. Run Your First Scan
```bash
# Streamlined single command - complete workflow
./smbseek.py --country US

# With verbose output for learning
./smbseek.py --country US --verbose
```

**That's it!** In a few minutes, you'll have a database full of SMB server data ready to explore.

---

## 📦 Complete Installation Guide

### System Requirements
- **Python**: 3.8 or newer (recommended: 3.10+)
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
python3 -m venv smbseek_env
source smbseek_env/bin/activate
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
python3 -m venv smbseek_env
source smbseek_env/bin/activate
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
python3 -m venv smbseek_env
source smbseek_env/bin/activate
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
- **Generate reports** from historical data
- **Export data** in various formats

### The Workflow
1. **Scan**: Query Shodan and test SMB servers (`./smbseek.py [--country ...]`)
2. **Store**: Results are saved automatically in `smbseek.db`
3. **Query**: Explore findings with `python tools/db_query.py`
4. **Act**: Feed the data into your reporting or security processes

---

## 🔧 Basic Usage

### Your First Scan
```bash
# Activate your virtual environment
source venv/bin/activate  # Linux/macOS
# OR: venv\Scripts\activate  # Windows

# Single command interface - complete workflow
./smbseek.py --country US

# Or scan with global defaults
./smbseek.py
```

### Common Scan Commands
```bash
# SMBSeek 3.0 single command interface
./smbseek.py                       # Uses global defaults
./smbseek.py --country US          # Scan specific country
./smbseek.py --country US,GB,CA    # Scan multiple countries
./smbseek.py --quiet               # Quiet mode (less output)
./smbseek.py --verbose             # Verbose mode (detailed information)

# Legacy subcommands (deprecated – emit warnings)
./smbseek.py run --country US      # ⚠️ Deprecated
./smbseek.py discover --country US # ⚠️ Deprecated
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
ℹ 📊 Progress: 225/900 (25.0%) | Success: 12, Failed: 213 (5%)
[225/900] Testing 192.168.1.100...
  ✓ 192.168.1.100: Guest/Blank (smbclient)
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

> **Important**  
> SMBSeek only records “accessible” hosts when a guest credential (guest/guest or guest/blank) works. Null-session/anonymous responses are still logged in discovery output, but they are excluded from share enumeration and database rollups so everything shown in the UI is actually browseable with guest access. Each accessible share now includes a ready-to-use `smb://` link (for example `smb://guest:@203.0.113.10/Public`) so you can open it directly in Finder or Explorer without retyping credentials.

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
# Database query tools
python3 tools/db_query.py --countries
```
This shows how many vulnerable servers were found in each country.

**Example 2: Show me the most accessible servers**
```bash
# Database query tools
python3 tools/db_query.py --summary
```
This displays servers with the most accessible shares, sorted by accessibility.

**Example 3: Which countries have the most vulnerable servers?**
```bash
# Database query tools
python3 tools/db_query.py --countries
```
See the geographic distribution of vulnerable SMB servers.

**Example 4: What are the most common share names?**
```bash
# Database query tools
python3 tools/db_query.py --shares
```
Discover the most frequently found share names across all servers.

**Example 5: Show me servers discovered in the last week**
```bash
python3 tools/db_query.py --recent --days 7
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

### Security Assessment
```bash
./smbseek.py --country US              # Run discovery + share enumeration
python3 tools/db_query.py --summary    # Review key findings
python3 tools/db_query.py --countries  # Identify hotspots
python3 tools/db_maintenance.py --export  # Optional: export snapshots
```

### Broad Recon / Research
```bash
./smbseek.py --country US,GB,CA        # Multi-country scan
python3 tools/db_query.py --all        # Explore comprehensive data
python3 tools/db_query.py --shares     # Investigate common share names
```

### Continuous Monitoring
```bash
./smbseek.py                          # Use defaults for recurring scans
python3 tools/db_query.py --recent --days 7   # Track recent changes
python3 tools/db_maintenance.py --maintenance  # Keep database optimized
python3 tools/db_maintenance.py --backup       # Regular backups
```

---

## 🌍 Country Configuration and Resolution

### How SMBSeek Selects Countries to Scan

SMBSeek uses a 3-tier system to determine which countries to scan:

1. **Command Line Override** (highest priority)
   ```bash
   ./smbseek.py --country US            # Scan only United States
   ./smbseek.py --country US,GB,CA      # Scan multiple countries
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

**Ready to start exploring SMB security? Run your first scan and discover what's out there!**
