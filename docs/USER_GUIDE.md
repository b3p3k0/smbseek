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
- **Generate reports** from historical data
- **Export data** in various formats

### The Workflow
1. **Scan**: Query Shodan and test SMB servers
2. **Store**: Save results automatically in the database  
3. **Query**: Use built-in tools to explore your data
4. **Analyze**: Generate insights and reports

---

## 🔧 Basic Usage

### Your First Scan
```bash
# Activate your virtual environment
source venv/bin/activate  # Linux/macOS
# OR: venv\Scripts\activate  # Windows

# Scan servers in the United States
python3 tools/smb_scan.py -c US
```

### Common Scan Commands
```bash
# Scan multiple countries
python3 tools/smb_scan.py -c US,GB,CA

# Quiet mode (less output)
python3 tools/smb_scan.py -q -c US

# Verbose mode (detailed information)  
python3 tools/smb_scan.py -v -c US

# Scan globally (not recommended for beginners)
python3 tools/smb_scan.py -t
```

### Understanding the Output
When a scan completes, you'll see a summary like:
```
✓ Found 45 servers with weak authentication
✓ Database updated with 45 new entries
✓ Total servers in database: 123
```

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
python3 tools/db_query.py --countries
```
This shows how many vulnerable servers were found in each country.

**Example 2: Show me the most accessible servers**
```bash
python3 tools/db_query.py --summary
```
This displays servers with the most accessible shares, sorted by accessibility.

**Example 3: Which countries have the most vulnerable servers?**
```bash
python3 tools/db_query.py --countries
```
See the geographic distribution of vulnerable SMB servers.

**Example 4: What are the most common share names?**
```bash
python3 tools/db_query.py --shares
```
Discover the most frequently found share names across all servers.

**Example 5: Show me servers discovered in the last week**
```bash
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
1. **Initial Discovery**: `python3 tools/smb_scan.py -c US`
2. **Review Results**: `python3 tools/db_query.py --summary`
3. **Focus Areas**: `python3 tools/db_query.py --countries`
4. **Generate Report**: `python3 tools/db_maintenance.py --export`

### Educational/Research Workflow  
1. **Broad Scan**: `python3 tools/smb_scan.py -c US,GB,CA`
2. **Explore Data**: `python3 tools/db_query.py --all`
3. **Analyze Patterns**: Use custom SQL queries
4. **Document Findings**: Export to spreadsheet software

### Monitoring Workflow
1. **Regular Scans**: Set up scheduled scanning
2. **Track Changes**: `python3 tools/db_query.py --statistics`
3. **Database Maintenance**: `python3 tools/db_maintenance.py --maintenance`
4. **Backup Data**: `python3 tools/db_maintenance.py --backup`

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