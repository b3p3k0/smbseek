# Enhanced Share Tracking User Guide

## What's New in SMBSeek Share Tracking

SMBSeek now provides enhanced share tracking that gives you complete visibility into both the total number of shares discovered on each host and which ones are actually accessible. This enhancement helps you better understand the scope of your SMB discovery results.

### New Capabilities

**Before Enhancement:**
- ✅ Track which shares are accessible on each host
- ❌ No easy way to see total shares discovered vs. accessible shares

**After Enhancement:**
- ✅ Track which shares are accessible on each host  
- ✅ See total shares discovered per host (accessible + non-accessible)
- ✅ Get comprehensive statistics and counts
- ✅ Better data for reporting and analysis

## Quick Start Guide

### Step 1: Check Your Current Database

First, let's see what data you currently have:

```bash
# Check your current database status  
python3 tools/db_query.py --summary
```

This will show you how many hosts and shares are currently tracked.

### Step 2: Install the Enhancement (Required)

Run this command to add the enhanced tracking capability to your existing database:

```bash
# Install the enhanced share tracking
python3 tools/add_share_summary_view.py
```

**Safe Operation**: This command only adds new functionality - it won't modify or delete your existing data.

### Step 3: Verify Installation

Check that the enhancement was installed correctly:

```bash
# Verify the enhancement
python3 tools/add_share_summary_view.py --dry-run
```

You should see a message indicating the view already exists.

## Understanding the New Data Format

### Example: Before vs After

**Your existing data** (what you had before):
- Host 192.168.1.100 has accessible shares: home, files, documents

**Enhanced data** (what you get now):
- Host 192.168.1.100 discovered 5 total shares: home, files, documents, admin$, c$  
- Of these, 3 are accessible: home, files, documents
- Share access rate: 60% (3 accessible out of 5 total)

### Data You Can Now Access

1. **Total shares discovered** per host
2. **Accessible shares count** per host  
3. **Complete share lists** (all shares found during enumeration)
4. **Access rates** and statistics
5. **Historical tracking** of when shares were last tested

## Using the Enhanced Features

### Method 1: Through Database Queries

You can access the new data through SQL queries:

```bash
# Get enhanced summary (after installing the enhancement)
sqlite3 smbseek.db "SELECT * FROM v_host_share_summary LIMIT 5;"
```

This will show you a table with columns like:
- `ip_address`: The host IP
- `total_shares_discovered`: Total number of shares found
- `accessible_shares_count`: How many are accessible
- `all_shares_list`: Complete list of share names
- `accessible_shares_list`: Just the accessible ones

### Method 2: Through the GUI (If Available)

If you're using a GUI tool that integrates with SMBSeek, it should automatically use the enhanced data to show you:
- Share discovery statistics
- Access rate percentages  
- Complete vs. accessible share breakdowns
- Host-by-host share details

## Common Usage Scenarios

### Scenario 1: Security Assessment

**Question**: "How many shares are exposed vs. how many total shares exist?"

**Answer**: Use the enhanced summary to see:
```bash
sqlite3 smbseek.db "
SELECT 
  COUNT(*) as hosts,
  SUM(total_shares_discovered) as total_shares,
  SUM(accessible_shares_count) as accessible_shares,
  ROUND((SUM(accessible_shares_count) * 100.0 / SUM(total_shares_discovered)), 1) as access_rate_percent
FROM v_host_share_summary;"
```

### Scenario 2: Inventory Management

**Question**: "Which hosts have the most shares, and what are they?"

**Answer**:
```bash
sqlite3 smbseek.db "
SELECT ip_address, country, total_shares_discovered, accessible_shares_count, all_shares_list
FROM v_host_share_summary 
ORDER BY total_shares_discovered DESC 
LIMIT 10;"
```

### Scenario 3: Risk Analysis

**Question**: "Which hosts have high share counts but low access rates?"

**Answer**:
```bash
sqlite3 smbseek.db "
SELECT ip_address, total_shares_discovered, accessible_shares_count,
       ROUND((accessible_shares_count * 100.0 / total_shares_discovered), 1) as access_rate
FROM v_host_share_summary 
WHERE total_shares_discovered >= 5 AND accessible_shares_count < 2
ORDER BY total_shares_discovered DESC;"
```

## Troubleshooting

### Problem: "View doesn't exist" error

**Solution**: You need to install the enhancement first:
```bash
python3 tools/add_share_summary_view.py
```

### Problem: No data in enhanced views

**Possible causes**:
1. **No share discovery yet**: Run SMBSeek discovery first:
   ```bash
   ./smbseek.py
   ```

2. **No accessible shares found**: This is normal if targets have strong security. The enhancement will still show total shares discovered.

### Problem: Enhancement installation fails

**Solution**: Check your database file location:
```bash
# Specify database path explicitly
python3 tools/add_share_summary_view.py --database /path/to/your/smbseek.db
```

### Problem: Want to see what would happen before installing

**Solution**: Use dry-run mode:
```bash
python3 tools/add_share_summary_view.py --dry-run
```

## Data Export and Reporting

### Export Enhanced Data to CSV

```bash
# Export comprehensive share data
sqlite3 -header -csv smbseek.db "
SELECT ip_address as Host, 
       country as Country,
       total_shares_discovered as Total_Shares,
       accessible_shares_count as Accessible_Shares,
       accessible_shares_list as Accessible_Share_Names,
       last_seen as Last_Scan_Date
FROM v_host_share_summary 
ORDER BY total_shares_discovered DESC;" > share_summary.csv
```

### Generate Statistics Report

```bash
# Create a statistics summary
sqlite3 smbseek.db "
SELECT 'Total Hosts' as Metric, COUNT(*) as Value FROM v_host_share_summary
UNION ALL  
SELECT 'Hosts with Accessible Shares', COUNT(*) FROM v_host_share_summary WHERE accessible_shares_count > 0
UNION ALL
SELECT 'Total Shares Discovered', SUM(total_shares_discovered) FROM v_host_share_summary  
UNION ALL
SELECT 'Total Accessible Shares', SUM(accessible_shares_count) FROM v_host_share_summary;"
```

## Best Practices

### 1. Regular Updates
Run SMBSeek scans regularly to keep share data current:
```bash
# Rescan existing hosts every 30 days (default)
./smbseek.py --force-hosts 192.168.1.100
```

### 2. Data Backup
Before installing enhancements, backup your database:
```bash
cp smbseek.db smbseek.db.backup
```

### 3. Performance
- The enhancement includes performance optimizations for large datasets
- Use the new database view for faster queries on large result sets
- Consider limiting queries with `LIMIT` clauses for very large databases

### 4. Security Considerations
- Enhanced tracking provides better visibility into share exposure
- Use total vs. accessible ratios to identify potential security gaps
- Monitor for hosts with many shares but weak access controls

## Getting Help

### Check Current Version
```bash
./smbseek.py --help
```

### Verbose Mode for Debugging
```bash
# Run with detailed output
python3 tools/add_share_summary_view.py --database smbseek.db --verbose
```

### Support Resources
- See `../dev/GUI_INTEGRATION_GUIDE.md` for developer integration details
- Check database status: `./smbseek.py database query --summary`
- View logs in verbose mode for troubleshooting

## Frequently Asked Questions

**Q: Will this enhancement affect my existing data?**  
A: No, it only adds new query capabilities. All existing data remains unchanged.

**Q: Do I need to re-run my scans after installing?**  
A: No, the enhancement works with existing scan data immediately.

**Q: Can I uninstall the enhancement?**  
A: The enhancement only adds a database view. You can remove it with:
```sql
DROP VIEW IF EXISTS v_host_share_summary;
```

**Q: Does this slow down SMBSeek?**  
A: No, it includes performance optimizations and doesn't affect scanning speed.

**Q: What if I have a very large database?**  
A: The enhancement is optimized for large datasets and includes indexing for better performance.

This enhancement gives you the comprehensive share tracking capabilities you requested while maintaining all existing functionality and ensuring data safety.
