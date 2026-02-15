# SMBSeek Database Migration Guide

## Overview

SMBSeek has been migrated from CSV/JSON file storage to a SQLite database system for improved data management, querying capabilities, and performance. This guide covers the migration process and new database features.

## Database Architecture

### Core Components

1. **SQLite Database** (`smbseek.db`) - Central data store
2. **Database Manager** (`db_manager.py`) - Connection and transaction management
3. **Data Access Layer** (`SMBSeekDataAccessLayer`) - High-level database operations
4. **Import Utilities** (`db_import.py`) - Migrate existing data files
5. **Query Utilities** (`db_query.py`) - Database reporting and analysis
6. **Maintenance Tools** (`db_maintenance.py`) - Backup, cleanup, optimization

### Database Schema

The database consists of 6 main tables:

- **`smb_servers`** - Central registry of SMB servers
- **`scan_sessions`** - Track scanning operations and configurations
- **`share_access`** - Share accessibility test results
- **`file_manifests`** - File discovery records
- **`vulnerabilities`** - Security vulnerability findings
- **`failure_logs`** - Connection failures and analysis

### Pre-built Views

- **`v_active_servers`** - Active servers with statistics
- **`v_vulnerability_summary`** - Vulnerability counts by type/severity
- **`v_scan_statistics`** - Scan success rates and metrics

## Migration Process

### Step 1: Import Existing Data

Import all your existing CSV and JSON files:

```bash
# Import all supported files from current directory
python3 db_import.py --all --verbose

# Import specific files
python3 db_import.py --csv ip_record.csv
python3 db_import.py --json share_access_20250819_162025.json

# Import from specific directory
python3 db_import.py --directory /path/to/data/files
```

**Supported File Types:**
- `ip_record*.csv` - SMB scan results
- `failed_record*.csv` - Connection failures
- `share_access_*.json` - Share accessibility data
- `file_manifest_*.json` - File discovery data
- `vulnerability_report_*.json` - Security findings

### Step 2: Verify Data Import

Check that your data was imported correctly:

```bash
# Show comprehensive database summary
python3 db_query.py --all

# Show specific reports
python3 db_query.py --summary
python3 db_query.py --vulnerabilities
python3 db_query.py --countries
python3 db_query.py --shares
```

### Step 3: Database Maintenance

Set up regular database maintenance:

```bash
# Create backup
python3 db_maintenance.py --backup

# Run routine maintenance
python3 db_maintenance.py --maintenance

# Run full maintenance (includes vacuum)
python3 db_maintenance.py --full-maintenance

# Check database health
python3 db_maintenance.py --check
```

## Configuration

Database settings are configured in `config.json`:

```json
{
  "database": {
    "enabled": true,
    "path": "smbseek.db",
    "backup_enabled": true,
    "backup_interval_hours": 24,
    "backup_directory": "db_backups",
    "max_backup_files": 30,
    "connection_timeout": 30,
    "enable_wal_mode": true,
    "enable_foreign_keys": true,
    "vacuum_on_startup": false,
    "legacy_file_output": true
  }
}
```

### Configuration Options

- **`enabled`** - Enable/disable database usage
- **`path`** - Database file location
- **`backup_enabled`** - Automatic backups
- **`backup_interval_hours`** - Backup frequency
- **`backup_directory`** - Backup storage location
- **`max_backup_files`** - Backup retention count
- **`legacy_file_output`** - Continue generating CSV/JSON files

## Database Operations

### Common Queries

```bash
# Show top 20 servers with most shares
python3 db_query.py --summary

# Show vulnerability distribution
python3 db_query.py --vulnerabilities

# Show country-wise server distribution
python3 db_query.py --countries

# Show authentication method breakdown
python3 db_query.py --auth

# Show most common share names
python3 db_query.py --shares
```

### Advanced Querying

For custom queries, you can access the database directly:

```python
from db_manager import DatabaseManager, SMBSeekDataAccessLayer

# Initialize database access
db_manager = DatabaseManager("smbseek.db")
dal = SMBSeekDataAccessLayer(db_manager)

# Custom queries
servers = dal.get_server_summary(limit=50)
vulns = dal.get_vulnerability_summary()
stats = dal.get_scan_statistics(days=7)

# Direct SQL queries
results = db_manager.execute_query("""
    SELECT country, COUNT(*) as count 
    FROM smb_servers 
    WHERE status = 'active' 
    GROUP BY country 
    ORDER BY count DESC
""")
```

### Data Export

Export database contents back to CSV:

```bash
# Export all tables to CSV files
python3 db_maintenance.py --export

# Export to specific directory
python3 db_maintenance.py --export --output-dir exports/
```

## Maintenance Operations

### Backup Management

```bash
# Create manual backup
python3 db_maintenance.py --backup

# View database information
python3 db_maintenance.py --info

# Cleanup old data (90+ days)
python3 db_maintenance.py --cleanup 90
```

### Performance Optimization

```bash
# Update database statistics for better query performance
python3 db_maintenance.py --analyze

# Reclaim space and defragment
python3 db_maintenance.py --vacuum

# Check database integrity
python3 db_maintenance.py --check
```

### Automated Maintenance

Create a cron job for regular maintenance:

```bash
# Add to crontab for daily maintenance at 2 AM
0 2 * * * cd /path/to/smbseek && python3 db_maintenance.py --maintenance
```

## Benefits of Database Migration

### Improved Performance
- **Indexed queries** for fast data retrieval
- **Efficient joins** between related data
- **Optimized storage** with data compression

### Enhanced Data Integrity
- **Foreign key constraints** ensure referential integrity
- **Transaction support** for atomic operations
- **Data validation** at the database level

### Advanced Analytics
- **Cross-tool correlation** of scan results
- **Historical trend analysis** across time periods
- **Aggregated reporting** with built-in views

### Operational Benefits
- **Concurrent access** support for multiple tools
- **Automated backups** with configurable retention
- **Data deduplication** eliminates redundant records
- **Centralized configuration** through config.json

## Backward Compatibility

The migration maintains full backward compatibility:

- **Legacy file outputs** can still be generated
- **Existing tool interfaces** remain unchanged
- **CSV/JSON workflows** continue to work
- **Gradual migration** path from files to database

## Troubleshooting

### Common Issues

**Database locked errors:**
```bash
# Check for orphaned connections
python3 db_maintenance.py --check
```

**Import errors:**
```bash
# Run import with verbose logging
python3 db_import.py --all --verbose
```

**Performance issues:**
```bash
# Update database statistics
python3 db_maintenance.py --analyze

# Vacuum database to reclaim space
python3 db_maintenance.py --vacuum
```

### Recovery Procedures

**Restore from backup:**
```bash
# Stop all SMBSeek tools
# Replace database file with backup
cp db_backups/smbseek_backup_YYYYMMDD_HHMMSS.db smbseek.db

# Verify integrity
python3 db_maintenance.py --check
```

**Rebuild from CSV/JSON files:**
```bash
# Remove corrupted database
rm smbseek.db

# Re-import all data
python3 db_import.py --all --verbose
```

## RCE Status Values

`host_probe_cache.rce_status` now supports five values: `not_run`, `clean`, `flagged`, `unknown`, and `error`.

- `unknown` represents inconclusive probes (INSUFFICIENT_DATA or NOT_ASSESSABLE).
- `error` represents probe/analysis failures; log but do not discard.
- Downstream validators, exports, and UI filters must accept all five values to remain forward compatible.

## Best Practices

1. **Regular Backups** - Enable automatic backups in config.json
2. **Periodic Maintenance** - Run weekly maintenance with --analyze
3. **Monitor Database Size** - Use --info to track growth
4. **Clean Old Data** - Regularly clean up old scan sessions
5. **Index Optimization** - Let ANALYZE update query statistics
6. **Backup Testing** - Periodically verify backup integrity

## Support and Documentation

- **Schema Reference** - See `db_schema.sql` for complete schema
- **API Documentation** - Check `db_manager.py` for all methods
- **Configuration Guide** - Review `config.json` for all options
- **Import Examples** - See `db_import.py --help` for usage

The database migration provides a solid foundation for future SMBSeek enhancements while maintaining compatibility with existing workflows.
