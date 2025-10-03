# SMBSeek 3.0 Migration Guide

**Breaking changes and migration path from SMBSeek 2.x to 3.0**

---

## Overview

SMBSeek 3.0 introduces a streamlined single-command interface that significantly simplifies the user experience while maintaining all core functionality. This guide helps users migrate from the multi-subcommand interface to the new unified workflow.

## Quick Migration Reference

### Primary Workflow Changes

| SMBSeek 2.x (Old) | SMBSeek 3.0 (New) |
|-------------------|-------------------|
| `./smbseek.py run --country US` | `./smbseek.py --country US` |
| `./smbseek.py run --verbose` | `./smbseek.py --verbose` |
| `./smbseek.py run --quiet` | `./smbseek.py --quiet` |

### Database Operations

| SMBSeek 2.x (Old) | SMBSeek 3.0 (New) |
|-------------------|-------------------|
| `./smbseek.py db query --summary` | `python tools/db_query.py --summary` |
| `./smbseek.py db backup` | `python tools/db_maintenance.py --backup` |
| `./smbseek.py db import --csv file.csv` | `python tools/db_import.py --csv file.csv` |

### Removed Features

| SMBSeek 2.x (Old) | SMBSeek 3.0 (Status) |
|-------------------|---------------------|
| `./smbseek.py collect` | ⚠️ **REMOVED** - File collection discontinued |
| `./smbseek.py report` | ⚠️ **REMOVED** - Use database tools directly |
| `./smbseek.py analyze` | ⚠️ **REMOVED** - Functionality integrated into main workflow |

---

## Detailed Migration Steps

### 1. Update Your Scripts

**Before (SMBSeek 2.x):**
```bash
#!/bin/bash
# Old scanning script
./smbseek.py run --country US --verbose
./smbseek.py db query --summary
./smbseek.py db backup
```

**After (SMBSeek 3.0):**
```bash
#!/bin/bash
# New scanning script
./smbseek.py --country US --verbose
python tools/db_query.py --summary
python tools/db_maintenance.py --backup
```

### 2. Update Configuration Files

**No changes required** - `conf/config.json` format remains identical.

### 3. Database Schema

**No migration required** - Database schema is fully backward compatible.

### 4. Cron Jobs and Automation

**Before:**
```bash
# /etc/crontab entry
0 2 * * * cd /path/to/smbseek && ./smbseek.py run --country US --quiet
```

**After:**
```bash
# /etc/crontab entry
0 2 * * * cd /path/to/smbseek && ./smbseek.py --country US --quiet
```

---

## Backward Compatibility

### Deprecated Commands (Still Functional)

SMBSeek 3.0 provides backward compatibility with deprecation warnings:

```bash
# These commands still work but show warnings:
./smbseek.py run --country US          # ⚠️ Shows deprecation warning
./smbseek.py discover --country US     # ⚠️ Shows deprecation warning
./smbseek.py access                    # ⚠️ Shows deprecation warning

# Guidance message displayed:
# "⚠️ DEPRECATED: Use './smbseek.py --country US' for the unified workflow"
```

### Grace Period

- **Current version (3.0.x)**: Deprecated commands work with warnings
- **Future version (4.0.x)**: Deprecated commands will be removed
- **Migration window**: 12+ months from SMBSeek 3.0.0 release

---

## New Features in SMBSeek 3.0

### 1. Simplified Interface

- **Single command**: `./smbseek.py --country US` performs complete discovery + share enumeration
- **Automatic workflow**: No need to manually chain discover → access commands
- **Session management**: Unified session tracking across operations

### 2. Enhanced Database Tools

- **Standalone tools**: Database operations moved to dedicated `tools/` scripts
- **Better performance**: Direct database access without CLI overhead
- **Programmatic access**: Easier integration with external tools

### 3. Improved Output

- **Roll-up summaries**: Consolidated results at the end of each scan
- **Better progress tracking**: Real-time updates during long operations
- **Consistent formatting**: Standardized output across all operations

---

## Migration Checklist

### For End Users

- [ ] Update command line invocations (remove `run` subcommand)
- [ ] Update any scripts or aliases
- [ ] Update cron jobs and automation
- [ ] Test new interface with `./smbseek.py --help`
- [ ] Verify database operations with `python tools/db_query.py --summary`

### For Developers

- [ ] Update integration scripts
- [ ] Modify any API calls to use operation classes directly
- [ ] Update documentation and examples
- [ ] Test backward compatibility if needed
- [ ] Plan migration away from deprecated subcommands

### For System Administrators

- [ ] Update deployment scripts
- [ ] Modify monitoring and alerting rules
- [ ] Update backup procedures (no changes needed)
- [ ] Train users on new interface
- [ ] Plan deprecation timeline for automated systems

---

## Troubleshooting

### Common Migration Issues

**Issue**: `./smbseek.py run --country US` still works but shows warnings
**Solution**: Update to `./smbseek.py --country US` to remove warnings

**Issue**: Database commands not found
**Solution**: Use `python tools/db_query.py` instead of `./smbseek.py db`

**Issue**: File collection functionality missing
**Solution**: File collection was intentionally removed. Use third-party tools on enumerated shares if needed.

**Issue**: Reporting functionality missing
**Solution**: Query the database directly using `python tools/db_query.py` or standard SQL tools

### Getting Help

```bash
# General help
./smbseek.py --help

# Database tools help
python tools/db_query.py --help
python tools/db_maintenance.py --help

# Check version
./smbseek.py --version
```

---

## Benefits of Migration

### For Users

- **Simpler commands**: Fewer subcommands to remember
- **Faster workflow**: Automatic operation chaining
- **Better feedback**: Improved progress reporting
- **Consistent interface**: Standardized argument patterns

### For Developers

- **Cleaner architecture**: Modular backend with unified frontend
- **Better testing**: Simplified command surface area
- **Easier integration**: Direct access to operation classes
- **Future-proof**: Foundation for additional features

### For Organizations

- **Reduced training**: Simpler interface for new users
- **Better automation**: More reliable command patterns
- **Consistent results**: Unified session management
- **Lower maintenance**: Fewer moving parts

---

## Support and Resources

### Documentation

- [README.md](../README.md) - Updated for SMBSeek 3.0
- [USER_GUIDE.md](USER_GUIDE.md) - Complete user documentation
- [DEVNOTES.md](DEVNOTES.md) - Developer reference

### Getting Help

- Check `./smbseek.py --help` for latest syntax
- Review database operations with `python tools/db_query.py --help`
- Test compatibility with `python test_cli_flags.py`

### Rollback Procedure

If needed, you can temporarily rollback by:

1. Using deprecated commands with warnings: `./smbseek.py run --country US`
2. These will continue to work until SMBSeek 4.0
3. Plan migration during the 12+ month compatibility window

---

## Migration Timeline

- **SMBSeek 3.0.0**: New interface available, old interface deprecated
- **SMBSeek 3.1.x**: Bug fixes and improvements to new interface
- **SMBSeek 3.x**: Ongoing support for deprecated commands with warnings
- **SMBSeek 4.0.0**: Deprecated commands removed (12+ months from 3.0.0)

**Recommendation**: Migrate to the new interface immediately to take advantage of improvements and avoid future compatibility issues.