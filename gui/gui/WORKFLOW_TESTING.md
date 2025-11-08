# SMBSeek GUI - Data Exchange Workflow Testing Guide

This document outlines comprehensive testing procedures for the SMBSeek GUI data exchange workflow to ensure team collaboration features work correctly.

## Test Environment Setup

### Prerequisites
- SMBSeek backend installed and functional
- GUI environment set up with mock data
- Two separate GUI instances or shared test files

### Test Data Preparation
```bash
# Setup test environment with mock data
cd /path/to/xsmbseek
./setup_gui_dev_env.sh

# Run GUI in mock mode for controlled testing
cd gui
python main.py --mock
```

## Export Workflow Testing

### Test 1: Server List Export (CSV)
1. **Start GUI** in mock mode: `python main.py --mock`
2. **Open Server List** - Click "Servers Found" card on dashboard
3. **Apply Filters** - Select specific country and auth method
4. **Export CSV**:
   - Click "📊 Export All" button
   - Choose "Export All as CSV" from menu
   - Save to test location
5. **Verify CSV Contents**:
   - Open in spreadsheet application
   - Verify headers match expected field set
   - Check data integrity and formatting
   - Confirm metadata comments at top

### Test 2: Vulnerability Report Export (JSON)
1. **Open Vulnerability Report** - Click "Critical Vulnerabilities" card
2. **Filter by Severity** - Set filter to "Critical" only  
3. **Export JSON**:
   - Click "📊 Export" button
   - Choose "Export Filtered as JSON"
   - Save to test location
4. **Verify JSON Structure**:
   - Validate JSON syntax
   - Check for metadata section
   - Verify data array structure
   - Confirm export timestamp and filters applied

### Test 3: Multi-Format Export (ZIP)
1. **Open Server List** window
2. **Select Subset** - Choose specific servers using Ctrl+click
3. **Export ZIP**:
   - Click "📤 Export Selected" button
   - Choose "Export Selected as ZIP (CSV+JSON)"
   - Save to test location
4. **Verify ZIP Contents**:
   - Extract archive
   - Confirm presence of CSV, JSON, and metadata files
   - Validate each file's content independently

## Import Workflow Testing

### Test 4: CSV Import with Merge Mode
1. **Create New GUI Instance** or clear existing data
2. **Open Import Dialog** - Press Ctrl+I
3. **Import Process**:
   - Select CSV file from Test 1
   - Choose data type "servers"
   - Set import mode to "merge"
   - Preview data to verify structure
   - Confirm import operation
4. **Verify Results**:
   - Check Server List window shows imported data
   - Verify record counts match export
   - Test filtering still works correctly

### Test 5: JSON Import with Replace Mode
1. **Import JSON** from Test 2:
   - Select JSON file
   - Choose "vulnerabilities" data type
   - Set import mode to "replace"
   - Preview and import
2. **Verify Replacement**:
   - Check that all existing vulnerabilities were replaced
   - Confirm only filtered data from export is present
   - Validate vulnerability details are complete

### Test 6: ZIP Import with Validation
1. **Test Validation**:
   - Select ZIP file from Test 3
   - Choose "servers" data type
   - Preview data before importing
   - Verify validation passes for all records
2. **Import with Conflict Resolution**:
   - Set mode to "append" to test duplicate handling
   - Import and verify skipped records are reported
   - Check statistics in completion dialog

## Cross-Format Compatibility Testing

### Test 7: CSV → JSON → CSV Round-Trip
1. Export server data as CSV
2. Import the CSV file
3. Export the same data as JSON  
4. Import the JSON file (replace mode)
5. Export again as CSV
6. **Verify**: Original and final CSV files contain identical data

### Test 8: Mixed Data Type Import
1. **Export Multiple Data Types**:
   - Export servers as CSV
   - Export vulnerabilities as JSON
   - Export shares as ZIP
2. **Import All**:
   - Import each file type separately
   - Verify data appears in correct windows
   - Check cross-references (vulnerabilities link to servers)

## Error Handling Testing

### Test 9: Invalid File Format Testing
1. **Test Unsupported Formats**:
   - Try importing .txt, .xlsx, .pdf files
   - Verify appropriate error messages
   - Ensure application remains stable
2. **Test Corrupted Files**:
   - Create malformed CSV (missing headers, wrong delimiters)
   - Test invalid JSON syntax
   - Verify validation catches errors before import

### Test 10: Large Dataset Performance
1. **Create Large Export** (if possible, or simulate):
   - Export maximum available data
   - Test export progress dialog functionality
   - Verify export completes without memory issues
2. **Test Large Import**:
   - Import the large dataset
   - Verify progress dialog shows incremental updates
   - Check import statistics accuracy

## Interface Mode Testing

### Test 11: Simple/Advanced Mode Export Consistency
1. **Test in Simple Mode**:
   - Export server list in simple mode
   - Note which fields are included
2. **Test in Advanced Mode**:
   - Switch to advanced mode (F1)
   - Export same server list
   - Verify advanced mode includes additional fields
3. **Import Compatibility**:
   - Import both exports into fresh instances
   - Verify both work correctly regardless of export mode

### Test 12: Settings Persistence
1. **Configure Preferences**:
   - Set default export location
   - Set preferred import mode
   - Change interface mode
2. **Restart Application**:
   - Close and reopen GUI
   - Verify settings persist across sessions
   - Test that preferences are applied to new operations

## Team Collaboration Workflow Testing

### Test 13: Multi-User Scenario Simulation
1. **User A Actions**:
   - Run comprehensive scan (or use mock data)
   - Apply filters for specific region
   - Export findings as ZIP
2. **User B Actions** (simulate by using different folder):
   - Import User A's ZIP file
   - Add additional filters
   - Export subset as CSV for reporting
3. **User C Actions**:
   - Import both User A's ZIP and User B's CSV
   - Merge data and export comprehensive report
4. **Verify**: All data remains consistent across transfers

### Test 14: Email Attachment Workflow
1. **Export Small Dataset** as ZIP
2. **Email Simulation**:
   - Compress file further if needed for email limits
   - Copy to different location (simulate email download)
3. **Import from "Email"**:
   - Import the copied file
   - Verify no data corruption occurred
   - Check all metadata preserved

## Integration Testing

### Test 15: Backend Integration (if available)
1. **Real Backend Test**:
   - Run GUI with real backend: `python main.py`
   - Perform actual scan if possible
   - Export real scan results
   - Import results into fresh instance
   - Verify data integrity throughout

### Test 16: Cross-Platform Testing (if possible)
1. **Export on Platform A** (Windows/Linux/macOS)
2. **Import on Platform B** (different OS)
3. **Verify**:
   - File format compatibility
   - Character encoding preserved
   - Date/time formats handled correctly

## Regression Testing Checklist

### After Code Changes, Verify:
- [ ] All export formats (CSV, JSON, ZIP) work correctly
- [ ] Import validation catches common errors
- [ ] Progress dialogs show during long operations
- [ ] Settings persistence works across restarts
- [ ] Keyboard shortcuts (Ctrl+I, F1) function properly
- [ ] Simple/Advanced mode toggle affects exports appropriately
- [ ] Error messages are user-friendly and helpful
- [ ] Export/import statistics are accurate
- [ ] File size estimates are reasonable

## Performance Benchmarks

### Acceptable Performance Targets:
- **Export 1000 servers**: < 5 seconds
- **Import 1000 servers**: < 10 seconds
- **ZIP creation**: < 3 seconds additional overhead
- **Data validation**: < 2 seconds for typical datasets
- **UI responsiveness**: No blocking during operations (progress dialogs used)

## Documentation Verification

### Verify Documentation Accuracy:
- [ ] README.md export field sets match actual exports
- [ ] Keyboard shortcuts listed match implementation
- [ ] Troubleshooting steps resolve common issues
- [ ] Architecture documentation reflects current code structure

---

## Test Result Template

```
Test ID: [Test Number]
Test Name: [Test Description]
Date: [YYYY-MM-DD]
Tester: [Name]
Environment: [OS, Python version, GUI mode]

Steps Executed:
1. [Step 1]
2. [Step 2]
...

Expected Result:
[What should happen]

Actual Result:  
[What actually happened]

Status: [PASS/FAIL/BLOCKED]
Issues Found: [None/List issues]
Notes: [Additional observations]
```

This comprehensive testing guide ensures the data exchange workflow functions correctly across all supported scenarios and provides a framework for ongoing quality assurance.