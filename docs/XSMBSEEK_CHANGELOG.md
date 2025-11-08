# SMBSeek GUI Changelog

All notable changes to the SMBSeek GUI project will be documented in this file.

## [1.2.1] - 2025-11-08

### Added
- **Scan Templates**: Start New Scan dialog now includes a Templates toolbar so you can save/load per-scan parameter sets (search strings, regions, filters, execution tuning) without touching the global SMBSeek config file.
  - Ships with six curated presets (stored under `templates/default_scan_templates/`) seeded from secybr’s public Shodan dork tutorials to showcase real-world use cases on first launch.
- **Server List Probe Column**: The server list now shows a 🧪 status indicator (○ = unprobed, ✔ = probed, ✖ reserved) next to the favorite/avoid columns so analysts can immediately see which hosts have snapshots.
- **Server Detail Probe**: Added a Probe dialog to the Server Details view. It lets analysts adjust limits, enumerate a bounded number of directories/files per accessible share using the original anonymous credentials, caches the result under `~/.smbseek/probes/`, and renders an ASCII tree inside the details view. Requires the `impacket` library.
- **Server Detail Extract**: Introduced an Extract button between Probe and Explore. It reuses the known credentials to download a capped set of files (config-driven allow/deny lists, per-file size, cumulative size, time, and file-count limits) into a timestamped folder, surfaces live “downloading X/Y” status, and writes a JSON audit log under `~/.smbseek/extract_logs/`.
- **Sandbox Shares (Linux)**: When Podman or Docker is available, the Server Details dialog exposes a Sandbox Shares button that runs share enumeration inside a disposable container instead of opening the host file explorer.
- **Probe Indicator Matching**: GUI now loads `security.ransomware_indicators` from the SMBSeek backend config and marks any host whose probe results include those filenames with a ✖ glyph plus a detail-view alert listing the hits.

### Changed
- **Scan Dialog Layout Refresh**: Start New Scan dialog now opens at 1210x825 with a responsive two-column layout that splits targeting controls (search strings, country, regions, filters) on the left and execution controls (rescan, concurrency, rate limits, API key) on the right for greatly reduced scrolling.
- **Button Placement**: Cancel and Start buttons are grouped on the lower-right with shared spacing for a consistent call-to-action row.
- **Input Focus Flow**: Search Strings field now receives initial keyboard focus to match its new prominence at the top of the dialog.
- **Server Detail Layout**: Removed the legacy "Security Assessment" block and now render probe snapshots directly beneath the Share Access section for better readability.
- **Backend Security Defaults**: The GUI now assumes SMBSeek runs in cautious mode and surfaces the new `--legacy` flag warning whenever legacy compatibility is requested.
- **Quarantined Extracts**: Extract operations no longer write directly to the operator-selected folder; files are staged under `~/.smbseek/quarantine/<purpose>/<timestamp>` so they can be reviewed before promotion.

### Fixed
- **Country Input Padding**: Country Code card uses the same horizontal padding as neighboring sections, eliminating the subtle width mismatch reported in UI review.

### Removed
- **Legacy Profile Manager Dialog**: The dashboard Profiles button and its file-based save/load workflow have been retired in favor of in-dialog scan templates.

## [1.2.0] - 2025-09-05

### Changed
- **Dashboard Interface Reorganization**: Complete redesign of main dashboard for compact, efficient layout
  - Removed unused metric cards: "Available Shares", "High Risk Vulnerabilities", "Recent Discoveries"
  - Removed entire country breakdown section for cleaner interface
  - Implemented horizontal layout with "Total Servers" card and expanded "Recent Activity" section
  - Optimized card proportions and button alignment for professional appearance

### Fixed
- **Critical Window Height Issue**: Resolved persistent 750px window height problem that ignored settings
  - Root cause: `update_idletasks()` calls triggered tkinter's automatic content-based window resizing
  - Solution: Replaced with safer `update()` calls and added window size enforcement mechanism
  - Dashboard now correctly maintains intended 350px height for compact layout
  - Added protective callbacks to prevent auto-resizing after UI operations

### Added
- **Window Size Protection**: New enforcement mechanism prevents unwanted window resizing
  - Size enforcement callbacks ensure window dimensions remain as intended
  - Multiple protection layers during data refresh and progress updates
  - Preserves window position while enforcing target dimensions

### Technical
- **Enhanced Progress Updates**: Improved UI update mechanism without geometry recalculation
- **Settings Migration**: Automatic migration of legacy window geometry settings
- **Defensive Programming**: Added error handling for UI destruction scenarios during updates

## [1.0.1] - 2025-08-23

### Removed
- **Top Findings Section**: Removed "TOP FINDINGS" section from main dashboard for cleaner interface
- **Auto-refresh Functionality**: Disabled automatic screen refresh (5-second intervals) to reduce distraction
  - Manual refresh still available via F5 key or explicit user action
  - Eliminates unnecessary network/database polling

### Fixed  
- **Configuration Editor Error**: Fixed tkinter Label parameter conflict causing "multiple values for keyword argument 'fg'" error
  - Root cause: Parameter collision in style.py create_styled_label() method
  - Solution: Use kwargs.pop() to handle fg parameter extraction

### Changed
- **Configuration Editor Interface**: Completely redesigned as simple text editor
  - Replaced complex dual-mode interface with straightforward text editing
  - Added Open, Save, Cancel buttons with clear functionality
  - Save button validates JSON syntax and closes window on success
  - Cancel button prompts for unsaved changes before closing
  - Small font file path display for reference
  - Enhanced user experience with immediate feedback on configuration changes

### Technical
- **Backend Configuration Propagation**: Ensured saved configuration changes automatically apply to subsequent backend operations
- **Error Handling**: Improved JSON validation and user feedback for configuration editing

## [1.1.0] - 2025-08-23

### Added
- **Complete Scan Management System**: Full scan workflow implementation with comprehensive UI
  - Scan configuration dialog with country selection and config editor integration
  - Real-time progress tracking with detailed "scanning host X/Y" status updates
  - Lock file coordination preventing concurrent scans (.scan_lock)
  - Comprehensive scan results dialog with success/failure/interruption handling
  
- **Enhanced Server List Browser**: Advanced date filtering and sorting capabilities
  - Date filters: "Since Last Scan", "Last 24 Hours", "Last 7 Days", "Last 30 Days"
  - Smart date field detection supporting various database schemas
  - Toggle between recent and all results with visual indicators
  - Advanced mode integration with all existing filtering options

- **Comprehensive Error Handling**: Robust error management throughout application
  - Global exception handler for unhandled errors with graceful fallback
  - Context-specific error messages with troubleshooting guidance
  - Safe progress updates with UI destruction protection
  - Fallback mechanisms for critical dialog failures

### Enhanced
- **Backend Interface Progress Parsing**: Significantly improved progress tracking
  - Phase detection for discovery, access testing, collection, and reporting
  - Enhanced regex patterns for detailed progress extraction
  - Smart percentage estimation based on scan phase and keywords
  - Support for "host X/Y" and "share A/B" progress formats

- **Configuration Editor**: Streamlined and improved functionality
  - Fixed tkinter parameter conflicts causing startup errors
  - Better error handling and user feedback
  - Integrated access from scan dialog for seamless workflow

### Fixed
- **Dashboard Improvements**: Removed distracting auto-refresh functionality
  - Eliminated automatic screen refreshes (5-second intervals)
  - Removed "TOP FINDINGS" section for cleaner interface
  - Manual refresh still available via F5 key for user control

- **UI Window Sizing**: Improved default window sizes for better element visibility
  - Main window now defaults to 800x600 (matches minimum size for optimal layout)
  - Configuration editor increased to 800x700 (from 800x600) for proper button panel spacing
  - Conservative sizing approach ensures all UI elements visible by default while maintaining responsiveness

- **Scan Dialog Space Optimization**: Enhanced scan dialog layout for maximum screen real estate efficiency
  - Dialog height optimized to 500x460 (from 500x400) for proper element visibility
  - Reduced padding throughout interface: header (20px→15px), sections (15px→10px), containers (15px→10px)
  - Button panel spacing optimized (20px→15px bottom margin) while maintaining accessibility
  - Hybrid approach combines height increase (+60px) with padding efficiency (~40px saved)
  - Result: ~100px additional usable space ensuring all UI elements are clearly visible

- **Metric Card Click Handler Fix**: Resolved UI error caused by conflicting click zones in dashboard metric cards
  - Removed redundant click handlers from card containers that caused error dialogs when clicked
  - Preserved "View Details" button functionality which opens server list browser correctly
  - Eliminated unwanted clickable areas around buttons that triggered different (broken) dialog paths
  - Clean, predictable user interface with single click target per metric card
  - Industry standard practice: single responsibility for UI click targets

- **Server List Double-Click Fix**: Resolved blank dialog issue and implemented standard file browser UX
  - Fixed double-click on server entries to show identical content as "View Details" button
  - Replaced unreliable selection-dependent logic with direct event-based row identification
  - Implemented standard file browser paradigm: single-click selects row, double-click opens details
  - Added comprehensive error handling with appropriate user feedback messages
  - Ensured visual feedback through explicit row selection during double-click operations
  - Industry standard practice: event-coordinate-based TreeView interaction handling

- **Comprehensive Scan Progress Tracking Overhaul**: Resolved "stuck at Initializing 5%" and implemented robust real-time updates
  - **Root Cause Fixed**: Backend outputs `ℹ 📊 Progress: X/Y (Z%)` with ANSI color codes, not simple patterns
  - **Enhanced Regex Patterns**: Updated patterns to handle ANSI color codes, info prefixes, and additional context
  - **Workflow Step Detection**: Added parsing for `[1/4] Discovery & Authentication` step transitions
  - **Early-Stage Activity**: Immediate feedback for Shodan queries and database loading (within 2-3 seconds)
  - **Progressive Mapping**: Workflow steps mapped to progress ranges (Discovery: 0-25%, Access: 25-60%, etc.)
  - **Unbuffered Output**: Fixed subprocess buffering with `PYTHONUNBUFFERED=1` for real-time updates
  - **Enhanced Patterns**: Added Shodan detection, database loading, authentication results tracking
  - **Fallback Mechanisms**: Time-based progress validation and forward-only percentage guarantee
  - **User Experience**: Activity indicators, phase-specific visual cues, runtime duration tracking
  - **Technical Achievement**: Comprehensive parsing alignment with actual backend output format

### Technical Improvements
- **Scan Manager Architecture**: Centralized scan coordination and management
  - Process detection with graceful fallback (psutil/os.kill)
  - Comprehensive scan state tracking and cleanup
  - Thread-safe progress callback management
  - Detailed scan results collection and metadata

- **Lock File Management**: Proper scan coordination with metadata
  - JSON-based lock files with process ID, timestamps, scan parameters
  - Automatic stale lock cleanup on application startup
  - Process existence validation for lock file integrity

- **Enhanced Documentation**: Updated all documentation to reflect new features
  - Comprehensive changelog with technical details
  - Updated development notes with implementation decisions
  - Clear user guidance for new scan management features

## [1.0.0] - 2025-01-21

### Added
- **Complete GUI Application**: Cross-platform tkinter-based interface for SMBSeek
- **Mission Control Dashboard**: Single-panel view with all critical security metrics
- **Real-time Progress Tracking**: Visual progress bars during scan operations
- **Backend Integration**: Subprocess-based communication with existing SMBSeek CLI
- **Database Browser**: Read-only access to scan results and historical data
- **Mock Mode**: Safe testing environment with realistic data
- **Comprehensive Testing**: 13 unit tests covering all core components
- **Cross-platform Support**: Works on Linux, macOS, and Windows

### Dashboard Features
- **Key Metrics Cards**: Total servers, accessible shares, vulnerabilities, recent discoveries
- **Top Findings Display**: Critical security findings with severity indicators
- **Country Breakdown**: Geographic distribution with visual progress bars
- **Recent Activity Timeline**: Chronological view of scanning activity
- **Auto-refresh**: 5-second interval updates with intelligent caching
- **Drill-down Interface**: Clickable elements for detailed analysis (placeholders)

### Technical Implementation
- **Backend Interface Layer**: Subprocess wrapper with timeout and retry logic
- **Database Access Layer**: Read-only SQLite access with connection pooling
- **Styling System**: Consistent cross-platform theming with accessibility
- **Progress Management**: Thread-safe updates via queue mechanism
- **Error Handling**: Graceful degradation and user-friendly error messages
- **Configuration Management**: Direct JSON file reading and writing

### Documentation
- **Development Notes**: Comprehensive session-by-session development log
- **User Guide**: Complete end-user documentation with examples
- **Architecture Documentation**: Technical design decisions and patterns
- **Setup Automation**: Complete environment setup script

### Testing & Quality
- **Unit Test Suite**: 100% pass rate across all components
- **Mock Data Framework**: Realistic test data for safe development
- **Integration Testing**: Component interaction validation
- **Cross-platform Testing**: Verified on Linux development environment

### Security Features
- **Read-only Database Access**: No interference with backend operations
- **Rate Limiting Awareness**: Respects backend security safeguards
- **Error Isolation**: Backend failures don't crash GUI
- **Mock Mode Security**: Safe testing without real network operations

### Developer Experience
- **Automated Setup**: Single script creates complete development environment
- **Documentation as Code**: Real-time documentation during development
- **Component Architecture**: Modular design for easy extension
- **Dependency Injection**: Clean separation of concerns for testing

## Architecture Decisions

### Mission Control vs Tabs Design
**Decision**: Single-panel dashboard with drill-down windows
**Rationale**: Provides security situation awareness; tabs hide critical information

### Backend Integration Strategy  
**Decision**: Subprocess calls with output parsing
**Rationale**: Complete backend isolation; no code modifications required

### Database Access Pattern
**Decision**: Read-only SQLite access with caching
**Rationale**: Real-time updates without interfering with backend operations

### Mock Mode Implementation
**Decision**: Comprehensive mock data with realistic patterns
**Rationale**: Safe development and testing without real backend dependencies

### Progress Tracking Method
**Decision**: Regex parsing of CLI output with thread-safe queue updates
**Rationale**: Real-time feedback without modifying backend progress reporting

## Known Limitations

### Current Version (1.0.0)
- **Drill-down Windows**: Placeholder implementation (planned for v1.1.0)
- **Scan Configuration**: Basic quick scan only (full config planned for v1.1.0)  
- **Data Export**: Export functionality not yet implemented
- **Advanced Filtering**: Basic country filtering only

### Technical Limitations
- **CLI Dependency**: Requires backend CLI for all scan operations
- **Single Backend**: Cannot connect to multiple backend instances
- **SQLite Only**: No support for other database backends
- **Network Required**: Shodan API access needed for live scanning

## Future Roadmap

### Version 1.1.0 (Planned)
- **Drill-down Windows**: Complete server list and geographic maps
- **Advanced Scanning**: Full scan configuration interface  
- **Enhanced Filtering**: Multi-criteria search and filtering
- **Data Export**: CSV and JSON export functionality

### Version 1.2.0 (Planned)
- **Scheduled Scans**: Automated scanning with cron-like scheduling
- **Alert System**: Notifications for critical vulnerabilities
- **Dashboard Customization**: User-configurable metric cards
- **Data Import/Export**: Backup and restore functionality

### Version 2.0.0 (Future)
- **Multi-backend Support**: Connect to multiple SMBSeek instances
- **Real-time Collaboration**: Shared scanning and analysis
- **Advanced Visualizations**: Network topology and relationship mapping
- **Integration APIs**: REST API for external tool integration

## Development Methodology

This project demonstrates successful human-AI collaboration in GUI development:

- **AI Responsibilities**: Complete technical implementation, architecture decisions, comprehensive documentation
- **Human Responsibilities**: Requirements validation, real-world testing, user experience feedback
- **Documentation-as-Code**: Real-time development logging prevents knowledge loss
- **Iterative Design**: Session-by-session improvements based on testing results

## Contributors

- **AI Developer**: Complete implementation and documentation
- **Human Partner**: Requirements, testing, and validation

---

*For detailed technical implementation notes, see [DEVNOTES.md](DEVNOTES.md)*  
*For user instructions, see [USER_GUIDE.md](USER_GUIDE.md)*
