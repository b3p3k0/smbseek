# xsmbseek - GUI Frontend for SMBSeek Security Toolkit

**A cross-platform graphical interface for the SMBSeek security toolkit**

xsmbseek provides a user-friendly GUI frontend that integrates with the SMBSeek security assessment toolkit as an external configurable dependency.

> Built in partnership with human testers plus AI collaborators (Claude & Codex). Claude helped bootstrap the earlier scaffolding; Codex now co-maintains the workflow, UI polish, and documentation—huge thanks to both teams for the pairing magic.

##  Quick Start

### Prerequisites
- Python 3.6+
- tkinter (usually included with Python)
- SMBSeek toolkit (https://github.com/b3p3k0/smbseek)

### Installation

1. **Clone xsmbseek:**
   ```bash
   git clone https://github.com/your-org/xsmbseek.git
   cd xsmbseek
   ```

2. **Install GUI dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install SMBSeek (required external dependency):**
   ```bash
   # Clone SMBSeek as a sibling directory (recommended)
   cd ..
   git clone https://github.com/b3p3k0/smbseek.git
   cd smbseek
   pip install -r requirements.txt
   cp conf/config.json.example conf/config.json
   # Edit conf/config.json and add your Shodan API key
   cd ../xsmbseek
   ```

4. **Run xsmbseek:**
   ```bash
   ./xsmbseek
   ```

   **Note:** If SMBSeek is installed elsewhere, specify the path:
   ```bash
   ./xsmbseek --smbseek-path /path/to/smbseek
   ```

### First Run
xsmbseek will automatically detect SMBSeek in common locations:
1. `./smbseek` (current directory)
2. `../smbseek` (sibling directory - recommended)
3. System PATH

If SMBSeek is not found automatically, xsmbseek will show a setup dialog to help you configure the correct path.

##  Usage

### Basic Commands
```bash
# Launch GUI (shows setup dialog if SMBSeek not found)
./xsmbseek

# Specify custom SMBSeek installation path
./xsmbseek --smbseek-path /path/to/smbseek

# Use custom configuration file
./xsmbseek --config my-config.json

# Development mode with mock data (no SMBSeek required)
./xsmbseek --mock

# Custom database location
./xsmbseek --database-path /path/to/database.db
```

### Configuration Management
xsmbseek uses a dual configuration system:
- **xsmbseek-config.json**: GUI settings, SMBSeek path, database path
- **SMBSeek configuration**: Handled by SMBSeek itself (`smbseek/conf/config.json`)

### Server List Enhancements
- Favorite (★), Avoid (☠), and Probe (🧪) columns sit at the front of the server table. The Probe indicator shows ○ when a host hasn’t been probed yet, △ once a probe snapshot exists with no ransomware hits, and ✖ when returned filenames match indicators defined in `smbseek/conf/config.json` (e.g., `HOW_TO_DECRYPT_FILES.txt` or `README-ID-*.txt`).

### Scan Templates
- Use the **Start New Scan** dialog’s Templates toolbar to save your favorite combinations of search strings, regions, and execution settings.
- Templates live under `~/.smbseek/templates/`; applying one simply repopulates the dialog fields (your underlying SMBSeek config stays untouched).
- We ship six curated presets (Anonymous SMB Shares, Domain Controller Null Sessions, QuickBooks Network Shares, NAS Exposure Sweep, Small Business Media Servers, Legacy SMBv1 Lab Sweep) seeded from `templates/default_scan_templates/` so fresh installs have useful examples immediately.
- These presets were inspired by the excellent [secybr Shodan tutorials](https://secybr.com/posts/shodan-tutorials-for-best-practicies/)—thanks to their team for sharing practical dorks with the community.
- Save as many of your own templates as you like, overwrite them when requirements change, or delete them from the same dropdown without leaving the scan flow. (Note: the “Legacy SMBv1 Lab Sweep” preset assumes your SMBSeek backend is launched with whatever SMB1 support flags your environment requires.)

### Probe Accessible Shares
- Open **Server List → Details** and click the **Probe** button to review probe limits and launch a quick enumeration of each accessible share without downloading files. The probe walks the first 3 directories per share and the first 5 files per directory by default (tweak these in the dialog before starting).
- Results are cached per host under `~/.smbseek/probes/` and rendered as an ASCII tree within the detail view so you can spot interesting data at a glance.
- The probe reuses the anonymous/guest credentials that succeeded during the scan and relies on the [`impacket`](https://github.com/SecureAuthCorp/impacket) library for SMB enumeration—install it in the GUI environment to enable this feature.
- Each probe also runs a lightweight indicator scan. Any filenames that match entries under `security.ransomware_indicators` in the backend config are listed in the detail view (“Indicators Detected”) and flip the probe column to ✖ so compromised hosts remain red across sessions.
- Want the exact patterns we ship (plus their CVE/report references)? See [`docs/RANSOMWARE_INDICATORS.md`](docs/RANSOMWARE_INDICATORS.md).

##  Architecture

### Project Structure
```
xsmbseek/                      # xsmbseek GUI frontend
├── xsmbseek                   # Executable GUI frontend
├── xsmbseek-config.json       # GUI configuration
├── gui/                       # GUI components
│   ├── components/            # Widgets and windows
│   └── utils/                 # GUI utilities
└── docs/                      # Documentation

../smbseek/                    # SMBSeek toolkit (external dependency)
├── smbseek.py                 # SMBSeek main executable
├── conf/                      # SMBSeek configuration
├── shared/                    # SMBSeek core modules
└── tools/                     # SMBSeek legacy tools
```

### Key Features
- **External Dependency Integration**: Treats SMBSeek as configurable external tool
- **Path Flexibility**: User-configurable SMBSeek installation location
- **Dual Configuration**: Separate settings for GUI and security tools
- **Mock Mode**: Development mode without SMBSeek dependency
- **Cross-Platform**: Works on Linux, macOS, and Windows

##  Development

### Testing
```bash
# Run basic functionality tests
python3 simple_test.py

# Test all CLI arguments
./xsmbseek --help
./xsmbseek --version

# Test mock mode (no SMBSeek required)
./xsmbseek --mock
```

### Development Mode
```bash
# Mock mode for GUI development
./xsmbseek --mock --config dev-config.json

# Test with different SMBSeek paths
./xsmbseek --smbseek-path /opt/smbseek --mock
```

##  Human Testing

See [`docs/HUMAN_TESTING_GUIDE.md`](docs/HUMAN_TESTING_GUIDE.md) for comprehensive testing instructions including:
- Brand new user journey
- Configuration management testing
- Error handling and recovery
- Integration testing with SMBSeek

##  Documentation

- **CLAUDE.md**: Development guidance for AI assistants
- **docs/HUMAN_TESTING_GUIDE.md**: Step-by-step testing instructions
- **SMBSeek Documentation**: See the SMBSeek repository for security tool documentation

##  Security

xsmbseek is a frontend for security assessment tools. It maintains the same ethical and security principles as SMBSeek:

- **Defensive Purpose Only**: For authorized security assessment
- **No Offensive Capabilities**: Read-only operations only
- **Rate Limiting**: Prevents aggressive scanning behavior
- **Audit Logging**: Comprehensive operation tracking

##  Contributing

1. Fork the repository
2. Create a feature branch
3. Test thoroughly using the human testing guide
4. Submit a pull request

##  License

This project follows the same license terms as specified in the LICENSE file.

##  Disclaimer

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring their use complies with all applicable laws and regulations.

---

For SMBSeek (the underlying security toolkit), visit: https://github.com/b3p3k0/smbseek
