# SMBSeek GUI

Cross-platform graphical interface for the SMBSeek security toolkit.

## Quick Start

```bash
# Setup development environment
./setup_gui_dev_env.sh

# Activate environment
source gui_env/bin/activate

# Run the GUI
python main.py
```

## Features

- **Mission Control Dashboard** - All critical information in one view
- **One-Click Scanning** - Simplified workflow execution
- **Database Browser** - Explore scan results with filtering and export
- **Configuration Editor** - GUI-based settings management
- **Real-time Progress** - Visual feedback during scans

## Documentation

- [User Guide](docs/USER_GUIDE.md) - End-user documentation
- [Development Notes](docs/DEVNOTES.md) - Architecture and development log
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## Requirements

- Python 3.8+
- tkinter (usually included with Python)
- SMBSeek backend (in ../backend/)

See [requirements-gui.txt](requirements-gui.txt) for complete dependencies.

## License

Same license as SMBSeek backend project.
