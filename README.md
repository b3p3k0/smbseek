# SMBSeek

A GUI for finding SMB servers with weak or no authentication, then auditing what's exposed.

---

## Setup

You'll need Python 3.8+ (3.10+ recommended), Tkinter, and smbclient:

```bash
# Ubuntu/Debian
sudo apt install python3-tk smbclient python3-venv

# Fedora/RHEL
sudo dnf install python3-tkinter samba-client python3-virtualenv

# Arch
sudo pacman -S tk smbclient python-virtualenv
```

Then:

```bash
git clone https://github.com/b3p3k0/smbseek
cd smbseek
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp conf/config.json.example conf/config.json
```

Edit `conf/config.json` and add your Shodan API key (requires paid membership):

```json
{
  "shodan": {
    "api_key": "your_key_here"
  }
}
```

Launch the GUI:

```bash
./xsmbseek
```

---

## Using xSMBSeek

### Dashboard

The main window. From here you can:
- Launch discovery scans (filtered by country or global)
- Open the Server List to work with hosts you've found
- Edit configuration

### Server List

 Shows discovered SMB hosts with IP, country, auth method, and share counts as well as status indicators and a favorite/avoid list.

**Operations** (right-click a host or bottom row buttons):
- **Probe** — enumerate shares, detect ransomware indicators
- **Browse** — read-only exploration of accessible shares
- **Extract** — collect files with hard limits on count, size, and time
- **Pry** — password audit against a specific user

Select multiple hosts for batch probing.

### Browsing Shares

Read-only navigation through SMB shares. Double-click directories to descend, files to preview. You can also select a file and click **View**.

The viewer auto-detects binary files and switches to hex mode. Text files get an encoding selector (UTF-8, Latin-1, etc.) if the default doesn't look right.

Files over the specified maximum (default: 5 MB) trigger a warning—you can bump that limit in `conf/config.json` under `file_browser.viewer.max_view_size_mb`, or click "Ignore Once" to load anyway (hard cap: 1 GB).

Downloads land in quarantine (`~/.smbseek/quarantine/`). The browser never writes to remote systems.

**Faster downloads:** Folder selections now stream enumeration and downloads concurrently, and per-file progress updates while bytes are flowing. Large downloads start immediately instead of waiting for full folder expansion.

### Extracting Files

Automated file collection with configurable limits:
- Max files per target
- Max total size
- Max runtime
- Max directory depth

All extracted files land in quarantine. The defaults are conservative — check `conf/config.json` if you need to adjust them.

### Pry (Password Audit)

Tests passwords from a wordlist against a single host/share/user. Optionally tries username-as-password first.

To use it, download a wordlist (we recommend [SecLists](https://github.com/danielmiessler/SecLists)) and set the path in config:

```json
{
  "pry": {
    "wordlist_path": "/path/to/SecLists/Passwords/Leaked-Databases/rockyou.txt"
  }
}
```

Pry includes lockout detection and configurable delays between attempts. That said, this feature exists mostly as a novelty/proof of concept — dedicated tools like Hydra or CrackMapExec will serve you better for serious password auditing.

---

## Configuration

App settings are stored in `conf/config.json`. The example file (`conf/config.json.example`) documents every option.

Key sections:
- `shodan.api_key` — required for discovery
- `pry.*` — wordlist path, delays, lockout behavior
- `file_collection.*` — extraction limits
- `file_browser.*` — browse mode limits
- `connection.*` — timeouts and rate limiting

Two additional files hold editable lists:

- `conf/exclusion_list.json` — Organizations to skip during Shodan queries (hosting providers, ISPs you don't care about etc.). Add entries to the `organizations` array.
- `conf/ransomware_indicators.json` — Filename patterns checked during probe. Matches flag a server as likely compromised.

These are separate so you can customize or share them without touching app settings.

The GUI includes a built-in config editor for common settings.

---

## Troubleshooting

**GUI won't start — `ModuleNotFoundError: tkinter`**

Install the Tkinter package for your distro (see Setup above).

**GUI displays wrong or crashes in a VM**

Install xvfb and run with a virtual display:

```bash
sudo apt install xvfb
xvfb-run -a ./xsmbseek
```

**Pry says wordlist not found**

Download SecLists and update `pry.wordlist_path` in your config to point at an actual file.

**Database locked**

Another SMBSeek process is probably running. Kill it:

```bash
ps aux | grep smbseek
kill <PID>
```

---

## Advanced

### Templates

**Scan templates** save your search configuration — country filters, Shodan limits, concurrency, rate limits. Click "Save Current" in the scan dialog. Templates live in `~/.smbseek/templates/` as JSON files you can edit directly.

**Filter templates** save your server list filters — search text, date range, countries, checkboxes. Click "Save Filters" in the advanced filter panel. Stored in `~/.smbseek/filter_templates/`.

Both auto-restore your last-used template on startup.

### CLI Usage

The CLI is useful for scripting and automation. The GUI uses the same backend.

```bash
./smbseek --country US              # Discover US servers
./smbseek --country US,GB,CA        # Multiple countries
./smbseek --string "SIPR files"     # Search by keyword
./smbseek --verbose                 # Detailed output
```

Results persist to `smbseek.db` (SQLite). For full CLI documentation, see [docs/guides/USER_GUIDE.md](docs/guides/USER_GUIDE.md).

---

## Legal

This tool is for authorized security assessments only. Scan networks you own or have written permission to test. Unauthorized access to computer systems is illegal in most places.


---

## Acknowledgements

**Pry password logic** derived from [mmcbrute](https://github.com/giMini/mmcbrute) (BSD-3-Clause)

**Wordlists** from [SecLists](https://github.com/danielmiessler/SecLists) (MIT)

Licensed under MIT. See `LICENSE` and `licenses/` for details.
