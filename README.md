# SMBSeek - GUI-first SMB security toolkit

**A defensive, Tkinter-based GUI for identifying SMB servers with weak authentication and demonstrating impact safely.**

[![Version](https://img.shields.io/badge/version-3.0.0-blue.svg)](https://github.com/b3p3k0/smbseek)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## TL;DR (GUI)
```bash
python3 -m venv venv
source venv/bin/activate         # venv\Scripts\activate on Windows
pip install -r requirements.txt
cp conf/config.json.example conf/config.json
./xsmbseek                        # launch the GUI
```
- Needs `python3-tk` and `smbclient` on your system; install via your package manager.
- For wordlists, grab SecLists (e.g., rockyou.txt) and point `pry.wordlist_path` to it.

## What you can do in the GUI
- **Dashboard:** Start scans, open the Server List, edit config, and view About/links.
- **Server List:** Probe hosts, read-only Browse, guarded Extract, and **Pry** weak passwords.
- **Denied Shares visibility:** Accessible/Denied share counts and lists to prioritize Pry.
- **Pry (single host/share/user):** Username + wordlist, optional username-as-password, lockout-safe defaults, progress updates.
- **Browse (read-only):** Navigate shares and download a single file into quarantine.
- **Extract (guarded):** Bounded file collection with size/time/file-count limits and quarantine.

## Safety & intent
SMBSeek is for authorized defensive assessments only. No warranty expressed or implied—use at your own risk. Cautious defaults (signing/SMB2+) are on; change `--legacy`/config only when you must talk to SMB1/unsigned targets.

## Install prerequisites
- Python 3.8+ (3.10+ recommended)
- System packages: `python3-tk` (Tk bindings), `smbclient` (share tests), plus `python3-venv`/`python3-pip`.
- Impacket and other deps are pulled via `pip install -r requirements.txt`.

## Run the GUI
```bash
./xsmbseek [--config path/to/conf/config.json]
```
Settings are read from `conf/config.json`; the GUI Config button opens the editor for common options.

### Key config knobs (GUI-relevant)
- `pry.wordlist_path`: default wordlist path (e.g., `conf/wordlists/rockyou.txt` from SecLists).
- `pry.user_as_pass`, `pry.stop_on_lockout`, `pry.attempt_delay`, `pry.max_attempts`.
- File browser/extract limits live under `file_browser` and `file_collection` sections.

## Wordlists
- Recommended: SecLists — https://github.com/danielmiessler/SecLists
- Place a list locally and set `pry.wordlist_path` (GUI will prefill if the file exists).

## Backend/CLI (short)
The original CLI scan tools still exist for automation:
```bash
./smbseek --country US       # discover + access test
./smbseek --verbose
```
See `docs/operations/` for CLI options. The GUI auto-runs DB migrations on startup.

## Troubleshooting (GUI-focused)
- `ModuleNotFoundError: tkinter`: install `python3-tk` / `python3-tkinter`.
- `smbclient: command not found`: install `smbclient`/`samba-client`.
- Pry timeouts: increase `pry.attempt_delay` or `connection.share_access_delay` in config.
- Missing wordlist: download from SecLists and update `pry.wordlist_path`.

## Credits
- Pry logic inspired by mmcbrute (BSD-3-Clause). See `licenses/mmcbrute-BSD-3-Clause.txt`.
- Wordlists: SecLists (MIT). See `licenses/seclists-MIT.txt`.

## License
MIT (see LICENSE). Third-party licenses in `licenses/`.
