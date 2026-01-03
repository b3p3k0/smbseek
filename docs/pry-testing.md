# Pry Manual Testing Runbook

Purpose: verify the Pry weak-password audit MVP in the xSMBSeek GUI.

## Prerequisites
- `impacket` installed (`pip install -r requirements.txt`).
- xSMBSeek running with access to at least one SMB target you are authorized to test.
- A plaintext wordlist (no `.gz`), readable on disk. Download one (e.g., `rockyou.txt`) from https://github.com/danielmiessler/SecLists and place it where you like (default path `conf/wordlists/rockyou.txt` if you want the dialog prefilled).

## Steps
1. Launch `./xsmbseek` and open the Server List.
2. Select exactly one host in the table.
3. Click **🔓 Pry Selected** (or use the row context menu item).
4. In the Pry dialog:
   - Enter the username (DOMAIN\\user allowed).
   - Choose the wordlist file via **Browse…**.
   - Leave “Try username as password” and “Stop on account lockout” checked (defaults).
   - Optionally adjust delay (default 1.0s) and max attempts (0 = unlimited).
5. Click **Start**.
6. Observe status text updates like `Pry 10.0.0.45: tried 25/500 passwords…`.
7. Wait for completion or click **⏹ Stop Batch** to cancel.

## Expected outcomes
- **Valid password found:** Batch summary line shows `user X authenticated with '<password>'`. No credential is stored elsewhere.
- **No password matches:** Summary shows `user X not authenticated with provided wordlist`.
- **Lockout detected:** Summary shows `Stopped due to account lockout after N attempts`; status marked failed.
- **Cancelled:** Summary shows `Cancelled after N attempts`.
- **Connection error:** Summary notes the failure (e.g., `Connection failed: <reason>`).

## Negative/edge checks
- Empty username or missing wordlist: Pry dialog blocks start with a friendly error.
- `.gz` wordlist path: Dialog blocks start (“gzip wordlists are not supported yet—please decompress first”).
- Huge wordlists: UI should remain responsive; progress updates every ~25 attempts or ~1s.

## Cleanup/notes
- Delay between attempts defaults to 1.0s (configurable via `pry.attempt_delay`).
- Max attempts default is 0 (no cap).
- No passwords are persisted to disk or database in MVP.
