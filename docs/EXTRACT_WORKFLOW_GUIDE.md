# Extract Workflow Guide

This guide describes how SMBSeek’s GUI **Extract** button safely collects files from remote SMB shares, the technical controls behind it, and where the current limits lie.

## Extract in Plain Language
- **Purpose:** give analysts a one-click way to pull a handful of suspicious files without firing up separate tooling.
- **Guardrails:** strict caps on number of files, total bytes, per-file size, directory depth, and runtime—all set by policy or the dialog inputs.
- **Destination:** every download is quarantined under `~/.smbseek/quarantine/<purpose>/<timestamp>` and accompanied by a JSON audit log so nothing sneaks into trusted folders.

## Under the Hood (with proof points)
```
Extract dialog (limits + destination)
        │
        ▼
Settings manager ──→ persists per-user defaults / templates
        │
        ▼
Extract runner thread
        │   (connect via smbclient/impacket with stored creds)
        ▼
Download controller ──→ enforces limits + writes metadata
        │
        ▼
Quarantine writer ──→ stores files + JSON audit log
```

1. **Deterministic limits.** The dialog feeds a `config_override` dict into the runner (max files, bytes, directories, timeout). Every call clamps values to safe minimums so even if the user types “0” or “-5,” the backend refuses to pull unlimited data.
2. **Credential reuse without escalation.** Extract uses the same authenticated host entries already present in the scan database. There’s no credential prompting or storage outside the existing workflow.
3. **Timeout-aware SMB client.** The runner sets per-share timeouts and aborts gracefully if a host stalls. Partial downloads are logged; nothing continues indefinitely.
4. **Immutable quarantine path.** All files land beneath `~/.smbseek/quarantine/...` regardless of user intent. The GUI never writes directly to Desktop/Documents, protecting the rest of the workstation.
5. **Audit-first logging.** For every file successfully copied, the runner records source IP, share name, remote path, size, and timestamp in JSON. That log sits beside the downloaded artifacts for chain-of-custody review.

## Limitations & Risks
- **Read-only intent, but remote ACLs win.** If the SMB account has write/delete rights, the protocol allows those operations. SMBSeek deliberately never calls write/delete APIs, but the credentials themselves may carry risk—keep them least-privileged.
- **Network bandwidth.** Pulling even a handful of files across a congested WAN can spike latency. Adjust the per-file and total-size caps to match your environment.
- **Encrypted / signed SMB sessions.** Extract relies on the same stack as the probe. If your environment mandates SMB signing or encryption, ensure the underlying libraries support it; otherwise downloads will fail even if shares appear accessible.
- **Not a full crawler.** Directory depth and file count limits are enforced to keep extractions surgical. Analysts needing whole-share backups should use dedicated ingest tooling instead.
- **Quarantine hygiene.** Files sit on disk until a human promotes or deletes them. Build operational processes around scanning/cleaning the `~/.smbseek/quarantine` tree.

## Troubleshooting
1. **Permissions errors:** confirm the credential used during scan still has read access; stale passwords are the #1 failure.
2. **Quota exceeded:** check the Extract dialog limits versus the file sizes you’re targeting. Logs will say “max_total_size_mb exceeded” when caps trigger.
3. **Timeouts:** increase “Per-share timeout” in settings if remote links are slow, but keep it bounded to avoid hanging the UI.
4. **Quarantine path unwritable:** ensure the local user owns `~/.smbseek/quarantine`. Recreate it with `mkdir -p ~/.smbseek/quarantine && chmod 700 ~/.smbseek/quarantine` if necessary.

For implementation specifics or to extend the workflow, see the `gui/components/server_list_window/details.py` extract dialog and `gui/utils/extract_runner.py` modules.
