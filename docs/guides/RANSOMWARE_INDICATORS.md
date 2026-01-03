# Probe Ransomware Indicator Reference

xsmbseek’s probe runner now surfaces “bad” hosts when cached directory listings contain ransom-note filenames that are widely associated with known ransomware families. This page is the public hand‑off for defenders who want to understand **why these patterns matter, how the GUI interprets them, and how to extend the list safely**.

## Why we match ransom-note filenames

* **Scenario**: An analyst runs a lightweight probe against an anonymous SMB share. Even without downloading files, we can see top-level filenames (e.g., `!want_to_cry.txt`). Those names often uniquely identify ransomware incidents that already compromised the host.
* **Goal**: Flag the server as a “lost cause” (✖) so analysts don’t waste time, and capture an audit trail explaining which threat family was observed.
* **Persistence**: Matches are written to `SettingsManager.probe.status_by_ip` and cached under `~/.smbseek/probes/<ip>.json`, so the server list stays red across sessions.

## Using and extending the indicator list

1. Indicators live in the backend config (`smbseek/conf/config.json → security.ransomware_indicators`). Editing that array immediately updates future probe runs—no code changes required.
2. Keep entries short (wildcards `*` and `?` are supported) and document any new additions in this file or internal runbooks.
3. Treat each entry as a high-signal ransom note; avoid generic names like `readme.txt` that will generate noise.
4. If you need to disable matching temporarily, remove the entry from the config and clear cached probes with `xsmbseek --clear-probes`.

## Indicator catalogue

| Indicator pattern | Associated family / behavior | CVE or reference |
| --- | --- | --- |
| `!want_to_cry.txt` | WantToCry/WannaCry clones leave this note (with qTox addresses) after encrypting data with the `.want_to_cry` extension and worm across SMB. | Campaign write-ups describe the note and the EternalBlue CVE-2017-0144 exploit path. citeturn5search0turn5search7turn15search5 |
| `!0XXX_DECRYPTION_README.TXT` | 0XXX/Hunt ransomware renames files to `.0xxx` or `.hunt` and drops this ransom note pointing to email/Tor support. | Detailed IOC lists from Trustwave and Sekoia reproduce the filename. citeturn6search0turn6search1 |
| `HOW_TO_DECRYPT_FILES.txt` | Hive (aka Hunters International) and AROS variants both include this text file alongside HTML notes to guide victims to Tor portals. | Incident reports for both families show the exact filename. citeturn7search1turn7search0 |
| `DECRYPT_INSTRUCTIONS.txt` | Vanguard, Wizard, and Play ransomware strains use this note when appending `.wizard`, `.play`, etc., to corporate assets. | Family-specific advisories display the full text of `DECRYPT_INSTRUCTIONS.txt`. citeturn8search1turn8search4turn8search7 |
| `_DECRYPT_INFO_.html` | Maktub Locker generates `_DECRYPT_INFO_<random>.html` in every folder with instructions to pay via the actor’s Tor site. | Multiple disinfection guides quote the filename and HTML structure. citeturn9search0turn9search1 |
| `README_FOR_DECRYPT.txt` | NAS-focused crews like Muhstik/eCh0raix drop this file together with `.ech0raix`/`.muhstik` extensions. | CERT advisories for eCh0raix show the ransom note content. citeturn10search8turn10search2 |
| `README-ID-*.txt` | Whole/Keylock ransomware families generate per-victim `README-ID-<id>.txt` files and threaten leak sites. | Responders captured wallpaper + README-ID samples in the wild. citeturn11search1 |
| `README_*.txt` | Keylock variants also use `README_<hostname>.txt` when an ID is unavailable; the content mirrors the README-ID note. | Same forensic reports show both naming schemes. citeturn11search2 |
| `Readme.*.txt` | LOLKEK/READYMIX ransomware (a STOP/Djvu branch) distributes `ReadMe.txt`/`ReadMe!.txt` files that direct victims to qTox. | Threat-hunting threads document the filenames and instructions. citeturn0reddit10 |
| `+readme-warning+.txt` | STOP/Djvu family consistently uses `+readme-warning+.txt` for ransom instructions across hundreds of extensions. | ID-Ransomware submissions and removal guides cite the exact note. citeturn13search1turn13search2 |
| `cAcTuS.readme.txt` | CACTUS double-extortion operators name their binary and note after a cactus motif, often following VPN appliance breaches. | Research blogs reproduce the `cAcTuS.readme.txt` file and intrusion vector (e.g., CVE-2023-38035). citeturn14search0turn14search6 |
| `RESTORE_FILES.txt` | Azov/Protected wipers (masquerading as ransomware) leave `RESTORE_FILES.txt` before corrupting every file. | TrustedSec and community IR write-ups include the filename and wiper behavior. citeturn0search0turn0search6 |
| `HELP_DECRYPT.*` | CryptoWall 3.0, CrypBoss, and derivative families spawn `HELP_DECRYPT.TXT/.PNG/.HTML` guides with Bitcoin wallet steps. | Multiple reverse-engineering reports show the trio of files. citeturn1search0turn1search6 |
| `RECOVER-FILES.txt` | 3AM and Egregor enterprise crews drop `RECOVER-FILES.txt` with Tor links immediately after halting services. | IOC repositories for both families show the ransom note name. citeturn2search1turn2search7 |
| `HOW TO RECOVER YOUR FILES.txt` | Noname/Demon ransomware leaks use this plain-English filename to demand Bitcoin from Windows domains. | RansomLook listings and removal guides reproduce the text. citeturn3search1turn3search2 |
| `RETURN FILES.txt` | Dharma/Crysis “Harma” variants append `.harma` and create `RETURN FILES.txt` instructions with multiple contact emails. | Malware removal advisories capture the filename and contact flow. citeturn3search8 |
| `Restore-My-Files.txt` | DOCM/BlackBit ransomware families append `.docm`/`.blackbit` and leave `Restore-My-Files.txt` pointing to ICQ/email. | DFIR blogs show the filename across recent docm/blackbit campaigns. citeturn2search0turn2search2 |
| `HOW_TO_DECYPHER_FILES.txt` | RASTAR/Thanos/ENERGY builders reuse this filename (with Telegram handles) when encrypting Windows fleets. | Reverse-engineering notes trace the shared template. citeturn12search0turn12search1 |
| `UNLOCK_FILES_INFO.txt` | Prometheus/BlackMatter-like operations sometimes use `UNLOCK_FILES_INFO.txt` (with `.unlock_files_info.txt` variations) to demand Monero. | Bike-shed DFIR posts capture the note and negotiation process. citeturn12search7 |
| `RESTORE_FILES.txt` | Azov (“Protected”) destructive ransomware writes `RESTORE_FILES.txt` in every directory before corrupting data. | TrustedSec and Spiceworks incident reports document the filename and double-extortion lures. citeturn0search0turn0search1 |
| `HELP_DECRYPT.*` | CryptoWall 3.0, CrypBoss, and similar families drop `HELP_DECRYPT` notes as `.txt/.png/.html` to direct victims to Tor portals. | Variant analyses list `HELP_DECRYPT.TXT/PNG/HTML` across multiple campaigns. citeturn0search2turn0search6 |
| `RECOVER-FILES.txt` | Egregor, 3AM, and other enterprise crews leave `RECOVER-FILES.txt` (sometimes with instructions to write via email or Tor). | Group-IB’s Egregor write-up and 3AM case studies mention the exact filename. citeturn1search2turn1search1 |
| `HOW TO RECOVER YOUR FILES.txt` | Noname/Demon ransomware shares use this plain-English title when demanding Bitcoin after encrypting corporate data. | Recent analyses of Noname/Demon leaks show `HOW TO RECOVER YOUR FILES.txt` on infected systems. citeturn1search3turn1search4 |
| `RETURN FILES.txt` | Dharma/Crysis derivatives tag each folder with `RETURN FILES.txt` containing contact emails and payment steps. | Incident responders note the Dharma variant’s `.RETURN FILES.txt` ransom notes. citeturn1search5 |
| `Restore-My-Files.txt` | Docm/Docl ransomware families append `.docm` and drop `Restore-My-Files.txt` giving ICQ/email addresses for negotiation. | Samples captured in 2023 show `Restore-My-Files.txt` plus `.docl` extensions. citeturn1search6 |

### Reading the table

* **Indicator pattern**: Exact string or wildcard we search for in probe output.
* **Associated family**: The best-known ransomware family that drops the file. Not exclusive—copycats reuse notes.
* **CVE/reference**: Either a documented CVE exploited by that family or a public report confirming the filename. If no CVE is listed, the reference explains the behavior.

## Analyst workflow tips

1. **Before triage**: Run probes against suspicious SMB hosts. If a ✖ appears, open the Server Details dialog to review the “Indicators Detected” block and record the evidence in your case notes.
2. **Remediation guidance**: Hosts already showing these ransom notes should be isolated and reimaged; the presence of the note implies a prior compromise, not just exposure.
3. **Updating indicators**: When you encounter a new ransom note filename:
   * Validate it (screenshot/log from the affected share).
   * Add it to `security.ransomware_indicators`, keeping the naming concise.
   * Submit a short PR updating this doc with the family name and public reference (CVE or article).

By keeping this list curated and cited, we help downstream defenders understand *why* xsmbseek paints a host red instead of treating it as a false positive.
