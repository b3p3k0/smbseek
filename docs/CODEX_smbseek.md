# CODEX Addendum – smbseek

Project-specific guidance for Codex when collaborating on the smbseek backend. Read this alongside `CODEX.md` at the start of each session.

## Project Snapshot
- Unified CLI lives in `smbseek.py`; it feeds parsed args into `workflow.UnifiedWorkflow`, which sequences `DiscoverOperation` then `AccessOperation`.
- Discovery pulls Shodan results, filters via `SMBSeekWorkflowDatabase`, and authenticates with `smbprotocol` while enforcing three-step credential tests.
- Share verification leans on `smbclient` for enumeration and access checks, persisting findings and statistics through the SQLite DAL (`tools/db_manager.py`).
- Configuration, output styling, and database plumbing are centralized in `shared/`; keep their interfaces stable for the legacy scripts and tools that still import them.
- Legacy subcommands remain as warning stubs—tests assert the warnings stay; do not remove them without a migration plan.

## Working Agreements
- Preserve single-command ergonomics and the deprecation detection flow in `smbseek.py`; surface trade-offs before altering CLI semantics.
- Maintain defensive posture: read-only SMB actions, respect rate limits, and highlight any change that touches auth sequences or rescan policies.
- When touching share parsing or authentication, protect invariants enforced by tests (`accessible_shares <= shares_found`) and database constraints.
- Route new console output through `SMBSeekOutput`; avoid ad-hoc prints so colors, quiet/verbose flags, and summaries stay consistent.
- Coordinate on any change that shifts session management or database schema—`UnifiedWorkflow` expects current contracts.

## Breadth Checks Before Editing
- CLI or flag tweaks demand syncs across docs (`README.md`, `docs/USER_GUIDE.md`), `test_cli_flags.py`, and help text embedded in `smbseek.py`.
- Config schema updates must align defaults in `shared/config`, validation logic, `conf/config.json`, and onboarding guidance in `docs/DEVNOTES.md`.
- Database changes require schema migrations (`tools/db_manager.py`, `docs/DATABASE_MIGRATION_GUIDE.md`) plus audits of DAL helpers.
- Adjustments to share parsing or smbclient flows need corresponding updates in `commands/access.py`, parser helpers, and `test_access_parsing.py`.
- Output summary or rollup modifications must stay in lockstep with automation that scrapes the wording (tests, reporting scripts, docs).

## Testing Expectations
- Run targeted suites: `python3 test_cli_flags.py`, `python3 test_access_parsing.py`, `python3 test_database_filtering.py`, and `python3 test_discover_metadata.py` when they touch the affected area.
- Record manual verifications for network-dependent paths (Shodan lookups, smbclient share access); note when sandboxing blocks full runs.
- For share parsing or database filtering changes, craft unit fixtures that cover Samba vs Windows variants; keep regression scenarios from docs alive.
- When tests cannot execute locally, spell out remote/real-world steps teammates should run and the expected outputs.
- After workflow edits, perform at least a dry run (`./smbseek.py --country XX --help` or equivalent) to confirm argument handling and warnings.

## Repo Hygiene & Operational Discipline
- Keep `.gitignore` current so clones start clean—exclude virtualenvs, caches, databases, and any temp artifacts.
- Never commit credentials, API keys, or internal docs; audit `conf/` and `tools/` outputs before staging, and prefer environment variables or sample templates for sensitive values.
- Commit early and often with focused diffs; push regularly so teammates (and automation) track progress and can roll back safely if needed.
- Before opening PRs, run `git status`/`git diff` to ensure only intentional files ship; rebase or merge mainline updates promptly to avoid drift.

## Documentation & Memory Hooks
- Re-read `CODEX.md` and this addendum each session; append concise lessons here whenever we learn something worth carrying forward.
- Mirror conventions that apply across repos back into the root `CODEX.md` once they prove stable.
- Keep CLI examples and behavioural notes in `docs/DEVNOTES.md` and `docs/USER_GUIDE.md` synchronized with the current implementation.
- Capture real-world gotchas (API quirks, smbclient behavior) in `docs/FUTURE.md` or this addendum to prevent rediscovery.

## Open Notes (2025-10-04)
- smbclient absence fallback: keep the verbose warning wording stable; tests assert messaging when enumeration degrades.
- `get_new_hosts_filter` statistics feed user-facing summaries—update the counts whenever altering filter logic to avoid misleading rollups.
- Deprecation notices in legacy commands must continue to emit "DEPRECATED" for CLI tests; coordinate before revising the phrasing.
- Discovery exclusion optimization: `self.exclusions` preserves original casing for Shodan query building; `self.exclusion_patterns` contains normalized lowercase for fast substring matching. Metadata caching in `self.shodan_host_metadata` uses explicit `org_normalized/isp_normalized` keys to avoid field conflicts. Memoization via `self._host_lookup_cache` prevents duplicate API calls within operations.
- Access concurrency: `access.max_concurrent_hosts` config enables parallel host processing (default 1). Thread-safe output via `_print_lock` in `SMBSeekOutput`. Rate limiting considerations apply when scaling concurrency—operators should adjust delays accordingly.
- Discovery concurrency: `discovery.max_concurrent_hosts` config enables parallel authentication testing during discovery phase (default 1). Thread-safe rate limiting via `_auth_rate_lock` and `_throttled_auth_wait()` helper. SMBClient fallback caching in `_smbclient_auth_cache` prevents duplicate command executions. Critical: coordinate concurrency with rate limiting—increasing discovery threads amplifies SMB attempts per unit time.
