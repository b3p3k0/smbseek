# Sandboxed Explorer Guide

This guide explains how SMBSeek’s GUI “Explore” button launches a containerized file browser so analysts can review remote shares without mounting them on the host OS.

## Explore Workflow at a Glance (non-technical)
- **Click Explore.** The GUI reuses the same credentials already associated with the host (anonymous/guest by default).
- **Fire up a sandbox.** A minimal Alpine Linux container starts via Podman/Docker and installs `pcmanfm` + GVFS modules inside the sandbox only.
- **Open the share safely.** `pcmanfm smb://<ip>/` runs inside that container, so any browsing, metadata caching, or GVFS mounts stay isolated from the analyst workstation.
- **See results locally.** The GUI streams container stdout/stderr back to the status bar; if anything fails, you know immediately.

## How the Sandbox Launch Works (with proof points)
```
Explore button
     │
     ▼
Credential parser ──→ derives username/password from stored auth method
     │
     ▼
Display detector ──→ chooses X11 (/tmp/.X11-unix) or Wayland (XDG_RUNTIME_DIR)
     │
     ▼
Sandbox manager ──→ Podman/Docker run --rm --network host …
     │
     ▼
Container bootstrap ──→ apk add pcmanfm gvfs gvfs-smb samba-client
     │
     ▼
Browser launch ──→ exec pcmanfm "smb://IP/"
```

1. **Deterministic command builder.** `SandboxManager.launch_file_browser` constructs the full container command in Python, so the GUI can echo exactly what ran if troubleshooting is required.
2. **Display binding with guardrails.** We only continue if `$DISPLAY` (X11) or `$WAYLAND_DISPLAY` + `$XDG_RUNTIME_DIR` (Wayland) resolves to an accessible socket. Otherwise we abort with a clear error instead of guessing.
3. **Credential isolation.** SMB usernames/passwords are injected as environment variables scoped to the container and never written to disk. The host file manager is never involved.
4. **Ephemeral runtime.** Containers run with `--rm`, drop privileges (`no-new-privileges`, `--cap-drop ALL` in investigation shells), and disappear after the browse session ends, leaving no lingering mounts.
5. **Network parity.** We reuse the host network namespace (`--network host`) so the sandbox sees the exact same routing/firewall context analysts already validated, avoiding confusing “works in GUI, fails in sandbox” discrepancies.

## Limitations & Risks
- **Linux + Podman/Docker only.** macOS/Windows users still need a local workaround; until we validate GUI sharing on those platforms the Explore button remains host-bound.
- **Display permissions.** X11 users must permit the container to connect (e.g., `xhost +si:localuser:$USER`). Wayland compositors vary; hardened setups may refuse all external clients.
- **Network inheritance.** Because we reuse the host network namespace, anything reachable from the analyst’s machine is reachable from the sandbox too. Treat the container like another process on your workstation.
- **Credential lifetime.** SMB credentials live in environment variables for the duration of the container. They disappear afterward, but anyone with root on the host could inspect `/proc/<pid>/environ` while the session is active.
- **Package downloads.** The sandbox `apk add` step requires outbound access to Alpine mirrors the first time it runs (or whenever the container image is cold). Offline environments should pre-build a custom image with the required packages.

## Troubleshooting Checklist
1. **Verify runtime:** `podman info` (or `docker info`) should succeed outside SMBSeek.
2. **Confirm display access:** For X11, run `xhost` and ensure the local user is whitelisted. For Wayland, confirm `$WAYLAND_DISPLAY` exists under `$XDG_RUNTIME_DIR`.
3. **Dry-run the container:** `podman run --rm --network host -e DISPLAY=$DISPLAY docker.io/library/alpine:latest sh -c "apk add pcmanfm gvfs gvfs-smb && pcmanfm --help"` should launch without errors (swap environment variables for Wayland).
4. **Check stderr:** When the GUI reports a failure it includes stderr from the container (e.g., “pcmanfm: cannot open display”). Use that as the starting point.

By understanding the flow and boundaries above, you can extend or troubleshoot the sandbox with confidence.
