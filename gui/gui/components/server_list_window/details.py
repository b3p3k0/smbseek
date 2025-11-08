"""
Server Detail Popup Operations

Handles server detail popup windows and exploration functionality.
Self-contained UI components with passed data dependencies.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import threading
from typing import Dict, Any, List, Optional, Sequence

from gui.utils import probe_cache, probe_runner, probe_patterns
from gui.utils.probe_runner import ProbeError


def show_server_detail_popup(parent_window, server_data, theme, settings_manager=None,
                             probe_status_callback=None, indicator_patterns: Optional[Sequence[probe_patterns.IndicatorPattern]] = None):
    """
    Show server detail popup window.

    Args:
        parent_window: Parent window for transient behavior
        server_data: Server dictionary with all fields
        theme: Theme object for styling
    """
    # Create popup window
    detail_window = tk.Toplevel(parent_window)
    detail_window.title(f"Server Details - {server_data.get('ip_address', 'Unknown')}")
    detail_window.geometry("700x700")
    detail_window.transient(parent_window)

    theme.apply_to_widget(detail_window, "main_window")

    # Create scrollable text area
    text_frame = tk.Frame(detail_window)
    text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    text_widget = tk.Text(text_frame, wrap=tk.WORD, state=tk.DISABLED)
    scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
    text_widget.configure(yscrollcommand=scrollbar.set)

    text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Initial render (includes cached probe data if available)
    ip_address = server_data.get('ip_address', 'Unknown')
    cached_probe = probe_cache.load_probe_result(ip_address) if ip_address else None
    if cached_probe and indicator_patterns:
        probe_patterns.attach_indicator_analysis(cached_probe, indicator_patterns)
    _render_server_details(text_widget, server_data, cached_probe)

    # Status label for probe feedback
    status_var = tk.StringVar(value="")
    status_label = theme.create_styled_label(
        detail_window,
        "",
        "small",
        fg=theme.colors["text_secondary"]
    )
    status_label.configure(textvariable=status_var)
    status_label.pack(pady=(0, 5))

    # Button frame for Explore and Close buttons
    button_frame = tk.Frame(detail_window)
    theme.apply_to_widget(button_frame, "main_window")
    button_frame.pack(pady=(0, 10))

    probe_state = {
        "running": False,
        "latest": cached_probe,
        "indicator_patterns": indicator_patterns or []
    }

    probe_button = tk.Button(
        button_frame,
        text="Probe",
        command=lambda: _open_probe_dialog(
            detail_window,
            server_data,
            text_widget,
            status_var,
            probe_state,
            settings_manager,
            theme,
            probe_button,
            probe_status_callback
        )
    )
    theme.apply_to_widget(probe_button, "button_secondary")
    probe_button.pack(side=tk.LEFT, padx=(0, 10))

    # Explore button
    explore_button = tk.Button(
        button_frame,
        text="Explore",
        command=lambda: explore_server(server_data)
    )
    theme.apply_to_widget(explore_button, "button_secondary")
    explore_button.pack(side=tk.LEFT, padx=(0, 10))

    # Close button
    close_button = tk.Button(
        button_frame,
        text="Close",
        command=detail_window.destroy
    )
    theme.apply_to_widget(close_button, "button_primary")
    close_button.pack(side=tk.LEFT)

    # Ensure window is fully rendered before setting grab
    detail_window.update_idletasks()
    detail_window.grab_set()


def explore_server(server_data):
    """
    Open server in system file explorer via SMB/CIFS protocol.

    Args:
        server_data: Server dictionary containing IP address and authentication info
    """
    ip_address = server_data.get('ip_address')
    auth_method = server_data.get('auth_method', 'Unknown')

    if not ip_address:
        messagebox.showerror(
            "Invalid Server",
            "Server IP address is not available."
        )
        return

    try:
        system = platform.system()

        if system == "Linux":
            # Use xdg-open to open SMB URL in default file manager
            subprocess.run(['xdg-open', f'smb://{ip_address}/'], check=True)
        elif system == "Windows":
            # Use explorer to open UNC path
            subprocess.run(['explorer', f'\\\\{ip_address}\\'], check=True)
        elif system == "Darwin":  # macOS
            # Use open to launch SMB URL in Finder
            subprocess.run(['open', f'smb://{ip_address}/'], check=True)
        else:
            raise OSError(f"Unsupported operating system: {system}")

    except subprocess.CalledProcessError as e:
        messagebox.showerror(
            "Connection Failed",
            f"Could not open SMB connection to {ip_address}\n\n"
            f"The server may be offline, unreachable, or your system may not support SMB connections.\n\n"
            f"Authentication method: {auth_method}\n"
            f"Command failed with exit code: {e.returncode}"
        )
    except FileNotFoundError:
        messagebox.showerror(
            "System Error",
            f"Could not find system file explorer.\n\n"
            f"Please ensure your system supports SMB connections and has a file manager installed."
        )
    except Exception as e:
        messagebox.showerror(
            "Unexpected Error",
            f"An unexpected error occurred while trying to connect to {ip_address}\n\n"
            f"Error: {str(e)}\n\n"
            f"Please check your network connection and SMB client configuration."
        )


def _format_server_details(server: Dict[str, Any], probe_section: Optional[str] = None) -> str:
    """Format server details for display with accessible shares list."""
    # Extract share information
    accessible_list = server.get('accessible_shares_list', '')
    accessible_count = server.get('accessible_shares', 0)
    total_shares = server.get('total_shares', accessible_count)

    # Format accessible shares list
    if accessible_list and accessible_list.strip():
        shares = [share.strip() for share in accessible_list.split(',') if share.strip()]
        if shares:
            share_list_text = '\n'.join([f'   • {share}' for share in shares])
        else:
            share_list_text = '   • None accessible'
    else:
        share_list_text = '   • None accessible'

    details = f"""📋 SMB Server Details

🖥 Basic Information:
   IP Address: {server.get('ip_address', 'Unknown')}
   Country: {server.get('country', 'Unknown')} ({server.get('country_code', 'Unknown')})
   Authentication: {server.get('auth_method', 'Unknown')}

📊 Scan Information:
   First Seen: {server.get('first_seen', 'Unknown')}
   Last Seen: {server.get('last_seen', 'Unknown')}
   Scan Count: {server.get('scan_count', 0)}
   Status: {server.get('status', 'Unknown')}

📁 Share Access:
   Total Shares Discovered: {total_shares}
   Accessible Shares: {accessible_count}

   Accessible Share List:
{share_list_text}

{probe_section or '🔍 Probe:\n   No probe has been run for this host yet.\n'}

📝 Additional Notes:
   This server was discovered through SMBSeek scanning and shows
   the authentication method and share accessibility results.

   For detailed vulnerability information and remediation steps,
   use the Vulnerability Report window.

   For complete share enumeration data, check the backend database
   or export the detailed scan results.
    """

    return details


def _render_server_details(
    text_widget: tk.Text,
    server: Dict[str, Any],
    probe_result: Optional[Dict[str, Any]]
) -> None:
    """Render server details with probe section embedded."""
    probe_text = _format_probe_section(probe_result)
    full_text = _format_server_details(server, probe_text)

    text_widget.configure(state=tk.NORMAL)
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, full_text)
    text_widget.configure(state=tk.DISABLED)


def _format_probe_section(probe_result: Optional[Dict[str, Any]]) -> str:
    """Return formatted probe section text."""
    if not probe_result:
        return "🔍 Probe:\n   No probe has been run for this host yet.\n"

    limits = probe_result.get("limits", {})
    max_dirs = limits.get("max_directories")
    max_files = limits.get("max_files")
    timeout = limits.get("timeout_seconds")

    lines: List[str] = [
        "🔍 Probe Snapshot:",
        f"   Run: {probe_result.get('run_at', 'Unknown')}",
        f"   Limits: {max_dirs or '?'} dirs / {max_files or '?'} files per share | Timeout: {timeout or '?'}s"
    ]

    shares = probe_result.get("shares", [])
    if shares:
        for share in shares:
            share_name = share.get("share", "Unknown Share")
            lines.append(f"   Share: {share_name}")
            directories = share.get("directories", [])
            if not directories:
                lines.append("      (no directories returned)")
            for directory in directories:
                dir_name = directory.get("name", "")
                lines.append(f"      📁 {dir_name}/")
                files = directory.get("files", [])
                if files:
                    for file_name in files:
                        lines.append(f"         • {file_name}")
                    if directory.get("files_truncated"):
                        lines.append("         … additional files not shown")
                else:
                    lines.append("         (no files listed)")
            if share.get("directories_truncated"):
                lines.append("      … additional directories not shown")
    else:
        lines.append("   No shares were successfully probed.")

    analysis = probe_result.get("indicator_analysis") if probe_result else None
    if analysis:
        matches = analysis.get("matches", [])
        if matches:
            lines.append("\n   ☠ Indicators Detected:")
            for match in matches[:5]:
                indicator = match.get("indicator", "Indicator")
                path = match.get("path", "(unknown path)")
                lines.append(f"      {indicator} → {path}")
            if len(matches) > 5:
                lines.append(f"      … {len(matches) - 5} additional hits")
        else:
            lines.append("\n   ✅ No ransomware indicators detected in sampled paths.")

    errors = probe_result.get("errors", [])
    if errors:
        lines.append("\n   ⚠ Probe Errors:")
        for err in errors:
            share = err.get("share", "Unknown share")
            message = err.get("message", "Unknown error")
            lines.append(f"      {share}: {message}")

    lines.append("")
    return "\n".join(lines)


def _parse_accessible_shares(raw_value: Optional[str]) -> List[str]:
    if not raw_value:
        return []
    return [share.strip() for share in raw_value.split(',') if share.strip()]


def _load_probe_config(settings_manager) -> Dict[str, int]:
    """Load probe limits from settings (fall back to defaults)."""
    defaults = {
        "max_directories": 3,
        "max_files": 5,
        "timeout_seconds": 10
    }
    if not settings_manager:
        return defaults

    try:
        max_dirs = int(settings_manager.get_setting('probe.max_directories_per_share', defaults["max_directories"]))
        max_files = int(settings_manager.get_setting('probe.max_files_per_directory', defaults["max_files"]))
        timeout = int(settings_manager.get_setting('probe.share_timeout_seconds', defaults["timeout_seconds"]))
    except Exception:
        return defaults

    return {
        "max_directories": max(1, max_dirs),
        "max_files": max(1, max_files),
        "timeout_seconds": max(1, timeout)
    }


def _start_probe(
    detail_window: tk.Toplevel,
    server_data: Dict[str, Any],
    text_widget: tk.Text,
    status_var: tk.StringVar,
    probe_state: Dict[str, Any],
    settings_manager,
    probe_button: Optional[tk.Button],
    config_override: Optional[Dict[str, int]] = None,
    probe_status_callback=None
) -> None:
    """Trigger background probe run."""
    if probe_state.get("running"):
        return

    ip_address = server_data.get('ip_address')
    if not ip_address:
        messagebox.showwarning("Probe Unavailable", "Server IP address is missing.")
        return

    accessible_shares = _parse_accessible_shares(server_data.get('accessible_shares_list', ''))
    if not accessible_shares:
        messagebox.showinfo("Probe", "No accessible shares to probe for this host.")
        return

    config = config_override or _load_probe_config(settings_manager)
    indicator_patterns = probe_state.get("indicator_patterns") or []
    status_var.set("Probing accessible shares…")
    probe_state["running"] = True
    if probe_button:
        probe_button.configure(state=tk.DISABLED)

    def worker():
        try:
            result = probe_runner.run_probe(
                ip_address,
                accessible_shares,
                max_directories=config["max_directories"],
                max_files=config["max_files"],
                timeout_seconds=config["timeout_seconds"]
            )
            analysis = probe_patterns.attach_indicator_analysis(result, indicator_patterns)
            probe_cache.save_probe_result(ip_address, result)
            issue_detected = bool(analysis.get("is_suspicious"))

            def on_success():
                probe_state["running"] = False
                probe_state["latest"] = result
                if issue_detected:
                    status_var.set(
                        f"Probe flagged ransomware indicators at {result.get('run_at', 'unknown')}"
                    )
                else:
                    status_var.set(f"Probe completed at {result.get('run_at', 'unknown')}")
                if probe_button:
                    probe_button.configure(state=tk.NORMAL)
                _render_server_details(text_widget, server_data, result)
                if probe_status_callback:
                    probe_status_callback(ip_address, 'issue' if issue_detected else 'clean')

            detail_window.after(0, on_success)
        except Exception as exc:
            error_message = str(exc)

            def on_error():
                probe_state["running"] = False
                if probe_button:
                    probe_button.configure(state=tk.NORMAL)
                status_var.set("Probe failed.")
                messagebox.showerror("Probe Failed", error_message)

            detail_window.after(0, on_error)

    threading.Thread(target=worker, daemon=True).start()


def _open_probe_dialog(
    parent_window: tk.Toplevel,
    server_data: Dict[str, Any],
    text_widget: tk.Text,
    status_var: tk.StringVar,
    probe_state: Dict[str, Any],
    settings_manager,
    theme,
    probe_button: Optional[tk.Button],
    probe_status_callback=None
) -> None:
    """Show settings + launch dialog for probes."""
    if probe_state.get("running"):
        messagebox.showinfo("Probe Running", "A probe is already in progress.")
        return

    config = _load_probe_config(settings_manager)

    dialog = tk.Toplevel(parent_window)
    dialog.title("Probe Accessible Shares")
    dialog.transient(parent_window)
    dialog.grab_set()

    if theme:
        theme.apply_to_widget(dialog, "main_window")

    tk.Label(dialog, text="Max directories per share:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
    dirs_var = tk.IntVar(value=config["max_directories"])
    tk.Entry(dialog, textvariable=dirs_var, width=10).grid(row=0, column=1, padx=10, pady=(10, 5))

    tk.Label(dialog, text="Max files per directory:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
    files_var = tk.IntVar(value=config["max_files"])
    tk.Entry(dialog, textvariable=files_var, width=10).grid(row=1, column=1, padx=10, pady=5)

    tk.Label(dialog, text="Per-share timeout (seconds):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
    timeout_var = tk.IntVar(value=config["timeout_seconds"])
    tk.Entry(dialog, textvariable=timeout_var, width=10).grid(row=2, column=1, padx=10, pady=5)

    def start_probe_from_dialog():
        try:
            new_config = {
                "max_directories": max(1, int(dirs_var.get())),
                "max_files": max(1, int(files_var.get())),
                "timeout_seconds": max(1, int(timeout_var.get()))
            }
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter valid integers for all fields.")
            return

        if settings_manager:
            settings_manager.set_setting('probe.max_directories_per_share', new_config["max_directories"])
            settings_manager.set_setting('probe.max_files_per_directory', new_config["max_files"])
            settings_manager.set_setting('probe.share_timeout_seconds', new_config["timeout_seconds"])

        dialog.destroy()
        _start_probe(
            parent_window,
            server_data,
            text_widget,
            status_var,
            probe_state,
            settings_manager,
            probe_button,
            config_override=new_config,
            probe_status_callback=probe_status_callback
        )

    button_frame = tk.Frame(dialog)
    button_frame.grid(row=3, column=0, columnspan=2, pady=10)

    tk.Button(button_frame, text="Start Probe", command=start_probe_from_dialog).pack(side=tk.LEFT, padx=(0, 5))
    tk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT)
