"""
Read-only SMB file browser window for xsmbseek.

Capabilities:
- Browse directories (list only) on a chosen share.
- Download a single file to quarantine.
- No previews, execution, or writes to SMB.
"""

import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime

from shared.smb_browser import SMBNavigator, ListResult, Entry
from shared.quarantine import build_quarantine_path, log_quarantine_event
try:
    from gui.utils.database_access import DatabaseReader
except ImportError:
    from utils.database_access import DatabaseReader
try:
    from gui.components.server_list_window import details as detail_helpers  # for credential derivation
except ImportError:
    from server_list_window import details as detail_helpers


def _format_file_size(size_bytes: int) -> str:
    """Convert bytes to human-readable format (e.g., '1.6 MB')."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    unit_index = 0
    size = float(size_bytes)
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} B"
    return f"{size:.1f} {units[unit_index]}"


def _load_file_browser_config(config_path: Optional[str]) -> Dict:
    defaults = {
        "allow_smb1": True,
        "connect_timeout_seconds": 8,
        "request_timeout_seconds": 10,
        "max_entries_per_dir": 5000,
        "max_depth": 12,
        "max_path_length": 240,
        "download_chunk_mb": 4,
        "quarantine_root": "~/.smbseek/quarantine",
    }
    if not config_path:
        return defaults
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
        defaults.update(data.get("file_browser", {}))
    except Exception:
        pass
    return defaults


class FileBrowserWindow:
    """Tkinter window for SMB navigation + download."""

    def __init__(
        self,
        parent: tk.Widget,
        ip_address: str,
        shares: List[str],
        auth_method: Optional[str],
        config_path: Optional[str],
        db_reader: Optional[DatabaseReader] = None,
        theme=None,
        settings_manager=None,
        share_credentials: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        self.parent = parent
        self.ip_address = ip_address
        self.shares = shares
        self.auth_method = auth_method or ""
        self.db_reader = db_reader
        self.theme = theme
        self.config = _load_file_browser_config(config_path)
        self.settings_manager = settings_manager
        self.share_credentials = share_credentials or {}

        creds = detail_helpers._derive_credentials(self.auth_method)
        self.username, self.password = creds
        self.folder_defaults = self.config.get("folder_download", {})
        self.max_batch_files = int(self.config.get("max_batch_files", 50))
        self.current_share: Optional[str] = None
        self.current_path = "\\"
        self.list_thread: Optional[threading.Thread] = None
        self.download_thread: Optional[threading.Thread] = None
        self.busy = False

        self.navigator = SMBNavigator(
            allow_smb1=bool(self.config.get("allow_smb1", True)),
            connect_timeout=float(self.config.get("connect_timeout_seconds", 8)),
            request_timeout=float(self.config.get("request_timeout_seconds", 10)),
            max_entries=int(self.config.get("max_entries_per_dir", 5000)),
            max_depth=int(self.config.get("max_depth", 12)),
            max_path_length=int(self.config.get("max_path_length", 240)),
            download_chunk_mb=int(self.config.get("download_chunk_mb", 4)),
        )
        self.max_batch_files = int(self.config.get("max_batch_files", 50))

        self._build_window()
        if self.shares:
            self.share_var.set(self.shares[0])
            self._on_share_changed()
        else:
            self._set_status("No accessible shares found for this host.")

    # --- UI setup ------------------------------------------------------

    def _build_window(self) -> None:
        self.window = tk.Toplevel(self.parent)
        self.window.title(f"SMB File Browser - {self.ip_address}")
        self.window.geometry("900x620")
        self.window.minsize(720, 480)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        if self.theme:
            self.theme.apply_to_widget(self.window, "main_window")

        top_frame = tk.Frame(self.window)
        top_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        tk.Label(top_frame, text="Share:").pack(side=tk.LEFT)
        self.share_var = tk.StringVar()
        self.share_select = ttk.Combobox(top_frame, textvariable=self.share_var, state="readonly", values=self.shares)
        self.share_select.pack(side=tk.LEFT, padx=(5, 10))
        self.share_select.bind("<<ComboboxSelected>>", lambda *_: self._on_share_changed())

        tk.Label(top_frame, text="Path:").pack(side=tk.LEFT)
        self.path_var = tk.StringVar(value="\\")
        self.path_label = tk.Label(top_frame, textvariable=self.path_var, anchor="w")
        self.path_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 10))

        button_frame = tk.Frame(self.window)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 5))

        self.btn_up = tk.Button(button_frame, text="⬆ Up", command=self._on_up)
        self.btn_refresh = tk.Button(button_frame, text="🔄 Refresh", command=self._refresh)
        self.btn_download = tk.Button(button_frame, text="⬇ Download to Quarantine", command=self._on_download)
        self.btn_cancel = tk.Button(button_frame, text="Cancel", command=self._on_cancel, state=tk.DISABLED)

        for btn in (self.btn_up, self.btn_refresh, self.btn_download, self.btn_cancel):
            btn.pack(side=tk.LEFT, padx=5)

        # Treeview for entries
        columns = ("name", "type", "size", "modified")
        self.tree = ttk.Treeview(self.window, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("name", text="Name")
        self.tree.heading("type", text="Type")
        self.tree.heading("size", text="Size")
        self.tree.heading("modified", text="Modified")
        self.tree.column("name", width=260, anchor="w")
        self.tree.column("type", width=90, anchor="w")
        self.tree.column("size", width=120, anchor="e")
        self.tree.column("modified", width=180, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.tree.bind("<Double-1>", self._on_item_double_click)

        self.status_var = tk.StringVar(value="Select a share to begin.")
        status = tk.Label(self.window, textvariable=self.status_var, anchor="w")
        status.pack(fill=tk.X, padx=10, pady=(0, 10))

    # --- Navigation helpers -------------------------------------------

    def _on_share_changed(self) -> None:
        share = self.share_var.get()
        if not share:
            return
        # Apply stored credentials if available for this share
        if self.share_credentials:
            creds = self.share_credentials.get(share)
            if creds:
                self.username = creds.get("username") or self.username
                self.password = creds.get("password") or self.password
        self._disconnect()
        self.current_share = share
        self.current_path = "\\"
        self.path_var.set(self.current_path)
        self._refresh()

    def _on_up(self) -> None:
        if self.current_path in ("\\", "/", ""):
            return
        parts = [p for p in self.current_path.split("\\") if p]
        new_path = "\\" + "\\".join(parts[:-1]) if parts[:-1] else "\\"
        self.current_path = new_path
        self.path_var.set(self.current_path)
        self._refresh()

    def _refresh(self) -> None:
        if self.busy or not self.current_share:
            return
        self._start_list_thread(self.current_path)

    def _on_item_double_click(self, _event=None) -> None:
        # Ignore double-clicks while a directory listing is in-flight to prevent
        # accidental path appends (e.g., foo\\bar -> foo\\bar\\bar).
        if self.busy:
            return
        selection = self.tree.selection()
        if not selection:
            return
        item_id = selection[0]
        item = self.tree.item(item_id)
        values = item.get("values", [])
        name = values[0] if values else None
        type_label = values[1] if len(values) > 1 else None
        if type_label == "dir":
            new_path = self._join_path(self.current_path, name)
            self.current_path = new_path
            self.path_var.set(new_path)
            self._refresh()

    def _on_download(self) -> None:
        if self.busy or not self.current_share:
            return
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("No selection", "Select one or more files to download.", parent=self.window)
            return

        files = []
        dirs = []
        skipped_dirs = 0
        for item_id in selection:
            item = self.tree.item(item_id)
            values = item.get("values", [])
            if len(values) < 2:
                continue
            name = values[0]
            type_label = values[1]
            if type_label == "file":
                remote_path = self._join_path(self.current_path, name)
                files.append(remote_path)
            else:
                dir_path = self._join_path(self.current_path, name)
                dirs.append(dir_path)

        if not files and not dirs:
            messagebox.showinfo("No files", "No files or folders selected.", parent=self.window)
            return

        if len(files) > self.max_batch_files:
            proceed = messagebox.askyesno(
                "Large selection",
                f"You selected {len(files)} files (limit {self.max_batch_files}). Download anyway?",
                icon="warning",
                parent=self.window,
            )
            if not proceed:
                return

        if dirs:
            limits = self._prompt_folder_limits()
            if not limits:
                return
        self._start_download_thread(files, dirs, limits if dirs else None)

    def _on_cancel(self) -> None:
        self.navigator.cancel()
        self._set_status("Cancellation requested…")
        self.btn_cancel.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        self.navigator.cancel()
        self._disconnect()
        self.window.destroy()
        self.window = None

    # --- Thread wrappers ----------------------------------------------

    def _prompt_folder_limits(self) -> Optional[Dict[str, int]]:
        dlg = tk.Toplevel(self.window)
        dlg.title("Folder Download Limits")
        dlg.transient(self.window)
        dlg.grab_set()

        defaults = self._load_folder_limit_defaults()
        max_depth_var = tk.IntVar(value=int(defaults.get("max_depth", 5)))
        max_files_var = tk.IntVar(value=int(defaults.get("max_files", 200)))
        max_total_mb_var = tk.IntVar(value=int(defaults.get("max_total_mb", 500)))
        max_file_mb_var = tk.IntVar(value=int(defaults.get("max_file_mb", 100)))

        def add_row(label, var, row):
            tk.Label(dlg, text=label).grid(row=row, column=0, sticky="w", padx=8, pady=4)
            tk.Entry(dlg, textvariable=var, width=8).grid(row=row, column=1, sticky="w", padx=8, pady=4)

        add_row("Max depth", max_depth_var, 0)
        add_row("Max files", max_files_var, 1)
        add_row("Max total MB", max_total_mb_var, 2)
        add_row("Max file MB", max_file_mb_var, 3)

        limits: Dict[str, int] = {}

        def on_ok():
            try:
                limits.update({
                    "max_depth": max(0, int(max_depth_var.get())),
                    "max_files": max(0, int(max_files_var.get())),
                    "max_total_mb": max(0, int(max_total_mb_var.get())),
                    "max_file_mb": max(0, int(max_file_mb_var.get())),
                })
            except Exception:
                messagebox.showerror("Invalid input", "Please enter numeric limits.", parent=dlg)
                return
            self._persist_folder_limit_defaults(limits)
            dlg.destroy()

        def on_cancel():
            limits.clear()
            dlg.destroy()

        btn_frame = tk.Frame(dlg)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(8, 6))
        tk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=5)
        tk.Button(btn_frame, text="Start", command=on_ok).pack(side=tk.RIGHT)

        dlg.wait_window()
        return limits or None

    def _start_list_thread(self, path: str) -> None:
        # Mark busy before the worker thread starts to block re-entrant navigation.
        self._set_busy(True)

        def worker():
            try:
                self._ensure_connected()
                result = self.navigator.list_dir(path)
                self._safe_after(0, lambda: self._populate_entries(result, path))
            except Exception as e:
                self._safe_after(0, lambda err=e: self._set_status(f"Error: {err}"))
                self._safe_after(0, lambda err=e: messagebox.showerror("Browse error", str(err), parent=self.window) if self._window_alive() else None)
            finally:
                self._safe_after(0, lambda: self._set_busy(False))

        self.list_thread = threading.Thread(target=worker, daemon=True)
        self.list_thread.start()

    def _start_download_thread(self, remote_paths: List[str], remote_dirs: List[str], folder_limits: Optional[Dict[str, int]]) -> None:
        def worker():
            try:
                self._set_busy(True)
                self._ensure_connected()
                dest_dir = build_quarantine_path(
                    self.ip_address,
                    self.current_share,
                    base_path=self.config.get("quarantine_root"),
                )
                files_to_download = list(remote_paths)
                expand_errors: List[Tuple[str, str]] = []
                if remote_dirs and folder_limits:
                    expanded, skipped, expand_errors = self._expand_directories(remote_dirs, folder_limits)
                    files_to_download.extend(expanded)
                total = len(files_to_download)
                completed = 0
                errors: List[Tuple[str, str]] = []

                for remote_path in files_to_download:
                    self._safe_after(0, lambda rp=remote_path, c=completed, t=total: self._set_status(f"Downloading {rp} ({c+1}/{t})"))
                    try:
                        result = self.navigator.download_file(remote_path, dest_dir, preserve_structure=True)
                        try:
                            host_dir = Path(dest_dir).parent.parent  # host/date/share
                            log_quarantine_event(host_dir, f"downloaded {self.current_share}{remote_path} -> {result.saved_path}")
                        except Exception:
                            pass
                        completed += 1
                    except Exception as e:
                        errors.append((remote_path, str(e)))
                        continue

                summary_msg = f"Downloaded {completed}/{total} file(s)"
                total_errors = len(errors) + len(expand_errors)
                if total_errors:
                    summary_msg += f" ({total_errors} failed)"
                self._safe_after(0, lambda: self._set_status(summary_msg))
                if total_errors:
                    combined = errors + expand_errors
                    err_text = "\n".join(f"{p}: {err}" for p, err in combined[:5])
                    self._safe_after(0, lambda: messagebox.showwarning("Download issues", err_text, parent=self.window) if self._window_alive() else None)
                else:
                    self._safe_after(0, lambda: messagebox.showinfo("Download complete", summary_msg, parent=self.window) if self._window_alive() else None)
            except Exception as e:
                self._safe_after(0, lambda err=e: self._set_status(f"Download failed: {err}"))
                self._safe_after(0, lambda err=e: messagebox.showerror("Download failed", str(err), parent=self.window) if self._window_alive() else None)
            finally:
                self._safe_after(0, lambda: self._set_busy(False))

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    # --- SMB helpers ---------------------------------------------------

    def _expand_directories(self, dirs: List[str], limits: Dict[str, int]) -> Tuple[List[str], int, List[Tuple[str, str]]]:
        max_depth = limits.get("max_depth", 0)
        max_files = limits.get("max_files", 0)
        max_total_mb = limits.get("max_total_mb", 0)
        max_file_mb = limits.get("max_file_mb", 0)

        expanded: List[str] = []
        errors: List[Tuple[str, str]] = []
        skipped = 0
        total_bytes = 0

        stack: List[Tuple[str, int]] = [(d, 0) for d in dirs]

        while stack:
            current_path, depth = stack.pop()
            if max_depth and depth > max_depth:
                continue
            try:
                entries = self.navigator.list_dir(current_path)
            except Exception as exc:
                errors.append((current_path, str(exc)))
                continue
            for entry in entries.entries:
                name = entry.name
                rel = self._join_path(current_path, name)
                if entry.is_dir:
                    stack.append((rel, depth + 1))
                    continue

                size = entry.size or 0
                if max_file_mb and size > max_file_mb * 1024 * 1024:
                    skipped += 1
                    continue
                if max_total_mb:
                    if (total_bytes + size) > max_total_mb * 1024 * 1024:
                        errors.append((rel, "total size limit reached"))
                        return expanded, skipped, errors
                expanded.append(rel)
                total_bytes += size
                if max_files and len(expanded) >= max_files:
                    return expanded, skipped, errors

        return expanded, skipped, errors

    def _ensure_connected(self) -> None:
        if self.navigator and self.current_share and self.navigator.share_name == self.current_share:
            return
        if not self.current_share:
            raise RuntimeError("No share selected.")
        self.navigator.cancel()
        self.navigator.disconnect()
        self._set_status(f"Connecting to {self.ip_address}/{self.current_share}…")
        self.navigator.connect(
            host=self.ip_address,
            share=self.current_share,
            username=self.username,
            password=self.password,
        )

    def _disconnect(self) -> None:
        try:
            self.navigator.disconnect()
        except Exception:
            pass

    # --- UI updates ----------------------------------------------------

    def _populate_entries(self, result: ListResult, path: str) -> None:
        # Clear existing
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Sort directories first, then files
        sorted_entries = sorted(
            result.entries,
            key=lambda e: (0 if e.is_dir else 1, e.name.lower()),
        )

        for entry in sorted_entries:
            mtime_str = ""
            if entry.modified_time:
                mtime_str = datetime.fromtimestamp(entry.modified_time).strftime("%Y-%m-%d %H:%M:%S")
            self.tree.insert(
                "",
                "end",
                values=(entry.name, "dir" if entry.is_dir else "file", _format_file_size(entry.size), mtime_str),
            )

        status_parts = [f"Path {path} ({len(result.entries)} items)"]
        if result.truncated:
            status_parts.append(f"truncated at {self.config.get('max_entries_per_dir')}")
        if result.warning:
            status_parts.append(result.warning)
        self._set_status(" | ".join(status_parts))
        self.btn_cancel.configure(state=tk.NORMAL if self.busy else tk.DISABLED)

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for btn in (self.btn_up, self.btn_refresh, self.btn_download):
            if btn and btn.winfo_exists():
                btn.configure(state=state)
        if self.btn_cancel and self.btn_cancel.winfo_exists():
            self.btn_cancel.configure(state=tk.NORMAL if busy else tk.DISABLED)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    def _window_alive(self) -> bool:
        return bool(self.window and self.window.winfo_exists())

    def _safe_after(self, delay_ms: int, callback) -> None:
        if not self._window_alive():
            return
        try:
            self.window.after(delay_ms, callback)
        except Exception:
            pass

    def _load_folder_limit_defaults(self) -> Dict[str, int]:
        """
        Load folder download limits, preferring user settings over config defaults.
        """
        defaults = self.folder_defaults or {}
        if self.settings_manager:
            try:
                saved = self.settings_manager.get_setting('file_browser.folder_limits', {}) or {}
                # Merge saved over defaults
                defaults = {**defaults, **saved}
            except Exception:
                pass
        return defaults

    def _persist_folder_limit_defaults(self, limits: Dict[str, int]) -> None:
        """Persist folder download limits to settings."""
        if not self.settings_manager:
            return
        try:
            self.settings_manager.set_setting('file_browser.folder_limits', limits)
        except Exception:
            pass

    # --- Path helpers --------------------------------------------------

    @staticmethod
    def _join_path(base: str, name: str) -> str:
        base_norm = base.rstrip("\\/")
        if not base_norm:
            return f"\\{name}"
        return f"{base_norm}\\{name}"
