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
from typing import Dict, List, Optional
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
        share_credentials: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> None:
        self.parent = parent
        self.ip_address = ip_address
        self.shares = shares
        self.auth_method = auth_method or ""
        self.db_reader = db_reader
        self.theme = theme
        self.config = _load_file_browser_config(config_path)
        self.share_credentials = share_credentials or {}

        creds = detail_helpers._derive_credentials(self.auth_method)
        self.username, self.password = creds
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
        self.tree = ttk.Treeview(self.window, columns=columns, show="headings")
        self.tree.heading("name", text="Name")
        self.tree.heading("type", text="Type")
        self.tree.heading("size", text="Size (bytes)")
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
            messagebox.showinfo("No selection", "Select a file to download.")
            return
        item = self.tree.item(selection[0])
        values = item.get("values", [])
        if len(values) < 2 or values[1] != "file":
            messagebox.showinfo("Download", "Select a file (not a directory).")
            return
        filename = values[0]
        remote_path = self._join_path(self.current_path, filename)
        self._start_download_thread(remote_path)

    def _on_cancel(self) -> None:
        self.navigator.cancel()
        self._set_status("Cancellation requested…")
        self.btn_cancel.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        self.navigator.cancel()
        self._disconnect()
        self.window.destroy()

    # --- Thread wrappers ----------------------------------------------

    def _start_list_thread(self, path: str) -> None:
        def worker():
            try:
                self._set_busy(True)
                self._ensure_connected()
                result = self.navigator.list_dir(path)
                self.window.after(0, self._populate_entries, result, path)
            except Exception as e:
                self.window.after(0, lambda err=e: self._set_status(f"Error: {err}"))
                self.window.after(0, lambda err=e: messagebox.showerror("Browse error", str(err)))
            finally:
                self.window.after(0, lambda: self._set_busy(False))

        self.list_thread = threading.Thread(target=worker, daemon=True)
        self.list_thread.start()

    def _start_download_thread(self, remote_path: str) -> None:
        def worker():
            try:
                self._set_busy(True)
                self._ensure_connected()
                dest_dir = build_quarantine_path(
                    self.ip_address,
                    self.current_share,
                    base_path=self.config.get("quarantine_root"),
                )
                result = self.navigator.download_file(remote_path, dest_dir)
                msg = f"Downloaded to {result.saved_path}"
                try:
                    host_dir = Path(dest_dir).parent.parent  # host/date/share
                    log_quarantine_event(host_dir, f"downloaded {self.current_share}{remote_path} -> {result.saved_path}")
                except Exception:
                    pass
                self.window.after(0, lambda: self._set_status(msg))
                self.window.after(0, lambda: messagebox.showinfo("Download complete", msg))
            except Exception as e:
                self.window.after(0, lambda err=e: self._set_status(f"Download failed: {err}"))
                self.window.after(0, lambda err=e: messagebox.showerror("Download failed", str(err)))
            finally:
                self.window.after(0, lambda: self._set_busy(False))

        self.download_thread = threading.Thread(target=worker, daemon=True)
        self.download_thread.start()

    # --- SMB helpers ---------------------------------------------------

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
                values=(entry.name, "dir" if entry.is_dir else "file", entry.size, mtime_str),
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
            btn.configure(state=state)
        self.btn_cancel.configure(state=tk.NORMAL if busy else tk.DISABLED)

    def _set_status(self, text: str) -> None:
        self.status_var.set(text)

    # --- Path helpers --------------------------------------------------

    @staticmethod
    def _join_path(base: str, name: str) -> str:
        base_norm = base.rstrip("\\/")
        if not base_norm:
            return f"\\{name}"
        return f"{base_norm}\\{name}"
