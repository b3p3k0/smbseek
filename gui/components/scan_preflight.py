"""
Scan pre-flight controller and configuration dialogs.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, filedialog
from pathlib import Path
from typing import Optional, Dict, Any, List


class ProbeConfigDialog:
    """Collect probe batch settings before a scan begins."""

    def __init__(self, parent: tk.Toplevel, theme, settings_manager) -> None:
        self.parent = parent
        self.theme = theme
        self.settings = settings_manager
        self.dialog: Optional[tk.Toplevel] = None
        self.result: Optional[Dict[str, Any]] = None

        defaults = {
            "workers": 3,
            "max_dirs": 3,
            "max_files": 5,
            "timeout": 10,
            "rce": False
        }
        if self.settings:
            try:
                defaults["workers"] = int(self.settings.get_setting('probe.batch_max_workers', defaults['workers']))
                defaults["max_dirs"] = int(self.settings.get_setting('probe.max_directories_per_share', defaults['max_dirs']))
                defaults["max_files"] = int(self.settings.get_setting('probe.max_files_per_directory', defaults['max_files']))
                defaults["timeout"] = int(self.settings.get_setting('probe.share_timeout_seconds', defaults['timeout']))
                defaults["rce"] = bool(self.settings.get_setting('scan_dialog.rce_enabled', defaults['rce']))
            except Exception:
                pass

        self.worker_var = tk.IntVar(value=defaults['workers'])
        self.max_dirs_var = tk.IntVar(value=defaults['max_dirs'])
        self.max_files_var = tk.IntVar(value=defaults['max_files'])
        self.timeout_var = tk.IntVar(value=defaults['timeout'])
        self.rce_var = tk.BooleanVar(value=defaults['rce'])

    def show(self) -> Dict[str, Any]:
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Configure Bulk Probe")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        if self.theme:
            self.theme.apply_to_widget(self.dialog, "main_window")

        frame = tk.Frame(self.dialog)
        frame.pack(padx=20, pady=20)

        self._add_entry(frame, "Worker threads (max 8):", self.worker_var, 0)
        self._add_entry(frame, "Max directories per share:", self.max_dirs_var, 1)
        self._add_entry(frame, "Max files per directory:", self.max_files_var, 2)
        self._add_entry(frame, "Share timeout (seconds):", self.timeout_var, 3)

        rce_check = tk.Checkbutton(frame, text="Enable RCE analysis", variable=self.rce_var)
        rce_check.grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        if self.theme:
            self.theme.apply_to_widget(rce_check, "checkbox")

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=5, column=0, columnspan=2, pady=(15, 0))
        save_btn = tk.Button(btn_frame, text="Save & Continue", command=self._save)
        disable_btn = tk.Button(btn_frame, text="Disable Probe", command=self._disable)
        abort_btn = tk.Button(btn_frame, text="Abort Scan", command=self._abort)
        for btn in (save_btn, disable_btn, abort_btn):
            if self.theme:
                self.theme.apply_to_widget(btn, "button_secondary")
            btn.pack(side=tk.LEFT, padx=5)

        self.dialog.protocol("WM_DELETE_WINDOW", self._abort)
        self.parent.wait_window(self.dialog)
        return self.result or {"status": "abort"}

    def _add_entry(self, parent, label, var, row):
        tk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=var, width=10).grid(row=row, column=1, sticky="w", pady=5)

    def _save(self):
        try:
            data = {
                "status": "ok",
                "workers": max(1, min(8, int(self.worker_var.get()))),
                "max_dirs": max(1, int(self.max_dirs_var.get())),
                "max_files": max(1, int(self.max_files_var.get())),
                "timeout": max(1, int(self.timeout_var.get())),
                "rce": bool(self.rce_var.get())
            }
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid Input", "Please enter numeric values for probe limits.", parent=self.dialog)
            return

        if self.settings:
            try:
                self.settings.set_setting('probe.batch_max_workers', data['workers'])
                self.settings.set_setting('probe.max_directories_per_share', data['max_dirs'])
                self.settings.set_setting('probe.max_files_per_directory', data['max_files'])
                self.settings.set_setting('probe.share_timeout_seconds', data['timeout'])
                self.settings.set_setting('scan_dialog.rce_enabled', data['rce'])
            except Exception:
                pass

        self.result = data
        self.dialog.destroy()

    def _disable(self):
        self.result = {"status": "disable"}
        self.dialog.destroy()

    def _abort(self):
        self.result = {"status": "abort"}
        self.dialog.destroy()


class ExtractConfigDialog:
    """Collect extract batch settings before a scan begins."""

    def __init__(self, parent: tk.Toplevel, theme, settings_manager) -> None:
        self.parent = parent
        self.theme = theme
        self.settings = settings_manager
        self.dialog: Optional[tk.Toplevel] = None
        self.result: Optional[Dict[str, Any]] = None

        defaults = {
            "workers": 2,
            "path": str(Path.home()),
            "max_file": 50,
            "max_total": 200,
            "max_time": 300,
            "max_files": 10
        }
        if self.settings:
            try:
                defaults["workers"] = int(self.settings.get_setting('extract.batch_max_workers', defaults['workers']))
                defaults["path"] = str(self.settings.get_setting('extract.last_directory', defaults['path']))
                defaults["max_file"] = int(self.settings.get_setting('extract.max_file_size_mb', defaults['max_file']))
                defaults["max_total"] = int(self.settings.get_setting('extract.max_total_size_mb', defaults['max_total']))
                defaults["max_time"] = int(self.settings.get_setting('extract.max_time_seconds', defaults['max_time']))
                defaults["max_files"] = int(self.settings.get_setting('extract.max_files_per_target', defaults['max_files']))
            except Exception:
                pass

        self.worker_var = tk.IntVar(value=defaults['workers'])
        self.path_var = tk.StringVar(value=defaults['path'])
        self.max_file_var = tk.IntVar(value=defaults['max_file'])
        self.max_total_var = tk.IntVar(value=defaults['max_total'])
        self.max_time_var = tk.IntVar(value=defaults['max_time'])
        self.max_files_var = tk.IntVar(value=defaults['max_files'])

    def show(self) -> Dict[str, Any]:
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Configure Bulk Extract")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        if self.theme:
            self.theme.apply_to_widget(self.dialog, "main_window")

        frame = tk.Frame(self.dialog)
        frame.pack(padx=20, pady=20)

        self._add_entry(frame, "Worker threads (max 8):", self.worker_var, 0)

        tk.Label(frame, text="Quarantine path:").grid(row=1, column=0, sticky="w", pady=5)
        path_frame = tk.Frame(frame)
        path_frame.grid(row=1, column=1, sticky="w", pady=5)
        tk.Entry(path_frame, textvariable=self.path_var, width=30).pack(side=tk.LEFT)
        browse_btn = tk.Button(path_frame, text="Browse", command=self._browse)
        browse_btn.pack(side=tk.LEFT, padx=(5, 0))

        self._add_entry(frame, "Max file size (MB):", self.max_file_var, 2)
        self._add_entry(frame, "Max total size (MB):", self.max_total_var, 3)
        self._add_entry(frame, "Max run time (seconds):", self.max_time_var, 4)
        self._add_entry(frame, "Max files per host:", self.max_files_var, 5)

        btn_frame = tk.Frame(frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=(15, 0))
        save_btn = tk.Button(btn_frame, text="Save & Continue", command=self._save)
        disable_btn = tk.Button(btn_frame, text="Disable Extract", command=self._disable)
        abort_btn = tk.Button(btn_frame, text="Abort Scan", command=self._abort)
        for btn in (save_btn, disable_btn, abort_btn):
            if self.theme:
                self.theme.apply_to_widget(btn, "button_secondary")
            btn.pack(side=tk.LEFT, padx=5)

        self.dialog.protocol("WM_DELETE_WINDOW", self._abort)
        self.parent.wait_window(self.dialog)
        return self.result or {"status": "abort"}

    def _browse(self):
        selection = filedialog.askdirectory(parent=self.dialog, title="Select Quarantine Path")
        if selection:
            self.path_var.set(selection)

    def _add_entry(self, parent, label, var, row):
        tk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=var, width=15).grid(row=row, column=1, sticky="w", pady=5)

    def _save(self):
        try:
            data = {
                "status": "ok",
                "workers": max(1, min(8, int(self.worker_var.get()))),
                "path": self.path_var.get().strip() or str(Path.home()),
                "max_file": max(1, int(self.max_file_var.get())),
                "max_total": max(1, int(self.max_total_var.get())),
                "max_time": max(30, int(self.max_time_var.get())),
                "max_files": max(1, int(self.max_files_var.get()))
            }
        except (ValueError, tk.TclError):
            messagebox.showerror("Invalid Input", "Please enter numeric values for extract limits.", parent=self.dialog)
            return

        if self.settings:
            try:
                self.settings.set_setting('extract.batch_max_workers', data['workers'])
                self.settings.set_setting('extract.last_directory', data['path'])
                self.settings.set_setting('extract.max_file_size_mb', data['max_file'])
                self.settings.set_setting('extract.max_total_size_mb', data['max_total'])
                self.settings.set_setting('extract.max_time_seconds', data['max_time'])
                self.settings.set_setting('extract.max_files_per_target', data['max_files'])
            except Exception:
                pass

        self.result = data
        self.dialog.destroy()

    def _disable(self):
        self.result = {"status": "disable"}
        self.dialog.destroy()

    def _abort(self):
        self.result = {"status": "abort"}
        self.dialog.destroy()


class SummaryDialog:
    def __init__(self, parent: tk.Toplevel, theme, lines: List[str], base_line: str) -> None:
        self.parent = parent
        self.theme = theme
        self.lines = lines
        self.base_line = base_line
        self.dialog: Optional[tk.Toplevel] = None
        self.result: Optional[bool] = None

    def show(self) -> bool:
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Review Scan Options")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        if self.theme:
            self.theme.apply_to_widget(self.dialog, "main_window")

        frame = tk.Frame(self.dialog)
        frame.pack(padx=20, pady=20)

        tk.Label(frame, text="Confirm settings before launching the scan", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")

        summary_text = tk.Text(frame, width=80, height=12, state="disabled")
        summary_text.pack(pady=(10, 0))
        summary_text.config(state="normal")
        summary_text.insert("end", f"Base scan: {self.base_line}\n")
        for line in self.lines:
            summary_text.insert("end", f"- {line}\n")
        summary_text.config(state="disabled")

        btn_frame = tk.Frame(frame)
        btn_frame.pack(pady=(15, 0))
        back_btn = tk.Button(btn_frame, text="Back to Scan", command=self._back)
        start_btn = tk.Button(btn_frame, text="Start Scan", command=self._start)
        if self.theme:
            self.theme.apply_to_widget(back_btn, "button_secondary")
            self.theme.apply_to_widget(start_btn, "button_primary")
        back_btn.pack(side=tk.LEFT, padx=5)
        start_btn.pack(side=tk.LEFT, padx=5)

        self.dialog.protocol("WM_DELETE_WINDOW", self._back)
        self.parent.wait_window(self.dialog)
        return bool(self.result)

    def _back(self):
        self.result = False
        self.dialog.destroy()

    def _start(self):
        self.result = True
        self.dialog.destroy()


class ScanPreflightController:
    def __init__(self, parent: tk.Toplevel, theme, settings_manager, scan_options: Dict[str, Any], scan_description: str) -> None:
        self.parent = parent
        self.theme = theme
        self.settings = settings_manager
        self.scan_options = scan_options
        self.scan_description = scan_description
        self.summary_lines: List[str] = []

    def run(self) -> Optional[Dict[str, Any]]:
        probe_enabled = self.scan_options.get('bulk_probe_enabled', False)
        extract_enabled = self.scan_options.get('bulk_extract_enabled', False)
        rce_enabled = bool(self.scan_options.get('rce_enabled', False))

        if not any((probe_enabled, extract_enabled, rce_enabled)):
            return self.scan_options

        if probe_enabled:
            outcome = ProbeConfigDialog(self.parent, self.theme, self.settings).show()
            status = outcome.get('status')
            if status == 'abort':
                return None
            if status == 'disable':
                self.scan_options['bulk_probe_enabled'] = False
                self.summary_lines.append('Probe disabled for this scan')
            else:
                self.summary_lines.append(
                    f"Probe enabled • workers {outcome['workers']} • dirs {outcome['max_dirs']} • files {outcome['max_files']} • timeout {outcome['timeout']}s • RCE {'On' if outcome['rce'] else 'Off'}"
                )
                self.scan_options['bulk_probe_enabled'] = True
                self.scan_options['rce_enabled'] = outcome['rce']
        if extract_enabled:
            outcome = ExtractConfigDialog(self.parent, self.theme, self.settings).show()
            status = outcome.get('status')
            if status == 'abort':
                return None
            if status == 'disable':
                self.scan_options['bulk_extract_enabled'] = False
                self.summary_lines.append('Extract disabled for this scan')
            else:
                self.summary_lines.append(
                    f"Extract enabled • workers {outcome['workers']} • path {outcome['path']} • file {outcome['max_file']}MB • total {outcome['max_total']}MB • time {outcome['max_time']}s • files {outcome['max_files']}"
                )
                self.scan_options['bulk_extract_enabled'] = True

        if self.scan_options.get('rce_enabled') and not self.scan_options.get('bulk_probe_enabled'):
            self.scan_options['rce_enabled'] = False
            self.summary_lines.append('RCE disabled (requires probe)')
        elif self.scan_options.get('rce_enabled'):
            self.summary_lines.append('RCE analysis will run with probe results')

        if not self.summary_lines:
            self.summary_lines.append('No optional post-scan actions selected')

        ok = SummaryDialog(self.parent, self.theme, self.summary_lines, self.scan_description).show()
        if not ok:
            return None
        return self.scan_options


def run_preflight(parent: tk.Toplevel, theme, settings_manager, scan_options: Dict[str, Any], scan_description: str) -> Optional[Dict[str, Any]]:
    controller = ScanPreflightController(parent, theme, settings_manager, scan_options, scan_description)
    return controller.run()
