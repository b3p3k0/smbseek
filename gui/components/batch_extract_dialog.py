"""
Batch Extract Settings Dialog

Unified dialog for configuring batch file extraction from SMB servers.
Supports two modes:
- "preflight": Used during scan workflow setup
- "on-demand": Used for extracting from server list selections

Design Decision: Single dialog class reduces code duplication and ensures
consistent extension filter display across both workflows.
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import json
from pathlib import Path
from typing import Dict, List, Any, Optional


class BatchExtractSettingsDialog:
    """
    Modal dialog for batch extract settings configuration.

    Supports two operational modes with different button layouts and return values:
    - preflight: Scan workflow (Save & Continue / Disable / Abort buttons)
    - on-demand: Server list extraction (Start / Cancel buttons)

    Both modes display extension filter info and provide access to config editor.
    """

    def __init__(
        self,
        parent: tk.Toplevel,
        theme,
        settings_manager,
        config_path: str,
        mode: str = "on-demand",
        target_count: Optional[int] = None,
        config_editor_callback: Optional[callable] = None
    ):
        """
        Initialize batch extract settings dialog.

        Args:
            parent: Parent window
            theme: Theme object for styling
            settings_manager: Settings manager instance
            config_path: Path to config.json
            mode: "preflight" or "on-demand"
            target_count: Number of targets (optional, for on-demand mode)
            config_editor_callback: Callback to open config editor (optional)
        """
        self.parent = parent
        self.theme = theme
        self.settings = settings_manager
        self.config_path = Path(config_path) if config_path else None
        self.mode = mode
        self.target_count = target_count
        self.config_editor_callback = config_editor_callback
        self.dialog: Optional[tk.Toplevel] = None
        self.result: Optional[Dict[str, Any]] = None

        # Load defaults from settings and config
        self._load_defaults()

    def _load_defaults(self):
        """Load default values from settings manager and config file."""
        # Basic defaults
        defaults = {
            "workers": 2,
            "path": str(Path.home()),
            "max_file": 50,
            "max_total": 200,
            "max_time": 300,
            "max_files": 10,
            "max_directory_depth": 3,
            "download_delay_seconds": 0.5,
            "connection_timeout": 30
        }

        # Load from settings manager
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

        # Load from config file for additional settings
        if self.config_path and self.config_path.exists():
            try:
                config_data = json.loads(self.config_path.read_text(encoding="utf-8"))
                file_cfg = config_data.get("file_collection", {})
                defaults["max_directory_depth"] = int(file_cfg.get("max_directory_depth", defaults["max_directory_depth"]))
                defaults["download_delay_seconds"] = float(file_cfg.get("download_delay_seconds", defaults["download_delay_seconds"]))
                defaults["connection_timeout"] = int(file_cfg.get("enumeration_timeout_seconds", defaults["connection_timeout"]))
            except Exception:
                pass

        # Create tkinter variables
        self.worker_var = tk.IntVar(value=defaults['workers'])
        self.path_var = tk.StringVar(value=defaults['path'])
        self.max_file_var = tk.IntVar(value=defaults['max_file'])
        self.max_total_var = tk.IntVar(value=defaults['max_total'])
        self.max_time_var = tk.IntVar(value=defaults['max_time'])
        self.max_files_var = tk.IntVar(value=defaults['max_files'])

        # Store for on-demand mode return value
        self.max_directory_depth = defaults["max_directory_depth"]
        self.download_delay_seconds = defaults["download_delay_seconds"]
        self.connection_timeout = defaults["connection_timeout"]

    def show(self) -> Optional[Dict[str, Any]]:
        """
        Display dialog and return result.

        Returns:
            Dict with settings (format depends on mode) or None if cancelled
        """
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Batch Extract Settings")
        self.dialog.transient(self.parent)
        self.dialog.grab_set()

        if self.theme:
            self.theme.apply_to_widget(self.dialog, "main_window")

        # Main container
        main_frame = tk.Frame(self.dialog)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

        row = 0

        # Target count (on-demand mode only)
        if self.mode == "on-demand" and self.target_count is not None:
            label = tk.Label(main_frame, text=f"Targets selected: {self.target_count}")
            label.grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 10))
            row += 1

        # Create input fields
        row = self._create_fields(main_frame, row)

        # Add extension filter display
        row = self._create_extension_display(main_frame, row)

        # Create buttons based on mode
        self._create_buttons(main_frame, row)

        # Handle window close
        if self.mode == "preflight":
            self.dialog.protocol("WM_DELETE_WINDOW", self._on_abort)
        else:
            self.dialog.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self.parent.wait_window(self.dialog)
        return self.result

    def _create_fields(self, parent: tk.Frame, start_row: int) -> int:
        """Create input fields. Returns next available row."""
        row = start_row

        # Worker threads
        tk.Label(parent, text="Worker threads (max 8):").grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=self.worker_var, width=15).grid(row=row, column=1, sticky="w", pady=5)
        row += 1

        # Quarantine path
        tk.Label(parent, text="Quarantine path:").grid(row=row, column=0, sticky="w", pady=5)
        path_frame = tk.Frame(parent)
        path_frame.grid(row=row, column=1, sticky="w", pady=5)
        tk.Entry(path_frame, textvariable=self.path_var, width=30).pack(side=tk.LEFT)
        browse_btn = tk.Button(path_frame, text="Browse", command=self._browse_path)
        if self.theme:
            self.theme.apply_to_widget(browse_btn, "button_secondary")
        browse_btn.pack(side=tk.LEFT, padx=(5, 0))
        row += 1

        # Max file size
        tk.Label(parent, text="Max file size (MB):").grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=self.max_file_var, width=15).grid(row=row, column=1, sticky="w", pady=5)
        row += 1

        # Max total size
        tk.Label(parent, text="Max total size (MB):").grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=self.max_total_var, width=15).grid(row=row, column=1, sticky="w", pady=5)
        row += 1

        # Max run time
        tk.Label(parent, text="Max run time (seconds):").grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=self.max_time_var, width=15).grid(row=row, column=1, sticky="w", pady=5)
        row += 1

        # Max files per host
        tk.Label(parent, text="Max files per host:").grid(row=row, column=0, sticky="w", pady=5)
        tk.Entry(parent, textvariable=self.max_files_var, width=15).grid(row=row, column=1, sticky="w", pady=5)
        row += 1

        return row

    def _create_extension_display(self, parent: tk.Frame, start_row: int) -> int:
        """Create extension filter display section. Returns next available row."""
        row = start_row

        # Add separator
        separator = tk.Frame(parent, height=2, bd=1, relief=tk.SUNKEN)
        separator.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(15, 10))
        row += 1

        # Load filters
        filters = self._load_extension_filters()
        allowed_count = len(filters["included_extensions"])
        denied_count = len(filters["excluded_extensions"])

        # Build count display text
        if allowed_count == 0:
            allowed_text = "None configured"
        else:
            allowed_text = f"{allowed_count} allowed"

        if denied_count == 0:
            denied_text = "No restrictions"
        else:
            denied_text = f"{denied_count} denied"

        # Extension count label
        label_text = f"Extensions: {allowed_text}, {denied_text}"
        ext_label = tk.Label(parent, text=label_text, justify="left")
        ext_label.grid(row=row, column=0, columnspan=2, sticky="w", pady=5)
        row += 1

        # Button frame for side-by-side buttons
        button_frame = tk.Frame(parent)
        button_frame.grid(row=row, column=0, columnspan=2, sticky="w", pady=5)

        # View Filters button
        view_button = tk.Button(button_frame, text="View Filters", command=self._show_extension_table)
        if self.theme:
            self.theme.apply_to_widget(view_button, "button_secondary")
        view_button.pack(side=tk.LEFT, padx=(0, 5))

        # Edit Configuration button (only if callback provided)
        if self.config_editor_callback:
            config_button = tk.Button(button_frame, text="⚙ Edit Configuration", command=self._open_config_editor)
            if self.theme:
                self.theme.apply_to_widget(config_button, "button_secondary")
            config_button.pack(side=tk.LEFT)

        row += 1

        # Add separator
        separator2 = tk.Frame(parent, height=2, bd=1, relief=tk.SUNKEN)
        separator2.grid(row=row, column=0, columnspan=2, sticky="ew", pady=(10, 15))
        row += 1

        return row

    def _load_extension_filters(self) -> Dict[str, List[str]]:
        """Load extension filters from config.json."""
        defaults = {
            "included_extensions": [],
            "excluded_extensions": []
        }

        if self.config_path and self.config_path.exists():
            try:
                config_data = json.loads(self.config_path.read_text(encoding="utf-8"))
                file_cfg = config_data.get("file_collection", {})
                defaults["included_extensions"] = file_cfg.get("included_extensions", [])
                defaults["excluded_extensions"] = file_cfg.get("excluded_extensions", [])
            except Exception:
                pass  # Use defaults on any error

        return defaults

    def _show_extension_table(self):
        """Show modal dialog with extension filter table."""
        filters = self._load_extension_filters()

        # Create modal dialog
        table_dialog = tk.Toplevel(self.dialog)
        table_dialog.title("Extension Filters")
        table_dialog.geometry("600x400")
        table_dialog.transient(self.dialog)
        table_dialog.grab_set()
        if self.theme:
            self.theme.apply_to_widget(table_dialog, "window")

        # Main container
        main_frame = tk.Frame(table_dialog)
        if self.theme:
            self.theme.apply_to_widget(main_frame, "card")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Two-column layout (Allowed | Denied)
        columns_frame = tk.Frame(main_frame)
        if self.theme:
            self.theme.apply_to_widget(columns_frame, "card")
        columns_frame.pack(fill=tk.BOTH, expand=True)

        # Allowed column
        allowed_frame = tk.Frame(columns_frame)
        if self.theme:
            self.theme.apply_to_widget(allowed_frame, "card")
        allowed_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        allowed_label = tk.Label(allowed_frame, text="Allowed Extensions")
        allowed_label.pack(anchor="w", pady=5)

        allowed_text = tk.Text(allowed_frame, height=15, width=25)
        if self.theme:
            self.theme.apply_to_widget(allowed_text, "text")
        allowed_text.pack(fill=tk.BOTH, expand=True)

        allowed_list = filters["included_extensions"]
        if allowed_list:
            allowed_text.insert("1.0", "\n".join(allowed_list))
        else:
            allowed_text.insert("1.0", "None configured")
        allowed_text.config(state="disabled")

        # Denied column
        denied_frame = tk.Frame(columns_frame)
        if self.theme:
            self.theme.apply_to_widget(denied_frame, "card")
        denied_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)

        denied_label = tk.Label(denied_frame, text="Denied Extensions")
        denied_label.pack(anchor="w", pady=5)

        denied_text = tk.Text(denied_frame, height=15, width=25)
        if self.theme:
            self.theme.apply_to_widget(denied_text, "text")
        denied_text.pack(fill=tk.BOTH, expand=True)

        denied_list = filters["excluded_extensions"]
        if denied_list:
            denied_text.insert("1.0", "\n".join(denied_list))
        else:
            denied_text.insert("1.0", "No restrictions")
        denied_text.config(state="disabled")

        # Close button
        close_button = tk.Button(main_frame, text="Close", command=table_dialog.destroy)
        if self.theme:
            self.theme.apply_to_widget(close_button, "button_primary")
        close_button.pack(pady=10)

    def _open_config_editor(self):
        """Open configuration editor."""
        if self.config_editor_callback and self.config_path:
            try:
                self.config_editor_callback(str(self.config_path))
            except Exception as e:
                messagebox.showerror(
                    "Configuration Editor Error",
                    f"Failed to open configuration editor:\n{str(e)}",
                    parent=self.dialog
                )

    def _create_buttons(self, parent: tk.Frame, start_row: int):
        """Create buttons based on mode."""
        button_frame = tk.Frame(parent)
        button_frame.grid(row=start_row, column=0, columnspan=2, pady=(15, 0))

        if self.mode == "preflight":
            # Preflight mode: Save & Continue / Disable Extract / Abort Scan
            save_btn = tk.Button(button_frame, text="Save & Continue", command=self._on_save)
            disable_btn = tk.Button(button_frame, text="Disable Extract", command=self._on_disable)
            abort_btn = tk.Button(button_frame, text="Abort Scan", command=self._on_abort)

            for btn in (save_btn, disable_btn, abort_btn):
                if self.theme:
                    self.theme.apply_to_widget(btn, "button_secondary")
                btn.pack(side=tk.LEFT, padx=5)
        else:
            # On-demand mode: Cancel / Start
            cancel_btn = tk.Button(button_frame, text="Cancel", command=self._on_cancel)
            start_btn = tk.Button(button_frame, text="Start", command=self._on_start)

            for btn in (cancel_btn, start_btn):
                if self.theme:
                    self.theme.apply_to_widget(btn, "button_secondary")

            start_btn.pack(side=tk.RIGHT, padx=5)
            cancel_btn.pack(side=tk.RIGHT)

    def _browse_path(self):
        """Open file dialog to select quarantine path."""
        selection = filedialog.askdirectory(parent=self.dialog, title="Select Quarantine Path")
        if selection:
            self.path_var.set(selection)

    def _validate_inputs(self) -> Optional[Dict[str, Any]]:
        """Validate input fields and return sanitized values or None on error."""
        try:
            workers = max(1, min(8, int(self.worker_var.get())))
            path = self.path_var.get().strip() or str(Path.home())
            max_file = max(1, int(self.max_file_var.get()))
            max_total = max(1, int(self.max_total_var.get()))
            max_time = max(30, int(self.max_time_var.get()))
            max_files = max(1, int(self.max_files_var.get()))

            return {
                "workers": workers,
                "path": path,
                "max_file": max_file,
                "max_total": max_total,
                "max_time": max_time,
                "max_files": max_files
            }
        except (ValueError, tk.TclError):
            messagebox.showerror(
                "Invalid Input",
                "Please enter numeric values for extraction limits.",
                parent=self.dialog
            )
            return None

    def _save_settings(self, values: Dict[str, Any]):
        """Save settings to settings manager."""
        if self.settings:
            try:
                self.settings.set_setting('extract.batch_max_workers', values['workers'])
                self.settings.set_setting('extract.last_directory', values['path'])
                self.settings.set_setting('extract.max_file_size_mb', values['max_file'])
                self.settings.set_setting('extract.max_total_size_mb', values['max_total'])
                self.settings.set_setting('extract.max_time_seconds', values['max_time'])
                self.settings.set_setting('extract.max_files_per_target', values['max_files'])
            except Exception:
                pass

    def _on_save(self):
        """Handle Save & Continue button (preflight mode)."""
        values = self._validate_inputs()
        if values is None:
            return

        self._save_settings(values)

        self.result = {
            "status": "ok",
            "workers": values["workers"],
            "path": values["path"],
            "max_file": values["max_file"],
            "max_total": values["max_total"],
            "max_time": values["max_time"],
            "max_files": values["max_files"]
        }
        self.dialog.destroy()

    def _on_disable(self):
        """Handle Disable Extract button (preflight mode)."""
        self.result = {"status": "disable"}
        self.dialog.destroy()

    def _on_abort(self):
        """Handle Abort Scan button (preflight mode)."""
        self.result = {"status": "abort"}
        self.dialog.destroy()

    def _on_start(self):
        """Handle Start button (on-demand mode)."""
        values = self._validate_inputs()
        if values is None:
            return

        self._save_settings(values)

        # Load extension filters for on-demand return value
        filters = self._load_extension_filters()

        self.result = {
            "worker_count": values["workers"],
            "download_path": values["path"],
            "max_file_size_mb": values["max_file"],
            "max_total_size_mb": values["max_total"],
            "max_time_seconds": values["max_time"],
            "max_files_per_target": values["max_files"],
            "max_directory_depth": self.max_directory_depth,
            "download_delay_seconds": self.download_delay_seconds,
            "included_extensions": filters["included_extensions"],
            "excluded_extensions": filters["excluded_extensions"],
            "connection_timeout": self.connection_timeout
        }
        self.dialog.destroy()

    def _on_cancel(self):
        """Handle Cancel button (on-demand mode)."""
        self.result = None
        self.dialog.destroy()
