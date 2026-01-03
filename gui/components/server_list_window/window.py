"""
Main Server List Window

Orchestrates all server list functionality using extracted modules.
Maintains all shared state and coordinates between components.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, Future
import threading
import platform
import csv
import os
import sys

# Add utils to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))

try:
    from gui.utils.database_access import DatabaseReader
    from gui.utils.style import get_theme
    from gui.utils.data_export_engine import get_export_engine
    from gui.utils.scan_manager import get_scan_manager
    from gui.utils.dialog_helpers import ensure_dialog_focus
    from gui.components.file_browser_window import FileBrowserWindow
    from gui.components.pry_dialog import PryDialog
except ImportError:
    # Handle relative imports when running from gui directory
    from utils.database_access import DatabaseReader
    from utils.style import get_theme
    from utils.data_export_engine import get_export_engine
    from utils.scan_manager import get_scan_manager
    from utils.dialog_helpers import ensure_dialog_focus
    from components.file_browser_window import FileBrowserWindow
    from components.pry_dialog import PryDialog

# Import modular components
from . import export, details, filters, table
try:
    from batch_extract_dialog import BatchExtractSettingsDialog  # standalone/absolute import
except ImportError:
    from ..batch_extract_dialog import BatchExtractSettingsDialog  # package relative fallback
from gui.utils import probe_cache, probe_patterns, probe_runner, extract_runner, pry_runner
from shared.quarantine import create_quarantine_dir


class ServerListWindow:
    """
    Server list browser window with filtering and export capabilities.

    Orchestrates modular components while maintaining all shared state.
    Acts as facade for clean external interface.
    """

    def __init__(self, parent: tk.Widget, db_reader: DatabaseReader,
                 window_data: Dict[str, Any] = None, settings_manager = None):
        """
        Initialize server list browser window.

        Args:
            parent: Parent widget
            db_reader: Database access instance
            window_data: Optional data for filtering/focus
            settings_manager: Optional settings manager for favorites functionality
        """
        self.parent = parent
        self.db_reader = db_reader
        self.theme = get_theme()
        self.window_data = window_data or {}
        self.settings_manager = settings_manager
        self.probe_status_map = {}
        self.ransomware_indicators = []
        self.indicator_patterns = []

        # Favorites and avoid functionality
        self.favorites_only = tk.BooleanVar()
        self.avoid_only = tk.BooleanVar()

        # Window and UI components
        self.window = None
        self.main_frame = None
        self.filter_frame = None
        self.filter_widgets = None
        self.table_frame = None
        self.button_frame = None

        # Table components
        self.tree = None
        self.scrollbar_v = None
        self.scrollbar_h = None

        # Filter variables - simplified for enhanced share tracking
        self.search_text = tk.StringVar()
        self.search_var = tk.StringVar()  # Additional search reference
        self.date_filter = tk.StringVar(value="All")
        self.shares_filter = tk.BooleanVar(value=True)  # Default checked to hide zero-share servers

        # UI components
        self.count_label = None
        self.selection_label = None
        self.status_label = None
        self.mode_button = None
        self.show_all_button = None
        self.context_menu = None
        self.probe_button = None
        self.extract_button = None
        self.pry_button = None
        self.browser_button = None
        self.stop_button = None
        self.table_overlay = None
        self.table_overlay_label = None
        self._stop_button_original_style = None
        self._context_menu_visible = False
        self._context_menu_bindings = []

        # Date filtering state
        self.filter_recent = self.window_data.get("filter_recent", False)
        self.last_scan_time = None

        # Data management
        self.all_servers = []
        self.filtered_servers = []
        self.selected_servers = []
        self.batch_job = None
        self._pending_table_refresh = False
        self._pending_selection = []

        # Window state
        self.is_advanced_mode = False

        # Sort state tracking for bidirectional column sorting
        self.current_sort_column = None
        self.current_sort_direction = None
        self.original_headers = {}  # Cache original column text for clean restoration

        # Default sort directions for each column
        self.default_sort_directions = {
            "IP Address": "asc",      # alphabetical A-Z
            "Shares": "desc",         # high numbers first (10, 5, 1)
            "Accessible": "desc",     # high share count first (sorts by number of shares)
            "Last Seen": "desc",      # MOST RECENT dates first (2024-01-02, 2024-01-01, 2023-12-31)
            "Country": "asc",         # alphabetical A-Z
            "probe": "desc"
        }

        self._create_window()
        self._load_data()

        if self.settings_manager:
            self.probe_status_map = self.settings_manager.get_probe_status_map()
            self._load_indicator_patterns()
        else:
            self._load_indicator_patterns()

    def _create_window(self) -> None:
        """Create the server list window."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("SMBSeek - Server List Browser")
        self.window.geometry("1500x1000")
        self.window.minsize(800, 500)

        # Apply theme
        self.theme.apply_to_widget(self.window, "main_window")

        # Make window modal (use master window if available)
        if hasattr(self.parent, 'winfo_toplevel'):
            master_window = self.parent.winfo_toplevel()
            self.window.transient(master_window)
        self.window.grab_set()

        # Center window
        self._center_window()

        # Build UI components
        self._create_header()
        self._create_filter_panel()
        self._create_server_table()
        self._create_button_panel()

        # Bind events
        self._setup_event_handlers()

        # Ensure window appears on top and gains focus (critical for VMs)
        ensure_dialog_focus(self.window, self.parent)

    def _load_indicator_patterns(self) -> None:
        """Load ransomware indicator patterns from SMBSeek config."""
        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path:
                try:
                    config_path = self.settings_manager.get_smbseek_config_path()
                except Exception:
                    config_path = None
        self.ransomware_indicators = probe_patterns.load_ransomware_indicators(config_path)
        self.indicator_patterns = probe_patterns.compile_indicator_patterns(self.ransomware_indicators)

    def _center_window(self) -> None:
        """Center window on parent."""
        if self.window is not None:
            self.window.update_idletasks()
            # Get parent window position and size
            parent_x = self.parent.winfo_x()
            parent_y = self.parent.winfo_y()
            parent_width = self.parent.winfo_width()
            parent_height = self.parent.winfo_height()
            # Calculate center position
            width = self.window.winfo_width()
            height = self.window.winfo_height()
            x = parent_x + (parent_width // 2) - (width // 2)
            y = parent_y + (parent_height // 2) - (height // 2)
            self.window.geometry(f"{width}x{height}+{x}+{y}")

    def _create_header(self) -> None:
        """Create window header with title and controls."""
        header_frame = tk.Frame(self.window)
        self.theme.apply_to_widget(header_frame, "main_window")
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        # Title
        title_label = self.theme.create_styled_label(
            header_frame,
            "🖥 SMB Server List",
            "heading"
        )
        title_label.pack(side=tk.LEFT)

        # Server count
        self.count_label = self.theme.create_styled_label(
            header_frame,
            "Loading...",
            "body"
        )
        self.count_label.pack(side=tk.LEFT, padx=(20, 0))

        # Close button
        close_button = tk.Button(
            header_frame,
            text="✕ Close",
            command=self._close_window
        )
        self.theme.apply_to_widget(close_button, "button_secondary")
        close_button.pack(side=tk.RIGHT)

        # Mode toggle button
        self.mode_button = tk.Button(
            header_frame,
            text="🔧 Advanced",
            command=self._toggle_mode
        )
        self.theme.apply_to_widget(self.mode_button, "button_secondary")
        self.mode_button.pack(side=tk.RIGHT, padx=(0, 10))

    def _create_filter_panel(self) -> None:
        """Create filtering controls panel using filters module."""
        # Prepare filter variables
        filter_vars = {
            'search_text': self.search_text,
            'date_filter': self.date_filter,
            'shares_filter': self.shares_filter,
            'favorites_only': self.favorites_only,
            'avoid_only': self.avoid_only
        }

        # Prepare callbacks
        filter_callbacks = {
            'on_search_changed': self._apply_filters,
            'on_date_filter_changed': self._apply_filters,
            'on_shares_filter_changed': self._apply_filters,
            'on_favorites_only_changed': self._apply_filters,
            'on_avoid_only_changed': self._apply_filters,
            'on_clear_search': self._clear_search,
            'on_reset_filters': self._reset_filters
        }

        # Add show all toggle if needed
        if self.filter_recent:
            filter_callbacks['on_show_all_toggle'] = self._toggle_show_all_results

        # Create filter panel using module
        self.filter_frame, self.filter_widgets = filters.create_filter_panel(
            self.window, self.theme, filter_vars, filter_callbacks
        )

        # Disable favorites/avoid checkboxes if no settings manager
        if not self.settings_manager:
            if 'favorites_checkbox' in self.filter_widgets:
                self.filter_widgets['favorites_checkbox'].configure(state="disabled")
            if 'avoid_checkbox' in self.filter_widgets:
                self.filter_widgets['avoid_checkbox'].configure(state="disabled")

        # Pack filter frame (shown/hidden based on mode)
        self._update_mode_display()

    def _create_server_table(self) -> None:
        """Create server data table using table module."""
        # Prepare callbacks
        table_callbacks = {
            'on_selection_changed': self._on_selection_changed,
            'on_double_click': self._on_double_click,
            'on_treeview_click': self._on_treeview_click,
            'on_sort_column': self._sort_by_column
        }

        # Create table using module
        self.table_frame, self.tree, self.scrollbar_v, self.scrollbar_h = table.create_server_table(
            self.window, self.theme, table_callbacks
        )

        self._create_context_menu(self.tree)
        self._bind_context_menu_events(self.tree)
        self._create_table_overlay()

        # Pack table frame
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _create_context_menu(self, tree: ttk.Treeview) -> None:
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="🔍 Probe Selected", command=self._on_probe_selected)
        self.context_menu.add_command(label="📦 Extract Selected", command=self._on_extract_selected)
        self.context_menu.add_command(label="🔓 Pry Selected", command=self._on_pry_selected)
        self.context_menu.add_command(label="🗂️ File Browser (read-only)", command=self._on_file_browser_selected)
        self._update_context_menu_state()

    def _bind_context_menu_events(self, tree: ttk.Treeview) -> None:
        tree.bind("<Button-3>", self._show_context_menu)
        if platform.system() == "Darwin":
            tree.bind("<Button-2>", self._show_context_menu)
            tree.bind("<Control-Button-1>", self._show_context_menu)

    def _create_table_overlay(self) -> None:
        self.table_overlay = tk.Frame(self.table_frame, bg="#f0f0f0")
        self.table_overlay.place_forget()
        self.table_overlay_label = tk.Label(
            self.table_overlay,
            text="Batch in progress… Server list locked",
            bg="#f0f0f0",
            fg="#555555"
        )
        self.table_overlay_label.pack(expand=True)

    def _set_table_interaction_enabled(self, enabled: bool) -> None:
        if not self.table_overlay:
            return
        if enabled:
            self.table_overlay.place_forget()
        else:
            self.table_overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.table_overlay.lift()

    def _create_button_panel(self) -> None:
        """Create bottom button panel with actions."""
        self.button_frame = tk.Frame(self.window)
        self.theme.apply_to_widget(self.button_frame, "main_window")
        self.button_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        # Left side - selection + status info
        info_container = tk.Frame(self.button_frame)
        self.theme.apply_to_widget(info_container, "main_window")
        info_container.pack(side=tk.LEFT, anchor="w")

        self.selection_label = self.theme.create_styled_label(
            info_container,
            "No selection",
            "small"
        )
        self.selection_label.pack(anchor="w")

        self.status_label = self.theme.create_styled_label(
            info_container,
            "Idle",
            "small"
        )
        self.status_label.pack(anchor="w")

        # Right side - action buttons
        button_container = tk.Frame(self.button_frame)
        self.theme.apply_to_widget(button_container, "main_window")
        button_container.pack(side=tk.RIGHT)

        # Batch/quick action buttons
        self.probe_button = tk.Button(
            button_container,
            text="🔍 Probe Selected",
            command=self._on_probe_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.probe_button, "button_primary")
        self.probe_button.pack(side=tk.LEFT, padx=(0, 5))

        self.extract_button = tk.Button(
            button_container,
            text="📦 Extract Selected",
            command=self._on_extract_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.extract_button, "button_secondary")
        self.extract_button.pack(side=tk.LEFT, padx=(0, 15))

        self.browser_button = tk.Button(
            button_container,
            text="🗂️ Browse (read-only)",
            command=self._on_file_browser_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.browser_button, "button_secondary")
        self.browser_button.pack(side=tk.LEFT, padx=(0, 15))

        self.pry_button = tk.Button(
            button_container,
            text="🔓 Pry Selected",
            command=self._on_pry_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.pry_button, "button_secondary")
        self.pry_button.pack(side=tk.LEFT, padx=(0, 15))

        self.stop_button = tk.Button(
            button_container,
            text="⏹ Stop Batch",
            command=self._stop_active_batch,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.stop_button, "button_secondary")
        self.stop_button.pack(side=tk.LEFT, padx=(0, 20))
        self._stop_button_original_style = {
            "bg": self.stop_button.cget("bg"),
            "fg": self.stop_button.cget("fg"),
            "activebackground": self.stop_button.cget("activebackground"),
            "activeforeground": self.stop_button.cget("activeforeground"),
            "text": self.stop_button.cget("text")
        }

        # Server details button
        self.details_button = tk.Button(
            button_container,
            text="📋 View Details",
            command=self._view_server_details
        )
        self.theme.apply_to_widget(self.details_button, "button_secondary")
        self.details_button.pack(side=tk.LEFT, padx=(0, 5))

        # Export selected button
        self.export_selected_button = tk.Button(
            button_container,
            text="📤 Export Selected",
            command=self._export_selected_servers
        )
        self.theme.apply_to_widget(self.export_selected_button, "button_secondary")
        self.export_selected_button.pack(side=tk.LEFT, padx=(0, 5))

        # Export all button
        self.export_all_button = tk.Button(
            button_container,
            text="📊 Export All",
            command=self._export_all_servers
        )
        self.theme.apply_to_widget(self.export_all_button, "button_primary")
        self.export_all_button.pack(side=tk.LEFT)

        self._update_action_buttons_state()

    def _setup_event_handlers(self) -> None:
        """Setup event handlers for the window."""
        # Window close event
        self.window.protocol("WM_DELETE_WINDOW", self._close_window)

        # Keyboard shortcuts
        self.window.bind("<Control-a>", self._select_all)
        self.window.bind("<Control-e>", lambda e: self._export_selected_servers())
        self.window.bind("<Control-b>", lambda e: self._on_file_browser_selected())
        self.window.bind("<Escape>", lambda e: self._close_window())
        self.window.bind("<F5>", lambda e: self._refresh_data())

    def _apply_filters(self, *, force: bool = False) -> None:
        """Apply current filters to server list using filter module functions."""
        if self._is_batch_active() and not force:
            if not self._pending_table_refresh:
                self._pending_selection = self._get_selected_ips()
            self._pending_table_refresh = True
            return

        filtered = self.all_servers[:]

        # Apply search filter
        search_term = self.search_text.get()
        if search_term:
            filtered = filters.apply_search_filter(filtered, search_term)

        # Apply date filter
        date_filter_value = self.date_filter.get()
        if date_filter_value and date_filter_value != "All":
            filtered = filters.apply_date_filter(filtered, date_filter_value, self.last_scan_time)

        # Apply accessible shares filter
        if self.shares_filter.get():
            filtered = filters.apply_shares_filter(filtered, True)

        # Apply favorites filter
        if self.favorites_only.get():
            filtered = filters.apply_favorites_filter(filtered, True, self.settings_manager)

        # Apply avoid filter
        if self.avoid_only.get():
            filtered = filters.apply_avoid_filter(filtered, True, self.settings_manager)

        self.filtered_servers = filtered

        # Update table display using table module
        table.update_table_display(self.tree, self.filtered_servers, self.settings_manager)

        # Update count display
        self.count_label.configure(
            text=f"Showing: {len(self.filtered_servers)} of {len(self.all_servers)} servers"
        )

        self._update_action_buttons_state()

    def _load_data(self) -> None:
        """Load server data from database."""
        try:
            # Get last scan time from scan manager
            scan_manager = get_scan_manager()
            self.last_scan_time = scan_manager.get_last_scan_time()

            # Get all servers with pagination (large limit to get all)
            servers, total_count = self.db_reader.get_server_list(
                limit=10000,  # Large limit to get all servers
                offset=0
            )

            self.all_servers = servers
            self._attach_probe_status(self.all_servers)

            # Set initial date filter if requested
            if self.filter_recent and self.last_scan_time:
                self.date_filter.set("Since Last Scan")

            # Reset sort state for fresh dataset
            self._reset_sort_state()

            # Apply initial filters and display data
            self._apply_filters()

            # Update count display
            self.count_label.configure(text=f"Total: {len(self.all_servers)} servers")

        except Exception as e:
            messagebox.showerror(
                "Data Loading Error",
                f"Failed to load server data:\n{str(e)}"
            )

    def _reset_sort_state(self) -> None:
        """Reset sort state and restore all headers to original text."""
        # Restore all headers to original text
        for column, original_text in self.original_headers.items():
            self.tree.heading(column, text=original_text)

        # Clear sort state
        self.current_sort_column = None
        self.current_sort_direction = None

    # Event handlers
    def _on_selection_changed(self) -> None:
        """Handle table selection changes."""
        selected_items = self.tree.selection()
        selected_count = len(selected_items)

        if selected_count == 0:
            self.selection_label.configure(text="No selection")
        elif selected_count == 1:
            self.selection_label.configure(text="1 server selected")
        else:
            self.selection_label.configure(text=f"{selected_count} servers selected")

        self._update_action_buttons_state()

    def _on_double_click(self, event) -> None:
        """Handle double-click on table row using table module."""
        table.handle_double_click(
            self.tree, event, self.filtered_servers,
            self._show_server_detail_popup
        )

    def _on_treeview_click(self, event) -> None:
        """Handle treeview clicks using table module."""
        callbacks = {
            'on_favorites_filter_changed': self._apply_filters,
            'on_avoid_filter_changed': self._apply_filters
        }
        table.handle_treeview_click(self.tree, event, self.settings_manager, callbacks)

    def _sort_by_column(self, column: str) -> None:
        """Sort table by specified column using table module."""
        self.current_sort_column, self.current_sort_direction = table.sort_table_by_column(
            self.tree, column, self.current_sort_column, self.current_sort_direction,
            self.original_headers, self.default_sort_directions
        )

    def _select_all(self, event=None) -> None:
        """Select all items in table."""
        table.select_all_items(self.tree)

    # Action handlers
    def _view_server_details(self) -> None:
        """Show detailed information for selected server."""
        selected_items = self.tree.selection()

        if not selected_items:
            messagebox.showwarning("No Selection", "Please select a server to view details.")
            return

        if len(selected_items) > 1:
            messagebox.showwarning("Multiple Selection", "Please select only one server to view details.")
            return

        # Get server data
        item = selected_items[0]
        values = self.tree.item(item)["values"]
        ip_address = values[3]  # IP Address now at index 3 (fav/avoid/probe)

        # Find server in data
        server_data = next(
            (server for server in self.filtered_servers if server.get("ip_address") == ip_address),
            None
        )

        if not server_data:
            messagebox.showerror("Error", "Server data not found.")
            return

        # Show details using details module
        self._show_server_detail_popup(server_data)

    def _show_server_detail_popup(self, server_data: Dict[str, Any]) -> None:
        """Show server detail popup using details module."""
        details.show_server_detail_popup(
            self.window,
            server_data,
            self.theme,
            self.settings_manager,
            probe_status_callback=self._handle_probe_status_update,
            indicator_patterns=self.indicator_patterns
        )

    def _export_selected_servers(self) -> None:
        """Export selected servers using export module."""
        selected_data = table.get_selected_server_data(self.tree, self.filtered_servers)
        if not selected_data:
            messagebox.showwarning("No Selection", "Please select servers to export.")
            return

        export.show_export_menu(
            self.window, selected_data, "selected", self.theme, get_export_engine()
        )

    def _export_all_servers(self) -> None:
        """Export all filtered servers using export module."""
        if not self.filtered_servers:
            messagebox.showwarning("No Data", "No servers to export.")
            return

        export.show_export_menu(
            self.window, self.filtered_servers, "all", self.theme, get_export_engine()
        )

    # Batch + context actions

    def _on_probe_selected(self) -> None:
        self._hide_context_menu()
        if self._is_batch_active():
            messagebox.showinfo("Batch Running", "Please wait for the current batch to finish or stop it before starting a new probe batch.")
            return

        targets = self._build_selected_targets()
        if not targets:
            messagebox.showwarning("No Selection", "Please select at least one server to probe.")
            return

        dialog_config = self._prompt_probe_batch_settings(len(targets))
        if not dialog_config:
            return

        self._start_batch_job("probe", targets, dialog_config)

    def _on_extract_selected(self) -> None:
        self._hide_context_menu()
        if self._is_batch_active():
            messagebox.showinfo("Batch Running", "Please wait for the current batch to finish or stop it before starting a new extract batch.")
            return

        targets = self._build_selected_targets()
        if not targets:
            messagebox.showwarning("No Selection", "Please select at least one server to extract from.")
            return

        # Get config path from settings manager
        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path and hasattr(self.settings_manager, "get_smbseek_config_path"):
                config_path = self.settings_manager.get_smbseek_config_path()

        # Use consolidated batch extract dialog
        dialog_config = BatchExtractSettingsDialog(
            parent=self.window,
            theme=self.theme,
            settings_manager=self.settings_manager,
            config_path=config_path,
            mode="on-demand",
            target_count=len(targets)
        ).show()

        if not dialog_config:
            return

        self._start_batch_job("extract", targets, dialog_config)

    def _on_pry_selected(self) -> None:
        self._hide_context_menu()
        if self._is_batch_active():
            messagebox.showinfo("Batch Running", "Please wait for the current batch to finish or stop it before starting Pry.")
            return

        targets = self._build_selected_targets()
        if len(targets) != 1:
            messagebox.showwarning("Select one server", "Choose exactly one server to run Pry.")
            return

        target = targets[0]
        ip_addr = target.get("ip_address") or ""

        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path and hasattr(self.settings_manager, "get_smbseek_config_path"):
                config_path = self.settings_manager.get_smbseek_config_path()

        dialog = PryDialog(
            parent=self.window,
            theme=self.theme,
            settings_manager=self.settings_manager,
            config_path=config_path,
            target_label=ip_addr
        )
        dialog_result = dialog.show()
        if not dialog_result:
            return

        options = dialog_result.get("options", {})
        options.update({
            "username": dialog_result.get("username", ""),
            "wordlist_path": dialog_result.get("wordlist_path", ""),
            "worker_count": 1
        })
        self._start_batch_job("pry", [target], options)

    def _on_file_browser_selected(self) -> None:
        self._hide_context_menu()
        if self._is_batch_active():
            messagebox.showinfo("Batch Running", "Please wait for the current batch to finish or stop it before browsing.")
            return

        targets = self._build_selected_targets()
        if len(targets) != 1:
            messagebox.showwarning("Select one server", "Choose exactly one server to browse.")
            return

        target = targets[0]
        ip_addr = target.get("ip_address")
        if not ip_addr:
            messagebox.showerror("Missing IP", "Unable to determine IP for selected server.")
            return

        shares = self.db_reader.get_accessible_shares(ip_addr) if self.db_reader else []
        def _clean_share_name(name: str) -> str:
            return name.strip().strip("\\/").strip()

        seen = set()
        share_names = []
        for s in shares:
            raw = s.get("share_name")
            cleaned = _clean_share_name(raw) if raw else ""
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            share_names.append(cleaned)
        if not share_names:
            messagebox.showinfo("No shares", "No accessible shares found for this host.")
            return

        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path and hasattr(self.settings_manager, "get_smbseek_config_path"):
                config_path = self.settings_manager.get_smbseek_config_path()

        FileBrowserWindow(
            parent=self.window,
            ip_address=ip_addr,
            shares=share_names,
            auth_method=target.get("auth_method", ""),
            config_path=config_path,
            db_reader=self.db_reader,
            theme=self.theme,
        )

    def _prompt_probe_batch_settings(self, target_count: int) -> Optional[Dict[str, Any]]:
        config = details._load_probe_config(self.settings_manager)
        default_workers = 3
        enable_rce_default = False
        if self.settings_manager:
            default_workers = int(self.settings_manager.get_setting('probe.batch_max_workers', default_workers))
            rce_pref = self.settings_manager.get_setting('probe_dialog.rce_enabled', None)
            enable_rce_default = bool(rce_pref) if rce_pref is not None else bool(self.settings_manager.get_setting('scan_dialog.rce_enabled', False))

        default_workers = max(1, min(8, default_workers))

        dialog = tk.Toplevel(self.window)
        dialog.title("Batch Probe Settings")
        dialog.transient(self.window)
        dialog.grab_set()
        self.theme.apply_to_widget(dialog, "main_window")

        tk.Label(dialog, text=f"Targets selected: {target_count}").grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="w")

        worker_var = tk.IntVar(value=default_workers)
        rce_var = tk.BooleanVar(value=enable_rce_default)
        max_dirs_var = tk.IntVar(value=config["max_directories"])
        max_files_var = tk.IntVar(value=config["max_files"])
        timeout_var = tk.IntVar(value=config["timeout_seconds"])

        def add_labeled_entry(row: int, label: str, var: tk.Variable):
            tk.Label(dialog, text=label).grid(row=row, column=0, padx=10, pady=5, sticky="w")
            tk.Entry(dialog, textvariable=var, width=10).grid(row=row, column=1, padx=10, pady=5, sticky="w")

        tk.Label(dialog, text="Worker threads (max 8):").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        tk.Entry(dialog, textvariable=worker_var, width=10).grid(row=1, column=1, padx=10, pady=5, sticky="w")

        add_labeled_entry(2, "Max directories/share:", max_dirs_var)
        add_labeled_entry(3, "Max files/directory:", max_files_var)
        add_labeled_entry(4, "Timeout per share (s):", timeout_var)

        tk.Checkbutton(dialog, text="Enable RCE analysis", variable=rce_var).grid(row=5, column=0, columnspan=2, padx=10, pady=(5, 10), sticky="w")

        result: Dict[str, Any] = {}

        def on_start():
            try:
                workers = max(1, min(8, int(worker_var.get())))
                max_dirs = max(1, int(max_dirs_var.get()))
                max_files = max(1, int(max_files_var.get()))
                timeout_val = max(1, int(timeout_var.get()))
            except (ValueError, tk.TclError):
                messagebox.showerror("Invalid Input", "Please enter numeric values for probe limits.", parent=dialog)
                return

            if self.settings_manager:
                self.settings_manager.set_setting('probe.batch_max_workers', workers)
                self.settings_manager.set_setting('probe.max_directories_per_share', max_dirs)
                self.settings_manager.set_setting('probe.max_files_per_directory', max_files)
                self.settings_manager.set_setting('probe.share_timeout_seconds', timeout_val)
                self.settings_manager.set_setting('probe_dialog.rce_enabled', bool(rce_var.get()))

            result.update({
                "worker_count": workers,
                "enable_rce": bool(rce_var.get()),
                "limits": {
                    "max_directories": max_dirs,
                    "max_files": max_files,
                    "timeout_seconds": timeout_val
                }
            })
            dialog.destroy()

        def on_cancel():
            dialog.destroy()

        button_frame = tk.Frame(dialog)
        button_frame.grid(row=6, column=0, columnspan=2, pady=(0, 10))
        tk.Button(button_frame, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=5)
        tk.Button(button_frame, text="Start", command=on_start).pack(side=tk.RIGHT)

        dialog.wait_window()
        return result or None

    # _prompt_extract_batch_settings removed - replaced by BatchExtractSettingsDialog

    def _build_selected_targets(self) -> List[Dict[str, Any]]:
        selected_servers = table.get_selected_server_data(self.tree, self.filtered_servers)
        descriptors: List[Dict[str, Any]] = []
        for server in selected_servers:
            ip_address = server.get("ip_address")
            if not ip_address:
                continue
            descriptors.append({
                "ip_address": ip_address,
                "auth_method": server.get("auth_method", ""),
                "shares": self._parse_accessible_shares(server.get("accessible_shares_list")),
                "data": server
            })
        return descriptors

    @staticmethod
    def _parse_accessible_shares(raw_value: Optional[Any]) -> List[str]:
        if not raw_value:
            return []
        if isinstance(raw_value, list):
            return [share.strip() for share in raw_value if isinstance(share, str) and share.strip()]
        return [share.strip() for share in str(raw_value).split(',') if share.strip()]

    def _start_batch_job(self, job_type: str, targets: List[Dict[str, Any]], options: Dict[str, Any]) -> None:
        if not targets:
            return

        worker_count = max(1, min(8, int(options.get("worker_count", 1))))
        cancel_event = threading.Event()
        executor = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix=f"{job_type}-batch")
        options = {**options, "worker_count": worker_count}

        self.batch_job = {
            "type": job_type,
            "targets": targets,
            "options": options,
            "executor": executor,
            "cancel_event": cancel_event,
            "results": [],
            "completed": 0,
            "total": len(targets),
            "futures": []
        }

        self._set_status(f"Running {job_type} batch (0/{len(targets)})…")
        self._update_action_buttons_state()

        for target in targets:
            future = executor.submit(self._run_batch_task, job_type, target, options, cancel_event)
            self.batch_job["futures"].append((target, future))
            future.add_done_callback(lambda fut, target=target: self.window.after(0, self._on_batch_future_done, target, fut))

        self._set_table_interaction_enabled(False)

    def _run_batch_task(self, job_type: str, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
        if cancel_event.is_set():
            return {
                "ip_address": target.get("ip_address"),
                "action": job_type,
                "status": "cancelled",
                "notes": "Cancelled"
            }

        try:
            if job_type == "probe":
                return self._execute_probe_target(target, options, cancel_event)
            if job_type == "extract":
                return self._execute_extract_target(target, options, cancel_event)
            if job_type == "pry":
                return self._execute_pry_target(target, options, cancel_event)
            raise RuntimeError(f"Unknown batch job type: {job_type}")
        except Exception as exc:
            return {
                "ip_address": target.get("ip_address"),
                "action": job_type,
                "status": "failed",
                "notes": str(exc)
            }

    def _execute_probe_target(self, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
        ip_address = target.get("ip_address")
        shares = target.get("shares", [])
        limits = options.get("limits", {})
        max_dirs = max(1, int(limits.get("max_directories", 3)))
        max_files = max(1, int(limits.get("max_files", 5)))
        timeout_seconds = max(1, int(limits.get("timeout_seconds", 10)))
        enable_rce = bool(options.get("enable_rce", False))

        username, password = details._derive_credentials(target.get("auth_method", ""))

        try:
            result = probe_runner.run_probe(
                ip_address,
                shares,
                max_directories=max_dirs,
                max_files=max_files,
                timeout_seconds=timeout_seconds,
                username=username,
                password=password,
                enable_rce_analysis=enable_rce,
                cancel_event=cancel_event,
                allow_empty=True
            )
        except probe_runner.ProbeError as exc:
            status = "cancelled" if "cancel" in str(exc).lower() else "failed"
            return {
                "ip_address": ip_address,
                "action": "probe",
                "status": status,
                "notes": str(exc)
            }

        if cancel_event.is_set():
            raise probe_runner.ProbeError("Probe cancelled")

        probe_cache.save_probe_result(ip_address, result)
        analysis = probe_patterns.attach_indicator_analysis(result, self.indicator_patterns)
        issue_detected = bool(analysis.get("is_suspicious"))
        self._handle_probe_status_update(ip_address, 'issue' if issue_detected else 'clean')

        share_count = len(result.get("shares", []))
        notes: List[str] = []
        if share_count:
            notes.append(f"{share_count} share(s)")
        else:
            notes.append("No accessible shares")

        if enable_rce and result.get("rce_analysis"):
            rce_status = result["rce_analysis"].get("status", "rce")
            notes.append(f"RCE: {rce_status}")

        if issue_detected:
            notes.append("Indicators detected")

        return {
            "ip_address": ip_address,
            "action": "probe",
            "status": "success",
            "notes": ", ".join(notes)
        }

    def _execute_extract_target(self, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
        ip_address = target.get("ip_address")
        shares = target.get("shares", [])
        if not shares:
            return {
                "ip_address": ip_address,
                "action": "extract",
                "status": "skipped",
                "notes": "No accessible shares"
            }

        base_path = Path(options.get("download_path", str(Path.home() / ".smbseek" / "quarantine"))).expanduser()
        try:
            quarantine_dir = create_quarantine_dir(ip_address, purpose="extract", base_path=base_path)
        except Exception as exc:
            return {
                "ip_address": ip_address,
                "action": "extract",
                "status": "failed",
                "notes": f"Quarantine error: {exc}"
            }

        username, password = details._derive_credentials(target.get("auth_method", ""))

        try:
            summary = extract_runner.run_extract(
                ip_address,
                shares,
                download_dir=quarantine_dir,
                username=username,
                password=password,
                max_total_bytes=options["max_total_size_mb"] * 1024 * 1024,
                max_file_bytes=options["max_file_size_mb"] * 1024 * 1024,
                max_file_count=options["max_files_per_target"],
                max_seconds=options["max_time_seconds"],
                max_depth=options["max_directory_depth"],
                allowed_extensions=options["included_extensions"],
                denied_extensions=options["excluded_extensions"],
                delay_seconds=options["download_delay_seconds"],
                connection_timeout=options["connection_timeout"],
                progress_callback=None,
                cancel_event=cancel_event
            )
            log_path = extract_runner.write_extract_log(summary)
        except extract_runner.ExtractError as exc:
            status = "cancelled" if "cancel" in str(exc).lower() else "failed"
            return {
                "ip_address": ip_address,
                "action": "extract",
                "status": status,
                "notes": str(exc)
            }

        files = summary["totals"].get("files_downloaded", 0)
        bytes_downloaded = summary["totals"].get("bytes_downloaded", 0)
        size_mb = bytes_downloaded / (1024 * 1024) if bytes_downloaded else 0
        note_parts = [f"{files} file(s)", f"{size_mb:.1f} MB"]
        if summary.get("timed_out"):
            note_parts.append("timed out")
        if summary.get("stop_reason"):
            note_parts.append(summary["stop_reason"].replace("_", " "))
        note_parts.append(f"log: {log_path}")

        return {
            "ip_address": ip_address,
            "action": "extract",
            "status": "success",
            "notes": ", ".join(note_parts)
        }

    def _execute_pry_target(self, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
        ip_address = target.get("ip_address")
        username = (options.get("username") or "").strip()
        wordlist_path = (options.get("wordlist_path") or "").strip()

        if not ip_address:
            return {
                "ip_address": ip_address,
                "action": "pry",
                "status": "failed",
                "notes": "Missing IP address"
            }
        if not username:
            return {
                "ip_address": ip_address,
                "action": "pry",
                "status": "failed",
                "notes": "Username is required"
            }
        if not wordlist_path:
            return {
                "ip_address": ip_address,
                "action": "pry",
                "status": "failed",
                "notes": "Password wordlist is required"
            }

        attempt_delay = float(options.get("attempt_delay", 1.0))
        max_attempts = int(options.get("max_attempts", 0))
        user_as_pass = bool(options.get("user_as_pass", True))
        stop_on_lockout = bool(options.get("stop_on_lockout", True))
        verbose = bool(options.get("verbose", False))

        def progress_cb(done: int, total: Optional[int]) -> None:
            total_display = total if total is not None and total > 0 else "?"
            try:
                self.window.after(0, self._set_status, f"Pry {ip_address}: tried {done}/{total_display} passwords…")
            except Exception:
                pass

        try:
            result = pry_runner.run_pry(
                ip_address=ip_address,
                username=username,
                wordlist_path=wordlist_path,
                user_as_pass=user_as_pass,
                stop_on_lockout=stop_on_lockout,
                verbose=verbose,
                attempt_delay=attempt_delay,
                max_attempts=max_attempts,
                cancel_event=cancel_event,
                progress_callback=progress_cb,
            )
        except pry_runner.PryError as exc:
            status = "cancelled" if "cancel" in str(exc).lower() else "failed"
            return {
                "ip_address": ip_address,
                "action": "pry",
                "status": status,
                "notes": str(exc)
            }
        except Exception as exc:
            return {
                "ip_address": ip_address,
                "action": "pry",
                "status": "failed",
                "notes": str(exc)
            }

        notes_text = result.notes
        if result.status == "cancelled" and result.notes.lower() == "cancelled":
            notes_text = f"Cancelled after {result.attempts} attempts"

        return {
            "ip_address": ip_address,
            "action": "pry",
            "status": result.status,
            "notes": notes_text
        }

    def _on_batch_future_done(self, target: Dict[str, Any], future: Future) -> None:
        if not self.batch_job:
            return

        try:
            result = future.result()
        except Exception as exc:
            result = {
                "ip_address": target.get("ip_address"),
                "action": self.batch_job.get("type", "batch"),
                "status": "failed",
                "notes": str(exc)
            }

        if not self.batch_job:
            return

        self.batch_job["results"].append(result)
        self.batch_job["completed"] += 1
        completed = self.batch_job["completed"]
        total = self.batch_job["total"]
        job_type = self.batch_job["type"].title()
        self._set_status(f"{job_type} batch {completed}/{total} complete")

        if completed >= total:
            self._finalize_batch_job()

    def _finalize_batch_job(self) -> None:
        if not self.batch_job:
            return

        executor = self.batch_job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)

        results = list(self.batch_job.get("results", []))
        job_type = self.batch_job.get("type", "batch")
        self.batch_job = None
        self._update_action_buttons_state()
        self._set_status(f"{job_type.title()} batch finished")
        self._flush_pending_refresh()
        self._set_table_interaction_enabled(True)
        if results:
            self._show_batch_summary(job_type, results)
        self._update_stop_button_style(False)

    def _stop_active_batch(self) -> None:
        if not self._is_batch_active():
            return
        cancel_event = self.batch_job.get("cancel_event")
        if cancel_event:
            cancel_event.set()
        executor = self.batch_job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)

        pending = []
        futures = self.batch_job.get("futures", [])
        for target, future in futures:
            if not future.done():
                future.cancel()
                pending.append(target)

        for target in pending:
            self.batch_job["results"].append({
                "ip_address": target.get("ip_address"),
                "action": self.batch_job.get("type", "batch"),
                "status": "cancelled",
                "notes": "Stopped by user"
            })

        self.batch_job["completed"] = self.batch_job["total"]
        self._set_status("Batch stopped")
        self._finalize_batch_job()

    def _is_batch_active(self) -> bool:
        return bool(self.batch_job and self.batch_job.get("completed", 0) < self.batch_job.get("total", 0))

    def _set_status(self, message: str) -> None:
        if self.status_label:
            self.status_label.configure(text=message)

    def _update_action_buttons_state(self) -> None:
        has_selection = bool(self.tree and self.tree.selection())
        batch_active = self._is_batch_active()

        new_state = tk.NORMAL if has_selection and not batch_active else tk.DISABLED
        for button in (self.probe_button, self.extract_button, self.pry_button, self.browser_button):
            if button:
                button.configure(state=new_state)

        if self.stop_button:
            self.stop_button.configure(state=tk.NORMAL if batch_active else tk.DISABLED)
            self._update_stop_button_style(batch_active)

        detail_state = tk.NORMAL if has_selection and not batch_active else tk.DISABLED
        if self.details_button:
            self.details_button.configure(state=detail_state)

        export_selected_state = tk.NORMAL if has_selection and not batch_active else tk.DISABLED
        if self.export_selected_button:
            self.export_selected_button.configure(state=export_selected_state)

        export_all_state = tk.NORMAL if not batch_active else tk.DISABLED
        if self.export_all_button:
            self.export_all_button.configure(state=export_all_state)

        self._update_context_menu_state()

    def _update_stop_button_style(self, batch_active: bool) -> None:
        if not self.stop_button:
            return

        if not hasattr(self, "_stop_button_original_style"):
            self._stop_button_original_style = {
                "bg": self.stop_button.cget("bg"),
                "fg": self.stop_button.cget("fg"),
                "activebackground": self.stop_button.cget("activebackground"),
                "activeforeground": self.stop_button.cget("activeforeground"),
                "text": self.stop_button.cget("text")
            }

        if batch_active:
            self.stop_button.configure(
                bg="#b00020",
                fg="#ffffff",
                activebackground="#d32f2f",
                activeforeground="#ffffff",
                text="⏹ Stop Batch (running)"
            )
        else:
            original = getattr(self, "_stop_button_original_style", None)
            if original:
                self.stop_button.configure(
                    bg=original.get("bg"),
                    fg=original.get("fg"),
                    activebackground=original.get("activebackground"),
                    activeforeground=original.get("activeforeground"),
                    text=original.get("text", "⏹ Stop Batch")
                )

    def _update_context_menu_state(self) -> None:
        if not self.context_menu:
            return
        has_selection = bool(self.tree and self.tree.selection())
        batch_active = self._is_batch_active()
        probe_state = tk.NORMAL if has_selection and not batch_active else tk.DISABLED
        extract_state = probe_state
        browser_state = probe_state
        self.context_menu.entryconfig(0, state=probe_state)
        self.context_menu.entryconfig(1, state=extract_state)
        self.context_menu.entryconfig(2, state=probe_state)
        self.context_menu.entryconfig(3, state=browser_state)

    def _show_context_menu(self, event) -> str:
        if not self.tree or not self.context_menu:
            return "break"
        if self._context_menu_visible:
            self._hide_context_menu()
        row = self.tree.identify_row(event.y)
        if not row:
            return "break"
        selected = set(self.tree.selection())
        if row not in selected:
            self.tree.selection_set(row)
        self._update_action_buttons_state()
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()
        self._context_menu_visible = True
        self._install_context_dismiss_handlers()
        return "break"

    def _install_context_dismiss_handlers(self) -> None:
        self._remove_context_dismiss_handlers()
        for sequence in ("<Button-1>", "<Button-3>"):
            bind_id = self.tree.bind(sequence, self._handle_context_dismiss_click, add="+")
            if bind_id:
                self._context_menu_bindings.append((sequence, bind_id))

    def _remove_context_dismiss_handlers(self) -> None:
        if not self._context_menu_bindings:
            return
        for sequence, bind_id in self._context_menu_bindings:
            try:
                self.tree.unbind(sequence, bind_id)
            except Exception:
                pass
        self._context_menu_bindings = []

    def _handle_context_dismiss_click(self, event=None):
        self._hide_context_menu()

    def _hide_context_menu(self) -> None:
        if not self._context_menu_visible or not self.context_menu:
            return
        try:
            self.context_menu.unpost()
        except Exception:
            pass
        self._context_menu_visible = False
        self._remove_context_dismiss_handlers()

    def _show_batch_summary(self, job_type: str, results: List[Dict[str, Any]]) -> None:
        dialog = tk.Toplevel(self.window)
        dialog.title(f"{job_type.title()} Batch Summary")
        dialog.geometry("700x400")
        dialog.transient(self.window)
        self.theme.apply_to_widget(dialog, "main_window")

        columns = ("ip", "action", "status", "notes")
        tree = ttk.Treeview(dialog, columns=columns, show="headings")
        headings = {
            "ip": "IP Address",
            "action": "Action",
            "status": "Result",
            "notes": "Notes"
        }
        for col in columns:
            tree.heading(col, text=headings[col])
            width = 130 if col != "notes" else 360
            tree.column(col, width=width, anchor="w")

        for entry in results:
            tree.insert(
                "",
                "end",
                values=(
                    entry.get("ip_address", "-"),
                    entry.get("action", job_type).title(),
                    entry.get("status", "unknown").title(),
                    entry.get("notes", "")
                )
            )

        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        button_frame = tk.Frame(dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        def export_summary():
            self._export_batch_summary(results, job_type, dialog)

        tk.Button(button_frame, text="Save CSV", command=export_summary).pack(side=tk.RIGHT, padx=(0, 5))
        tk.Button(button_frame, text="Close", command=dialog.destroy).pack(side=tk.RIGHT)

    def _export_batch_summary(self, results: List[Dict[str, Any]], job_type: str, parent: tk.Toplevel) -> None:
        path = filedialog.asksaveasfilename(
            parent=parent,
            title="Save Batch Summary",
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not path:
            return

        with open(path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["ip_address", "action", "status", "notes"])
            for entry in results:
                writer.writerow([
                    entry.get("ip_address", ""),
                    entry.get("action", job_type),
                    entry.get("status", ""),
                    entry.get("notes", "")
                ])

        messagebox.showinfo("Summary Saved", f"Saved batch summary to {path}", parent=parent)

    def _flush_pending_refresh(self) -> None:
        if not self._pending_table_refresh:
            return
        self._apply_filters(force=True)
        if self._pending_selection:
            self._restore_selection(self._pending_selection)
        self._pending_table_refresh = False
        self._pending_selection = []

    # Probe status helpers

    def _attach_probe_status(self, servers: List[Dict[str, Any]]) -> None:
        if not self.settings_manager:
            for server in servers:
                server["probe_status"] = 'unprobed'
                server["probe_status_emoji"] = self._probe_status_to_emoji('unprobed')
            return

        for server in servers:
            ip = server.get("ip_address")
            status = self._determine_probe_status(ip)
            server["probe_status"] = status
            server["probe_status_emoji"] = self._probe_status_to_emoji(status)

    def _determine_probe_status(self, ip_address: Optional[str]) -> str:
        if not ip_address:
            return 'unprobed'

        cached_result = probe_cache.load_probe_result(ip_address)
        derived_status = 'unprobed'
        if cached_result:
            if self.indicator_patterns:
                analysis = probe_patterns.attach_indicator_analysis(cached_result, self.indicator_patterns)
            else:
                analysis = {"is_suspicious": False}
            if analysis.get('is_suspicious'):
                derived_status = 'issue'
            else:
                derived_status = 'clean'

        stored_status = self.settings_manager.get_probe_status(ip_address)
        status = derived_status if derived_status != 'unprobed' else stored_status

        if status != stored_status:
            self.settings_manager.set_probe_status(ip_address, status)

        self.probe_status_map[ip_address] = status
        return status

    @staticmethod
    def _probe_status_to_emoji(status: str) -> str:
        mapping = {
            'clean': '✔',
            'issue': '✖',
            'unprobed': '○'
        }
        return mapping.get(status, '⚪')

    def _handle_probe_status_update(self, ip_address: str, status: str) -> None:
        if not ip_address:
            return
        if self.settings_manager:
            self.settings_manager.set_probe_status(ip_address, status)
        self.probe_status_map[ip_address] = status

        for server in self.all_servers:
            if server.get("ip_address") == ip_address:
                server["probe_status"] = status
                server["probe_status_emoji"] = self._probe_status_to_emoji(status)

        if self._is_batch_active():
            if not self._pending_table_refresh:
                self._pending_selection = self._get_selected_ips()
            self._pending_table_refresh = True
        else:
            selected_ips = self._get_selected_ips()
            self._apply_filters()
            self._restore_selection(selected_ips)

    def _get_selected_ips(self) -> List[str]:
        ips = []
        for item in self.tree.selection():
            values = self.tree.item(item)["values"]
            if len(values) >= 4:
                ips.append(values[3])
        return ips

    def _restore_selection(self, ip_addresses: List[str]) -> None:
        if not ip_addresses:
            return
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            if len(values) >= 4 and values[3] in ip_addresses:
                self.tree.selection_add(item)

    # Mode and filter management
    def _toggle_mode(self) -> None:
        """Toggle between simple and advanced mode."""
        self.is_advanced_mode = not self.is_advanced_mode
        self._update_mode_display()

    def _update_mode_display(self) -> None:
        """Update display based on current mode using filters module."""
        if self.is_advanced_mode:
            self.mode_button.configure(text="📊 Simple")
            self.filter_frame.pack(fill=tk.X, padx=10, pady=(0, 5), before=self.table_frame)
            if self.filter_widgets and 'advanced_filters_frame' in self.filter_widgets:
                filters.update_mode_display(self.filter_widgets['advanced_filters_frame'], True)
        else:
            self.mode_button.configure(text="🔧 Advanced")
            self.filter_frame.pack(fill=tk.X, padx=10, pady=(0, 5), before=self.table_frame)
            if self.filter_widgets and 'advanced_filters_frame' in self.filter_widgets:
                filters.update_mode_display(self.filter_widgets['advanced_filters_frame'], False)

    def _clear_search(self) -> None:
        """Clear search text."""
        self.search_text.set("")
        self._apply_filters()

    def _toggle_show_all_results(self) -> None:
        """Toggle between showing recent results and all results."""
        if self.date_filter.get() == "Since Last Scan":
            # Currently showing recent, switch to all
            self.date_filter.set("All")
            if self.filter_widgets and 'show_all_button' in self.filter_widgets:
                self.filter_widgets['show_all_button'].configure(text="📊 Show Recent Results")
        else:
            # Currently showing all, switch to recent
            if self.last_scan_time:
                self.date_filter.set("Since Last Scan")
                if self.filter_widgets and 'show_all_button' in self.filter_widgets:
                    self.filter_widgets['show_all_button'].configure(text="📈 Show All Results")

        self._apply_filters()

    def _reset_filters(self) -> None:
        """Reset all filters to default values."""
        self.search_text.set("")
        self.date_filter.set("All")
        self.shares_filter.set(False)
        self.favorites_only.set(False)
        self.avoid_only.set(False)
        self._apply_filters()

    def _refresh_data(self) -> None:
        """Refresh data from database."""
        self._load_data()

    def _close_window(self) -> None:
        """Close the server list window."""
        if self._is_batch_active():
            self._stop_active_batch()
        self.window.destroy()

    # Public API methods for external compatibility
    def apply_recent_discoveries_filter(self) -> None:
        """
        Programmatically filter server list to show only servers from most recent scan.

        Called when user clicks "View Details" on Recent Discoveries dashboard card.
        """
        try:
            # Clear existing filters first
            self.search_text.set("")
            self.date_filter.set("All")

            # Load servers with recent scan filter
            servers, total_count = self.db_reader.get_server_list(
                limit=10000,
                offset=0,
                recent_scan_only=True
            )

            self.all_servers = servers

            # Apply filters (should be no-op since we cleared them, but updates display)
            self._apply_filters()

            # Update count display to indicate filtered view
            self.count_label.configure(text=f"Recent Scan: {len(self.all_servers)} servers discovered")

            # Add visual indicator that this is a filtered view
            if hasattr(self, 'status_label'):
                self.status_label.configure(
                    text="📊 Showing servers from most recent scan session",
                    fg=self.theme.colors.get("accent", "#007acc")
                )

        except Exception as e:
            messagebox.showerror(
                "Filter Error",
                f"Failed to apply recent discoveries filter: {e}"
            )


# Module compatibility function
def open_server_list_window(parent: tk.Widget, db_reader: DatabaseReader,
                           window_data: Dict[str, Any] = None, settings_manager = None) -> None:
    """
    Open server list browser window.

    Args:
        parent: Parent widget
        db_reader: Database reader instance
        window_data: Optional data for window initialization
        settings_manager: Optional settings manager for favorites functionality
    """
    ServerListWindow(parent, db_reader, window_data, settings_manager)
