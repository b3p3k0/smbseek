"""
Main Server List Window

Orchestrates all server list functionality using extracted modules.
Maintains all shared state and coordinates between components.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime
import sqlite3
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
    from gui.utils.template_store import TemplateStore
    from gui.components.file_browser_window import FileBrowserWindow
    from gui.components.pry_dialog import PryDialog
    from gui.components.pry_status_dialog import BatchStatusDialog
    from shared.db_migrations import run_migrations
except ImportError:
    # Handle relative imports when running from gui directory
    from utils.database_access import DatabaseReader
    from utils.style import get_theme
    from utils.data_export_engine import get_export_engine
    from utils.scan_manager import get_scan_manager
    from utils.dialog_helpers import ensure_dialog_focus
    from utils.template_store import TemplateStore
    from components.file_browser_window import FileBrowserWindow
    from components.pry_dialog import PryDialog
    from components.pry_status_dialog import BatchStatusDialog
    from shared.db_migrations import run_migrations

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
    FILTER_TEMPLATE_PLACEHOLDER = "Select filter template..."

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

        # Favorites / avoid / probe filter toggles
        self.favorites_only = tk.BooleanVar()
        self.exclude_avoid = tk.BooleanVar()
        self.probed_only = tk.BooleanVar()
        self.exclude_compromised = tk.BooleanVar()

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

        # Country filter state
        self.country_listbox = None
        self.country_code_list = []

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
        self.delete_button = None
        self._delete_menu_index = None  # Store context menu index
        self._delete_in_progress = False  # Flag to prevent concurrent deletes
        self.table_overlay = None
        self.table_overlay_label = None
        self.pry_status_button = None
        self.batch_status_dialog = None
        self._stop_button_original_style = None
        self._context_menu_visible = False
        self._context_menu_bindings = []
        self.filter_template_var = tk.StringVar()
        self._filter_template_label_to_slug: Dict[str, str] = {}
        self._selected_filter_template_slug: Optional[str] = None
        self.filter_template_store = TemplateStore(
            settings_manager=None,
            base_dir=Path.home() / ".smbseek" / "filter_templates",
            seed_dir=None
        )

        # Date filtering state
        self.filter_recent = self.window_data.get("filter_recent", False)
        self.last_scan_time = None

        # Data management
        self.all_servers = []
        self.filtered_servers = []
        self.selected_servers = []
        self.active_jobs: Dict[str, Dict[str, Any]] = {}
        self._pending_table_refresh = False
        self._pending_selection = []

        # Window state
        self.is_advanced_mode = False
        self.pry_status_dialog = None

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

        # Modeless window; do not force stacking above dashboard

        # Center window
        self._center_window()

        # Build UI components
        self._create_header()
        self._create_filter_panel()
        self._create_server_table()
        self._create_button_panel()

        # Bind events
        self._setup_event_handlers()

        # Ensure window appears on top and gains focus (without forcing modal grab)
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

    def _create_filter_panel(self) -> None:
        """Create filtering controls panel using filters module."""
        # Load persisted filter preferences before building UI
        self._load_filter_preferences()

        # Prepare filter variables
        filter_vars = {
            'search_text': self.search_text,
            'date_filter': self.date_filter,
            'shares_filter': self.shares_filter,
            'favorites_only': self.favorites_only,
            'exclude_avoid': self.exclude_avoid,
            'probed_only': self.probed_only,
            'exclude_compromised': self.exclude_compromised
        }

        # Prepare callbacks
        filter_callbacks = {
            'on_search_changed': self._apply_filters,
            'on_date_filter_changed': self._apply_filters,
            'on_shares_filter_changed': self._apply_filters,
            'on_favorites_only_changed': self._apply_filters,
            'on_exclude_avoid_changed': self._apply_filters,
            'on_probed_only_changed': self._apply_filters,
            'on_exclude_compromised_changed': self._apply_filters,
            'on_country_filter_changed': self._apply_filters,
            'on_clear_search': self._clear_search,
            'on_reset_filters': self._reset_filters,
            'on_toggle_mode': self._toggle_mode,
            'on_filter_template_selected': self._on_filter_template_selected,
            'on_save_filter_template': self._on_save_filter_template
        }

        # Add show all toggle if needed
        if self.filter_recent:
            filter_callbacks['on_show_all_toggle'] = self._toggle_show_all_results

        # Create filter panel using module
        self.filter_frame, self.filter_widgets = filters.create_filter_panel(
            self.window, self.theme, filter_vars, filter_callbacks
        )

        # Wire template dropdown variable and populate options
        if 'filter_template_dropdown' in self.filter_widgets:
            dropdown = self.filter_widgets['filter_template_dropdown']
            dropdown.configure(textvariable=self.filter_template_var)
            self._refresh_filter_templates()

        # Capture mode toggle reference from filter panel
        if 'mode_button' in self.filter_widgets:
            self.mode_button = self.filter_widgets['mode_button']

        # Disable favorites/avoid checkboxes if no settings manager
        if not self.settings_manager:
            if 'favorites_checkbox' in self.filter_widgets:
                self.filter_widgets['favorites_checkbox'].configure(state="disabled")
            if 'exclude_avoid_checkbox' in self.filter_widgets:
                self.filter_widgets['exclude_avoid_checkbox'].configure(state="disabled")

        # Extract country listbox reference and populate it
        if 'country_listbox' in self.filter_widgets:
            self.country_listbox = self.filter_widgets['country_listbox']
            # Populate country filter with codes from database
            self._populate_country_filter()
            # Restore saved country filter selections from settings
            self._restore_country_filter_selections()

        # Pack filter frame (shown/hidden based on mode)
        self._update_mode_display()

    def _create_server_table(self) -> None:
        """Create server data table using table module."""
        # Prepare callbacks
        table_callbacks = {
            'on_selection_changed': self._on_selection_changed,
            'on_double_click': self._on_double_click,
            'on_treeview_click': self._on_treeview_click,
            'on_favorite_toggle': self._on_favorite_toggle,
            'on_avoid_toggle': self._on_avoid_toggle,
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
        self.context_menu.add_command(label="🗂️ Browse Selected", command=self._on_file_browser_selected)
        # Store index before adding Delete item (context menu currently has 4 items: 0-3)
        self._delete_menu_index = 4  # Will be the 5th item (index 4)
        self.context_menu.add_command(label="🗑️ Delete Selected", command=self._on_delete_selected)
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

        # Hidden by default; becomes visible to reopen batch status dialog
        self.pry_status_button = tk.Button(
            info_container,
            text="Show Task Status",
            command=self._show_pry_status_dialog
        )
        self.theme.apply_to_widget(self.pry_status_button, "button_secondary")
        self.pry_status_button.pack(anchor="w", pady=(4, 0))
        self.pry_status_button.pack_forget()

        # Right side - action buttons
        button_container = tk.Frame(self.button_frame)
        self.theme.apply_to_widget(button_container, "main_window")
        button_container.pack(side=tk.RIGHT)

        # Batch/quick action buttons
        self.details_button = tk.Button(
            button_container,
            text="📋 View Details",
            command=self._view_server_details
        )
        self.theme.apply_to_widget(self.details_button, "button_secondary")
        self.details_button.pack(side=tk.LEFT, padx=(0, 8))

        self.probe_button = tk.Button(
            button_container,
            text="🔍 Probe Selected",
            command=self._on_probe_selected,
            state=tk.DISABLED
        )
        # Use secondary styling to match the rest of the group (avoid blue highlight)
        self.theme.apply_to_widget(self.probe_button, "button_secondary")
        self.probe_button.pack(side=tk.LEFT, padx=(0, 8))

        self.extract_button = tk.Button(
            button_container,
            text="📦 Extract Selected",
            command=self._on_extract_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.extract_button, "button_secondary")
        self.extract_button.pack(side=tk.LEFT, padx=(0, 8))

        self.browser_button = tk.Button(
            button_container,
            text="🗂️ Browse Selected",
            command=self._on_file_browser_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.browser_button, "button_secondary")
        self.browser_button.pack(side=tk.LEFT, padx=(0, 8))

        self.pry_button = tk.Button(
            button_container,
            text="🔓 Pry Selected",
            command=self._on_pry_selected,
            state=tk.DISABLED
        )
        self.theme.apply_to_widget(self.pry_button, "button_secondary")
        self.pry_button.pack(side=tk.LEFT, padx=(0, 8))

        self.delete_button = tk.Button(
            button_container,
            text="🗑️ Delete Selected",
            command=self._on_delete_selected,
            state=tk.DISABLED
        )
        # Force a red theme to signal destructive action
        self.theme.apply_to_widget(self.delete_button, "button_danger")
        # Double padding before delete for visual separation; standard after
        self.delete_button.pack(side=tk.LEFT, padx=(16, 8))

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

        # Apply country filter
        selected_codes = self._get_selected_country_codes()
        if selected_codes:
            filtered = filters.apply_country_filter(filtered, selected_codes)

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

        # Apply exclude avoid filter
        if self.exclude_avoid.get():
            filtered = filters.apply_exclude_avoid_filter(filtered, True, self.settings_manager)

        # Apply probed-only filter
        if self.probed_only.get():
            filtered = filters.apply_probed_filter(filtered, True)

        # Apply exclude compromised filter
        if self.exclude_compromised.get():
            filtered = filters.apply_exclude_compromised_filter(filtered, True)

        self.filtered_servers = filtered

        # Update table display using table module
        table.update_table_display(self.tree, self.filtered_servers, self.settings_manager)

        # Update count display
        self.count_label.configure(
            text=f"Showing: {len(self.filtered_servers)} of {len(self.all_servers)} servers"
        )

        self._update_action_buttons_state()
        self._persist_filter_preferences()

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

            # Attach denied share counts
            try:
                denied_map = self.db_reader.get_denied_share_counts()
            except Exception:
                denied_map = {}

            for server in servers:
                ip = server.get("ip_address")
                server["denied_shares_count"] = denied_map.get(ip, 0) if ip else 0

            self.all_servers = servers
            self._attach_probe_status(self.all_servers)

            # Load denied share lists for details rendering
            try:
                for server in self.all_servers:
                    ip = server.get("ip_address")
                    server["denied_shares_list"] = self.db_reader.get_denied_shares(ip) if ip else []
            except Exception:
                for server in self.all_servers:
                    server["denied_shares_list"] = []

            # Set initial date filter if requested
            if self.filter_recent and self.last_scan_time:
                self.date_filter.set("Since Last Scan")

            # Reset sort state for fresh dataset
            self._reset_sort_state()

            # Repopulate country filter with fresh data
            # This handles new scans or deletions that change available countries
            # Note: _populate_country_filter preserves current selections
            self._populate_country_filter()

            # Apply initial filters and display data
            self._apply_filters()

            # Update count display
            self.count_label.configure(text=f"Total: {len(self.all_servers)} servers")

        except Exception as e:
            messagebox.showerror(
                "Data Loading Error",
                f"Failed to load server data:\n{str(e)}",
                parent=self.window
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

    def _on_favorite_toggle(self, ip: str, is_favorite: bool) -> None:
        if not ip or not self.settings_manager:
            return
        try:
            self.db_reader.upsert_user_flags(ip, favorite=is_favorite)
        except Exception:
            pass

    def _on_avoid_toggle(self, ip: str, is_avoid: bool) -> None:
        if not ip or not self.settings_manager:
            return
        try:
            self.db_reader.upsert_user_flags(ip, avoid=is_avoid)
        except Exception:
            pass

    def _on_double_click(self, event) -> None:
        """Handle double-click on table row using table module."""
        table.handle_double_click(
            self.tree, event, self.filtered_servers,
            self._show_server_detail_popup, self.window
        )

    def _on_treeview_click(self, event) -> None:
        """Handle treeview clicks using table module."""
        callbacks = {
            'on_favorites_filter_changed': self._apply_filters,
            'on_avoid_filter_changed': self._apply_filters,
            'on_favorite_toggle': self._on_favorite_toggle,
            'on_avoid_toggle': self._on_avoid_toggle
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
            messagebox.showwarning("No Selection", "Please select a server to view details.", parent=self.window)
            return

        if len(selected_items) > 1:
            messagebox.showwarning("Multiple Selection", "Please select only one server to view details.", parent=self.window)
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
            messagebox.showerror("Error", "Server data not found.", parent=self.window)
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
            indicator_patterns=self.indicator_patterns,
            probe_callback=self._launch_probe_from_detail,
            extract_callback=self._launch_extract_from_detail,
            browse_callback=self._launch_browse_from_detail
        )

    def _export_selected_servers(self) -> None:
        """Export selected servers using export module."""
        selected_data = table.get_selected_server_data(self.tree, self.filtered_servers)
        if not selected_data:
            messagebox.showwarning("No Selection", "Please select servers to export.", parent=self.window)
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
        targets = self._build_selected_targets()
        self._launch_probe_workflow(targets)

    def _on_extract_selected(self) -> None:
        self._hide_context_menu()
        targets = self._build_selected_targets()
        self._launch_extract_workflow(targets)

    def _on_pry_selected(self) -> None:
        self._hide_context_menu()
        targets = self._build_selected_targets()
        if len(targets) != 1:
            messagebox.showwarning("Select one server", "Choose exactly one server to run Pry.", parent=self.window)
            return

        target = targets[0]
        ip_addr = target.get("ip_address") or ""

        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path and hasattr(self.settings_manager, "get_smbseek_config_path"):
                config_path = self.settings_manager.get_smbseek_config_path()

        # Build share choices from share_access data
        shares = []
        try:
            shares = self.db_reader.get_denied_shares(ip_addr, limit=100)
            # Also include accessible shares for completeness
            shares += self.db_reader.get_accessible_shares(ip_addr)
            # Mark accessible flag for combobox badge
            for s in shares:
                s.setdefault("accessible", bool(s.get("permissions") or False))
        except Exception:
            shares = []

        dialog = PryDialog(
            parent=self.window,
            theme=self.theme,
            settings_manager=self.settings_manager,
            config_path=config_path,
            target_label=ip_addr,
            shares=shares
        )
        dialog_result = dialog.show()
        if not dialog_result:
            return

        options = dialog_result.get("options", {})
        options.update({
            "username": dialog_result.get("username", ""),
            "share_name": dialog_result.get("share_name", ""),
            "wordlist_path": dialog_result.get("wordlist_path", ""),
            "worker_count": 1
        })
        self._start_batch_job("pry", [target], options)

    def _on_file_browser_selected(self) -> None:
        self._hide_context_menu()
        targets = self._build_selected_targets()
        if not targets:
            messagebox.showwarning("No Selection", "Please select a server to browse.", parent=self.window)
            return
        if len(targets) != 1:
            messagebox.showwarning("Select one server", "Choose exactly one server to browse.", parent=self.window)
            return

        self._launch_browse_workflow(targets[0])

    def _on_delete_selected(self) -> None:
        """Handle delete selected servers action."""
        self._hide_context_menu()

        # Validate selection exists
        targets = self._build_selected_targets()
        if not targets:
            messagebox.showwarning("No Selection", "Please select servers to delete.", parent=self.window)
            return

        # Check if delete already in progress
        if getattr(self, '_delete_in_progress', False):
            messagebox.showinfo("Delete In Progress", "A delete operation is already running.", parent=self.window)
            return

        # Check if batch jobs are active
        if self._is_batch_active():
            messagebox.showinfo(
                "Batch Active",
                "Cannot delete servers while a batch operation is running. "
                "Please wait for the batch to complete or stop it first.",
                parent=self.window
            )
            return

        # Build target IP list (deduplicate)
        target_ips = list(set(target.get("ip_address") for target in targets if target.get("ip_address")))

        if not target_ips:
            messagebox.showwarning("No Valid IPs", "No valid IP addresses found in selection.", parent=self.window)
            return

        # Check for favorites in selection
        favorite_ips = [target.get("ip_address") for target in targets if target.get("favorite")]

        # Show confirmation dialog
        if favorite_ips:
            # Favorites present - show explicit warning
            favorite_list = "\n".join(f"• {ip}" for ip in favorite_ips)
            message = (
                f"You are about to delete {len(target_ips)} servers including "
                f"{len(favorite_ips)} favorite(s):\n\n{favorite_list}\n\n"
                f"This action cannot be undone. Continue?"
            )
            title = "Delete Favorite Servers?"
        else:
            # No favorites - brief confirmation
            message = f"Delete {len(target_ips)} selected servers? This action cannot be undone."
            title = "Delete Servers?"

        confirmed = messagebox.askyesno(title, message, parent=self.window)
        if not confirmed:
            return

        # Start background delete operation
        self._delete_in_progress = True
        self._set_status(f"Deleting {len(target_ips)} servers...")
        self._update_action_buttons_state()

        # Create executor and submit delete task
        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="delete-servers")
        future = executor.submit(self._run_delete_operation, target_ips)
        future.add_done_callback(lambda f: self.window.after(0, self._on_delete_complete, f))

    def _run_delete_operation(self, target_ips: List[str]) -> Dict[str, Any]:
        """Background thread worker for delete operation."""
        try:
            # Call database delete
            results = self.db_reader.bulk_delete_servers(target_ips)

            # If successful, clear probe cache for deleted IPs only
            if results.get("deleted_ips"):
                for ip in results["deleted_ips"]:
                    try:
                        probe_cache.clear_probe_result(ip)
                    except Exception:
                        pass  # Non-critical, continue

            return results

        except Exception as e:
            # Return error in results dict
            return {
                "deleted_count": 0,
                "deleted_ips": [],
                "error": str(e)
            }

    def _on_delete_complete(self, future) -> None:
        """Handle delete completion on UI thread."""
        try:
            results = future.result()

            deleted_count = results.get("deleted_count", 0)
            error = results.get("error")

            # Show results messagebox with partial success handling
            if deleted_count > 0 and error is None:
                # Full success
                messagebox.showinfo(
                    "Delete Complete",
                    f"Deleted {deleted_count} servers successfully.",
                    parent=self.window
                )
            elif deleted_count > 0 and error is not None:
                # Partial success
                messagebox.showwarning(
                    "Partial Delete",
                    f"Deleted {deleted_count} servers, but errors occurred:\n\n{error}",
                    parent=self.window
                )
            elif deleted_count == 0 and error is not None:
                # Full failure
                messagebox.showerror(
                    "Delete Failed",
                    f"Failed to delete servers:\n\n{error}",
                    parent=self.window
                )
            else:
                # No-op (shouldn't happen)
                messagebox.showinfo(
                    "Delete Complete",
                    "No servers were deleted.",
                    parent=self.window
                )

            # If any servers were deleted, refresh table
            if deleted_count > 0:
                self.db_reader.clear_cache()
                self._load_data()
                self._apply_filters(force=True)

            # Clear selection BEFORE re-enabling buttons
            if self.tree:
                self.tree.selection_remove(self.tree.selection())

            # Re-enable UI
            self._delete_in_progress = False
            self._update_action_buttons_state()
            self._set_status("Idle")

        except Exception as e:
            # Handle worker thread exceptions
            messagebox.showerror(
                "Delete Error",
                f"An error occurred during delete:\n\n{str(e)}",
                parent=self.window
            )
            self._delete_in_progress = False
            self._update_action_buttons_state()
            self._set_status("Idle")

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

    # Shared workflow launchers (used by main window + detail popup)

    def _launch_probe_workflow(self, targets: List[Dict[str, Any]]) -> None:
        if not targets:
            messagebox.showwarning("No Selection", "Please select at least one server to probe.", parent=self.window)
            return

        dialog_config = self._prompt_probe_batch_settings(len(targets))
        if not dialog_config:
            return

        self._start_batch_job("probe", targets, dialog_config)

    def _launch_extract_workflow(self, targets: List[Dict[str, Any]]) -> None:
        if not targets:
            messagebox.showwarning("No Selection", "Please select at least one server to extract from.", parent=self.window)
            return

        config_path = self._get_config_path()

        dialog_config = BatchExtractSettingsDialog(
            parent=self.window,
            theme=self.theme,
            settings_manager=self.settings_manager,
            config_path=config_path,
            config_editor_callback=self._open_config_editor,
            mode="on-demand",
            target_count=len(targets)
        ).show()

        if not dialog_config:
            return

        self._start_batch_job("extract", targets, dialog_config)

    def _launch_browse_workflow(self, target: Dict[str, Any]) -> None:
        ip_addr = target.get("ip_address")
        if not ip_addr:
            messagebox.showerror("Missing IP", "Unable to determine IP for selected server.", parent=self.window)
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

        share_creds = {}
        try:
            if self.db_reader:
                creds_rows = self.db_reader.get_share_credentials(ip_addr)
                for row in creds_rows:
                    raw_name = row.get("share_name")
                    cleaned_name = _clean_share_name(raw_name) if raw_name else ""
                    if cleaned_name:
                        share_creds[cleaned_name] = {
                            "username": row.get("username") or "",
                            "password": row.get("password") or "",
                            "source": row.get("source") or "",
                            "last_verified_at": row.get("last_verified_at")
                        }
        except Exception:
            share_creds = {}

        config_path = self._get_config_path()

        FileBrowserWindow(
            parent=self.window,
            ip_address=ip_addr,
            shares=share_names,
            auth_method=target.get("auth_method", ""),
            config_path=config_path,
            db_reader=self.db_reader,
            theme=self.theme,
            settings_manager=self.settings_manager,
            share_credentials=share_creds,
        )

    def _launch_probe_from_detail(self, server_data: Dict[str, Any]) -> None:
        target = self._server_data_to_target(server_data)
        if target:
            self._launch_probe_workflow([target])

    def _launch_extract_from_detail(self, server_data: Dict[str, Any]) -> None:
        target = self._server_data_to_target(server_data)
        if target:
            self._launch_extract_workflow([target])

    def _launch_browse_from_detail(self, server_data: Dict[str, Any]) -> None:
        target = self._server_data_to_target(server_data)
        if target:
            self._launch_browse_workflow(target)

    def _open_config_editor(self, config_path: str) -> None:
        """Open configuration editor window."""
        try:
            from gui.components.config_editor_window import open_config_editor_window
        except ImportError:
            try:
                from components.config_editor_window import open_config_editor_window
            except Exception as exc:
                messagebox.showerror("Configuration Editor Error", f"Unable to load config editor: {exc}", parent=self.window)
                return
        try:
            open_config_editor_window(self.window, config_path)
        except Exception as exc:
            messagebox.showerror("Configuration Editor Error", f"Failed to open configuration editor:\n{exc}", parent=self.window)

    # _prompt_extract_batch_settings removed - replaced by BatchExtractSettingsDialog

    def _build_selected_targets(self) -> List[Dict[str, Any]]:
        selected_servers = table.get_selected_server_data(self.tree, self.filtered_servers)
        descriptors: List[Dict[str, Any]] = []
        for server in selected_servers:
            target = self._server_data_to_target(server)
            if target:
                descriptors.append(target)
        return descriptors

    def _server_data_to_target(self, server_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        ip_address = server_data.get("ip_address")
        if not ip_address:
            return None
        return {
            "ip_address": ip_address,
            "auth_method": server_data.get("auth_method", ""),
            "shares": self._parse_accessible_shares(server_data.get("accessible_shares_list")),
            "data": server_data
        }

    @staticmethod
    def _parse_accessible_shares(raw_value: Optional[Any]) -> List[str]:
        if not raw_value:
            return []
        if isinstance(raw_value, list):
            return [share.strip() for share in raw_value if isinstance(share, str) and share.strip()]
        return [share.strip() for share in str(raw_value).split(',') if share.strip()]

    @staticmethod
    def _is_table_lock_required(job_type: str) -> bool:
        """Return True if the server table should be locked for this batch type."""
        # Concurrency-friendly: do not lock the table for any job
        return False

    @staticmethod
    def _normalize_share_name(name: str) -> str:
        """
        Strip badges or slashes from share labels (e.g., 'share (denied)' -> 'share').
        """
        if not name:
            return ""
        cleaned = name.split(" (")[0]
        return cleaned.strip().strip("\\/").strip()

    def _get_config_path(self) -> Optional[str]:
        config_path = None
        if self.settings_manager:
            config_path = self.settings_manager.get_setting('backend.config_path', None)
            if not config_path and hasattr(self.settings_manager, "get_smbseek_config_path"):
                config_path = self.settings_manager.get_smbseek_config_path()
        return config_path

    def _start_batch_job(self, job_type: str, targets: List[Dict[str, Any]], options: Dict[str, Any]) -> None:
        if not targets:
            return

        # Enforce max concurrent jobs
        if len(self.active_jobs) >= 3:
            messagebox.showinfo("Too many tasks", "Please wait for an existing task to finish before starting another.")
            return

        # Enforce per-host exclusivity
        active_hosts = set()
        for job in self.active_jobs.values():
            for t in job.get("targets", []):
                ip = t.get("ip_address")
                if ip:
                    active_hosts.add(ip)
        for t in targets:
            ip = t.get("ip_address")
            if ip and ip in active_hosts:
                messagebox.showinfo("Task already running", f"A task is already running for host {ip}. Please wait or stop it first.")
                return

        worker_count = max(1, min(8, int(options.get("worker_count", 1))))
        cancel_event = threading.Event()
        executor = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix=f"{job_type}-batch")
        options = {**options, "worker_count": worker_count}

        job_id = f"{job_type}-{len(self.active_jobs)+1}-{int(threading.get_ident())}"

        job_record = {
            "id": job_id,
            "type": job_type,
            "targets": targets,
            "options": options,
            "executor": executor,
            "cancel_event": cancel_event,
            "results": [],
            "completed": 0,
            "total": len(targets),
            "futures": [],
            "dialog": None,
        }
        self.active_jobs[job_id] = job_record

        self._set_status(f"Running {job_type} batch (0/{len(targets)})…")
        self._update_action_buttons_state()

        if job_type == "pry":
            host_label = targets[0].get("ip_address") or "-"
            dialog = self._init_batch_status_dialog(
                "pry",
                {
                    "Host": host_label,
                    "Username": (options.get("username") or "").strip(),
                    "Share": (options.get("share_name") or "").strip(),
                    "Wordlist": Path(options.get("wordlist_path", "")).name if options.get("wordlist_path") else "-",
                },
                cancel_event,
                total=len(targets),
            )
            job_record["dialog"] = dialog
        elif job_type == "probe":
            dialog = self._init_batch_status_dialog(
                "probe",
                {
                    "Targets": str(len(targets)),
                    "Workers": str(worker_count),
                    "Max dirs/share": str(options.get("limits", {}).get("max_directories", "")),
                    "Max files/dir": str(options.get("limits", {}).get("max_files", "")),
                },
                cancel_event,
                total=len(targets),
            )
            job_record["dialog"] = dialog
        elif job_type == "extract":
            dialog = self._init_batch_status_dialog(
                "extract",
                {
                    "Targets": str(len(targets)),
                    "Workers": str(worker_count),
                    "Max files/host": str(options.get("max_files_per_target", "")),
                    "Max size MB": str(options.get("max_total_size_mb", "")),
                },
                cancel_event,
                total=len(targets),
            )
            job_record["dialog"] = dialog

        for target in targets:
            future = executor.submit(self._run_batch_task, job_id, job_type, target, options, cancel_event)
            job_record["futures"].append((target, future))
            future.add_done_callback(lambda fut, target=target, jid=job_id: self.window.after(0, self._on_batch_future_done, jid, target, fut))

        if self._is_table_lock_required(job_type):
            self._set_table_interaction_enabled(False)

    def _run_batch_task(self, job_id: str, job_type: str, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
        if cancel_event.is_set():
            return {
                "ip_address": target.get("ip_address"),
                "action": job_type,
                "status": "cancelled",
                "notes": "Cancelled"
            }

        try:
            if job_type == "probe":
                return self._execute_probe_target(job_id, target, options, cancel_event)
            if job_type == "extract":
                return self._execute_extract_target(job_id, target, options, cancel_event)
            if job_type == "pry":
                return self._execute_pry_target(job_id, target, options, cancel_event)
            raise RuntimeError(f"Unknown batch job type: {job_type}")
        except Exception as exc:
            return {
                "ip_address": target.get("ip_address"),
                "action": job_type,
                "status": "failed",
                "notes": str(exc)
            }

    def _execute_probe_target(self, job_id: str, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
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
        try:
            self.db_reader.upsert_probe_cache(
                ip_address,
                status='issue' if issue_detected else 'clean',
                indicator_matches=len(analysis.get("matches", [])),
                snapshot_path=probe_cache.get_probe_result_path(ip_address) if hasattr(probe_cache, "get_probe_result_path") else None
            )
        except Exception:
            pass

        # Update dialog progress (per target)
        dialog = self.active_jobs.get(job_id, {}).get("dialog")
        self.window.after(0, self._update_batch_status_dialog, dialog, self.active_jobs.get(job_id, {}).get("completed", 0), self.active_jobs.get(job_id, {}).get("total"), f"Probed {ip_address}")

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

    def _execute_extract_target(self, job_id: str, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
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

        dialog = self.active_jobs.get(job_id, {}).get("dialog")

        try:
            self.window.after(0, self._update_batch_status_dialog, dialog, 0, self.active_jobs.get(job_id, {}).get("total"), f"Extracting {ip_address}")

            def progress_cb(rel_path: str, index: int, limit: Optional[int]) -> None:
                try:
                    self.window.after(0, self._update_batch_status_dialog, dialog, 0, None, f"{ip_address}: {index}/{limit or '?'} {rel_path}")
                except Exception:
                    pass

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
                progress_callback=progress_cb,
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

        # Update dialog progress (per target)
        self.window.after(0, self._update_batch_status_dialog, dialog, 1, self.active_jobs.get(job_id, {}).get("total"), f"Extracted {ip_address}")

        return {
            "ip_address": ip_address,
            "action": "extract",
            "status": "success",
            "notes": ", ".join(note_parts)
        }

    def _execute_pry_target(self, job_id: str, target: Dict[str, Any], options: Dict[str, Any], cancel_event: threading.Event) -> Dict[str, Any]:
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
        self._last_password_tried = getattr(self, "_last_password_tried", {})
        self._last_password_tried[job_id] = None

        def progress_cb(done: int, total: Optional[int]) -> None:
            total_display = total if total is not None and total > 0 else "?"
            try:
                self.window.after(0, self._set_status, f"Pry {ip_address}: tried {done}/{total_display} passwords…")
                dialog = self.active_jobs.get(job_id, {}).get("dialog")
                # Show the actual password tried in last event instead of repeating counts
                last_pwd = self._last_password_tried.get(job_id)
                last_event_msg = f"Tried {last_pwd}" if last_pwd else f"Tried {done}/{total_display}"
                self.window.after(0, self._update_batch_status_dialog, dialog, done, total, last_event_msg)
            except Exception:
                pass

        try:
            result = pry_runner.run_pry(
                ip_address=ip_address,
                username=username,
                wordlist_path=wordlist_path,
                share_name=options.get("share_name", ""),
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

        if result.status == "success" and result.found_password:
            try:
                self._persist_pry_success(target, options.get("share_name", ""), username, result.found_password)
            except Exception:
                pass
            try:
                self.db_reader.upsert_probe_cache(
                    ip_address,
                    status="issue",
                    indicator_matches=0,
                    snapshot_path=None
                )
            except Exception:
                pass

        notes_text = result.notes
        if result.status == "cancelled" and result.notes.lower() == "cancelled":
            notes_text = f"Cancelled after {result.attempts} attempts"

        return {
            "ip_address": ip_address,
            "action": "pry",
            "status": result.status,
            "notes": notes_text
        }

    def _on_batch_future_done(self, job_id: str, target: Dict[str, Any], future: Future) -> None:
        job = self.active_jobs.get(job_id)
        if not job:
            return
        dialog = job.get("dialog")

        try:
            result = future.result()
        except Exception as exc:
            result = {
                "ip_address": target.get("ip_address"),
                "action": job.get("type", "batch"),
                "status": "failed",
                "notes": str(exc)
            }

        job["results"].append(result)
        job["completed"] += 1
        completed = job["completed"]
        total = job["total"]
        job_type = job["type"].title()
        self._set_status(f"{job_type} batch {completed}/{total} complete")

        if completed >= total:
            self._finalize_batch_job(job_id, dialog)

    def _finalize_batch_job(self, job_id: str, dialog: Optional[BatchStatusDialog] = None) -> None:
        job = self.active_jobs.pop(job_id, None)
        if not job:
            return

        executor = job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)

        results = list(job.get("results", []))
        job_type = job.get("type", "batch")
        dlg = dialog or job.get("dialog")
        if dlg:
            primary_result = results[0] if results else {"status": "unknown", "notes": ""}
            self._finish_batch_status_dialog(dlg, primary_result.get("status", "unknown"), primary_result.get("notes", ""))

        self._update_action_buttons_state()
        self._set_status(f"{job_type.title()} batch finished")
        self._flush_pending_refresh()
        self._set_table_interaction_enabled(True)
        if results:
            self._show_batch_summary(job_type, results)
        # Close the status pop-out once the summary is shown
        if dlg:
            try:
                dlg.destroy()
            except Exception:
                pass
            if self.batch_status_dialog is dlg:
                self.batch_status_dialog = None
        self._update_stop_button_style(self._is_batch_active())

    def _stop_active_batch(self) -> None:
        """
        Stop the most recently started active job. Individual dialogs also have Cancel.
        """
        if not self.active_jobs:
            return
        # Stop the last inserted job (most recent)
        job_id = list(self.active_jobs.keys())[-1]
        job = self.active_jobs.get(job_id)
        if not job:
            return
        cancel_event = job.get("cancel_event")
        if cancel_event:
            cancel_event.set()
        executor = job.get("executor")
        if executor:
            executor.shutdown(wait=False, cancel_futures=True)

        pending = []
        futures = job.get("futures", [])
        for target, future in futures:
            if not future.done():
                future.cancel()
                pending.append(target)

        for target in pending:
            job["results"].append({
                "ip_address": target.get("ip_address"),
                "action": job.get("type", "batch"),
                "status": "cancelled",
                "notes": "Stopped by user"
            })

        job["completed"] = job["total"]
        self._set_status("Batch stopped")
        self._finalize_batch_job(job_id)

    def _stop_all_jobs(self) -> None:
        """Stop all active jobs (used on window close)."""
        for job_id in list(self.active_jobs.keys()):
            job = self.active_jobs.get(job_id)
            if not job:
                continue
            cancel_event = job.get("cancel_event")
            if cancel_event:
                cancel_event.set()
            executor = job.get("executor")
            if executor:
                executor.shutdown(wait=False, cancel_futures=True)
            job["completed"] = job["total"]
            self._finalize_batch_job(job_id)

    def _is_batch_active(self) -> bool:
        return any(job.get("completed", 0) < job.get("total", 0) for job in self.active_jobs.values())

    def _current_batch_type(self) -> Optional[str]:
        # Return most recently started job type if any
        if not self.active_jobs:
            return None
        latest = list(self.active_jobs.values())[-1]
        return latest.get("type")

    def _is_pry_batch_active(self) -> bool:
        return any(job.get("type") == "pry" and job.get("completed", 0) < job.get("total", 0) for job in self.active_jobs.values())

    def _is_probe_batch_active(self) -> bool:
        return any(job.get("type") == "probe" and job.get("completed", 0) < job.get("total", 0) for job in self.active_jobs.values())

    def _is_extract_batch_active(self) -> bool:
        return any(job.get("type") == "extract" and job.get("completed", 0) < job.get("total", 0) for job in self.active_jobs.values())

    def _set_status(self, message: str) -> None:
        if self.status_label:
            self.status_label.configure(text=message)

    def _set_pry_status_button_visible(self, visible: bool) -> None:
        if not self.pry_status_button:
            return
        if visible:
            try:
                self.pry_status_button.pack(anchor="w", pady=(4, 0))
            except Exception:
                pass
        else:
            try:
                self.pry_status_button.pack_forget()
            except Exception:
                pass

    def _show_pry_status_dialog(self) -> None:
        if self.batch_status_dialog:
            self.batch_status_dialog.show()
        elif self.active_jobs:
            # Show the most recent job dialog if available
            for job in reversed(list(self.active_jobs.values())):
                dlg = job.get("dialog")
                if dlg:
                    dlg.show()
                    self.batch_status_dialog = dlg
                    break

    def _init_batch_status_dialog(self, job_type: str, fields: Dict[str, str], cancel_event: threading.Event, total: Optional[int] = None) -> BatchStatusDialog:
        """Create a fresh batch status dialog for the active run."""
        dialog = BatchStatusDialog(
            parent=self.window,
            theme=self.theme,
            title=f"{job_type.title()} Status",
            fields=fields,
            on_cancel=lambda: cancel_event.set(),
            total=total
        )
        self.batch_status_dialog = dialog  # keep latest for quick reopen
        self._set_pry_status_button_visible(True)
        return dialog

    def _update_batch_status_dialog(self, dialog: BatchStatusDialog, done: int, total: Optional[int], message: Optional[str]) -> None:
        if not dialog:
            return
        try:
            dialog.update_progress(done, total, message)
        except Exception:
            pass

    def _finish_batch_status_dialog(self, dialog: BatchStatusDialog, status: str, notes: str) -> None:
        if not dialog:
            return
        try:
            dialog.mark_finished(status, notes)
            dialog.show()
        except Exception:
            pass
        self._set_pry_status_button_visible(True)

    def _destroy_batch_status_dialog(self) -> None:
        if self.batch_status_dialog:
            try:
                self.batch_status_dialog.destroy()
            except Exception:
                pass
        self.batch_status_dialog = None
        self._set_pry_status_button_visible(False)

    def _persist_pry_success(self, target: Dict[str, Any], share_label: str, username: str, password: str) -> None:
        """
        Persist Pry success to DB: mark share accessible and store credentials.
        """
        if not self.settings_manager:
            return
        db_path = None
        try:
            db_path = self.settings_manager.get_database_path()
        except Exception:
            return
        if not db_path:
            return

        ip_address = target.get("ip_address")
        auth_method = target.get("auth_method", "")
        share_name = self._normalize_share_name(share_label)
        if not ip_address or not share_name:
            return

        try:
            run_migrations(db_path)
        except Exception:
            # Continue even if migration logging fails
            pass

        now_ts = datetime.now().isoformat(timespec="seconds")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            # Ensure server row
            cur.execute("SELECT id, auth_method FROM smb_servers WHERE ip_address = ?", (ip_address,))
            row = cur.fetchone()
            if row:
                server_id = row["id"]
                cur.execute("UPDATE smb_servers SET last_seen = ? WHERE id = ?", (now_ts, server_id))
            else:
                cur.execute(
                    """
                    INSERT INTO smb_servers (ip_address, auth_method, first_seen, last_seen, scan_count)
                    VALUES (?, ?, ?, ?, 1)
                    """,
                    (ip_address, auth_method, now_ts, now_ts),
                )
                server_id = cur.lastrowid

            # Create a minimal pry session
            cur.execute(
                """
                INSERT INTO scan_sessions (tool_name, scan_type, status, started_at, completed_at, total_targets, successful_targets, failed_targets, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("xsmbseek", "pry", "completed", now_ts, now_ts, 1, 1, 0, f"Pry credential stored for {ip_address}"),
            )
            session_id = cur.lastrowid

            # Upsert share_access
            cur.execute(
                "SELECT id FROM share_access WHERE server_id = ? AND share_name = ?",
                (server_id, share_name),
            )
            row = cur.fetchone()
            if row:
                cur.execute(
                    """
                    UPDATE share_access
                    SET accessible = 1,
                        auth_status = ?,
                        error_message = NULL,
                        test_timestamp = ?,
                        session_id = ?
                    WHERE id = ?
                    """,
                    ("pry", now_ts, session_id, row["id"]),
                )
            else:
                cur.execute(
                    """
                    INSERT INTO share_access (server_id, session_id, share_name, accessible, auth_status, test_timestamp)
                    VALUES (?, ?, ?, 1, ?, ?)
                    """,
                    (server_id, session_id, share_name, "pry", now_ts),
                )

            # Upsert share_credentials
            cur.execute(
                """
                UPDATE share_credentials
                SET username = ?, password = ?, last_verified_at = ?, updated_at = ?
                WHERE server_id = ? AND share_name = ? AND source = 'pry'
                """,
                (username, password, now_ts, now_ts, server_id, share_name),
            )
            if cur.rowcount == 0:
                cur.execute(
                    """
                    INSERT INTO share_credentials (server_id, share_name, username, password, source, session_id, last_verified_at, updated_at)
                    VALUES (?, ?, ?, ?, 'pry', ?, ?, ?)
                    """,
                    (server_id, share_name, username, password, session_id, now_ts, now_ts),
                )

            conn.commit()
        except Exception as exc:
            try:
                conn.rollback()
            except Exception:
                pass
            # Log to console; avoid breaking UI
            print(f"Warning: failed to persist Pry credential for {ip_address}/{share_name}: {exc}")
        finally:
            conn.close()

    def _update_action_buttons_state(self) -> None:
        has_selection = bool(self.tree and self.tree.selection())
        batch_active = self._is_batch_active()
        pry_batch_active = self._is_pry_batch_active()
        probe_batch_active = self._is_probe_batch_active()
        extract_batch_active = self._is_extract_batch_active()

        # Allow browsing/details/export during running batches (read-only), but block starting new batches
        start_state = tk.NORMAL if has_selection and len(self.active_jobs) < 3 else tk.DISABLED
        for button in (self.probe_button, self.extract_button, self.pry_button):
            if button:
                button.configure(state=start_state)
        # Browse stays enabled during batch
        if self.browser_button:
            self.browser_button.configure(state=tk.NORMAL if has_selection else tk.DISABLED)

        # Delete - disabled if no selection, batch active, or delete in progress
        if self.delete_button:
            delete_allowed = has_selection and not batch_active and not getattr(self, '_delete_in_progress', False)
            delete_state = tk.NORMAL if delete_allowed else tk.DISABLED
            self.delete_button.configure(state=delete_state)

        if self.stop_button:
            self.stop_button.configure(state=tk.NORMAL if batch_active else tk.DISABLED)
            self._update_stop_button_style(batch_active)

        detail_state = tk.NORMAL if has_selection else tk.DISABLED
        if self.details_button:
            self.details_button.configure(state=detail_state)

        self._set_pry_status_button_visible(bool(batch_active or self.batch_status_dialog))

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
        # Delete (use stored index, not hardcoded)
        if self._delete_menu_index is not None:
            delete_allowed = has_selection and not batch_active and not getattr(self, '_delete_in_progress', False)
            delete_state = tk.NORMAL if delete_allowed else tk.DISABLED
            self.context_menu.entryconfig(self._delete_menu_index, state=delete_state)

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
            status = server.get("probe_status") or self._determine_probe_status(ip)
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

    def _set_mode(self, advanced: bool) -> None:
        """Set simple/advanced mode explicitly."""
        self.is_advanced_mode = bool(advanced)
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

    def _populate_country_filter(self) -> None:
        """
        Populate country filter listbox with distinct country codes from database.

        Note: Sorting is done by country code BEFORE adding display text "(count)",
        ensuring alphabetical ordering by code, not by the full display string.
        """
        if not self.country_listbox:
            return

        # Save current selections before repopulating (for data refresh scenario)
        saved_selections = self._get_selected_country_codes() if hasattr(self, 'country_code_list') else []

        # Clear existing items
        self.country_listbox.delete(0, tk.END)
        self.country_code_list = []  # Reset mapping

        if not self.db_reader:
            return

        # Get country breakdown (returns dict of code -> count)
        country_breakdown = self.db_reader.get_country_breakdown()

        if not country_breakdown:
            return  # Empty database

        # Sort alphabetically by country code (BEFORE adding display text)
        sorted_countries = sorted(country_breakdown.items())

        # Populate listbox with "CODE (count)" format
        for code, count in sorted_countries:
            display_text = f"{code} ({count})"
            self.country_listbox.insert(tk.END, display_text)
            self.country_code_list.append(code)  # Store code separately for filter logic

        # Restore selections after repopulation (handles data refresh)
        if saved_selections:
            for i, code in enumerate(self.country_code_list):
                if code in saved_selections:
                    self.country_listbox.selection_set(i)

    def _restore_country_filter_selections(self) -> None:
        """
        Restore country filter selections from persisted preferences.

        Must be called AFTER _populate_country_filter() so the listbox has items.
        Silently skips any saved codes that no longer exist in the database.
        """
        if not self.settings_manager or not self.country_listbox:
            return

        if not hasattr(self, 'country_code_list') or not self.country_code_list:
            return  # List not yet populated

        prefs = self.settings_manager.get_setting('windows.server_list.last_filters', {}) or {}
        saved_codes = prefs.get('country_codes', [])

        if not saved_codes:
            return  # Nothing to restore

        # Restore selections (silently skip missing codes)
        for i, code in enumerate(self.country_code_list):
            if code in saved_codes:
                self.country_listbox.selection_set(i)

    def _get_selected_country_codes(self) -> List[str]:
        """
        Get list of selected country codes from listbox.

        Returns empty list if listbox not yet populated (safe for early _apply_filters calls).
        """
        if not self.country_listbox or not hasattr(self, 'country_code_list'):
            return []  # Not yet populated, no filter applied

        if not self.country_code_list:
            return []  # Empty list, no filter applied

        selected_indices = self.country_listbox.curselection()
        return [self.country_code_list[idx] for idx in selected_indices]

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
        self.exclude_avoid.set(False)
        self.probed_only.set(False)
        self.exclude_compromised.set(False)

        # Clear country filter selection
        if self.country_listbox:
            self.country_listbox.selection_clear(0, tk.END)

        self._apply_filters()

    def _load_filter_preferences(self) -> None:
        """Load persisted filter preferences from settings."""
        if not self.settings_manager:
            return
        prefs = self.settings_manager.get_setting('windows.server_list.last_filters', {}) or {}
        self.favorites_only.set(bool(prefs.get('favorites_only', False)))
        self.exclude_avoid.set(bool(prefs.get('exclude_avoid', False)))
        self.probed_only.set(bool(prefs.get('probed_only', False)))
        self.exclude_compromised.set(bool(prefs.get('exclude_compromised', False)))
        self.shares_filter.set(bool(prefs.get('shares_filter', self.shares_filter.get())))
        self.search_text.set(prefs.get('search_text', self.search_text.get()))
        self.date_filter.set(prefs.get('date_filter', self.date_filter.get()))
        self.is_advanced_mode = bool(prefs.get('advanced_mode', self.is_advanced_mode))

    def _persist_filter_preferences(self) -> None:
        """Persist current filter selections to settings."""
        if not self.settings_manager:
            return
        prefs = {
            'favorites_only': bool(self.favorites_only.get()),
            'exclude_avoid': bool(self.exclude_avoid.get()),
            'probed_only': bool(self.probed_only.get()),
            'exclude_compromised': bool(self.exclude_compromised.get()),
            'shares_filter': bool(self.shares_filter.get()),
            'country_codes': self._get_selected_country_codes(),
            'search_text': self.search_text.get(),
            'date_filter': self.date_filter.get(),
            'advanced_mode': bool(self.is_advanced_mode),
        }
        self.settings_manager.set_setting('windows.server_list.last_filters', prefs)

    # --- Filter template helpers ------------------------------------------------

    def _get_last_filter_template_slug(self) -> Optional[str]:
        if not self.settings_manager:
            return None
        return self.settings_manager.get_setting('windows.server_list.filter_template_last_used', None)

    def _set_last_filter_template_slug(self, slug: Optional[str]) -> None:
        if not self.settings_manager:
            return
        try:
            self.settings_manager.set_setting('windows.server_list.filter_template_last_used', slug)
        except Exception:
            pass

    def _refresh_filter_templates(self, select_slug: Optional[str] = None) -> None:
        """Refresh filter template dropdown values."""
        if 'filter_template_dropdown' not in self.filter_widgets:
            return

        dropdown = self.filter_widgets['filter_template_dropdown']
        templates = self.filter_template_store.list_templates()
        self._filter_template_label_to_slug = {tpl.name: tpl.slug for tpl in templates}

        values = [self.FILTER_TEMPLATE_PLACEHOLDER] + [tpl.name for tpl in templates]
        dropdown['values'] = values

        target_slug = select_slug or self._get_last_filter_template_slug()
        target_label = None
        if target_slug:
            for name, slug in self._filter_template_label_to_slug.items():
                if slug == target_slug:
                    target_label = name
                    break

        if target_label:
            self.filter_template_var.set(target_label)
            self._selected_filter_template_slug = self._filter_template_label_to_slug.get(target_label)
        else:
            self.filter_template_var.set(self.FILTER_TEMPLATE_PLACEHOLDER)
            self._selected_filter_template_slug = None

    def _capture_filter_state(self) -> Dict[str, Any]:
        """Capture current filter settings into a serializable dict."""
        return {
            'search_text': self.search_text.get(),
            'date_filter': self.date_filter.get(),
            'shares_filter': bool(self.shares_filter.get()),
            'favorites_only': bool(self.favorites_only.get()),
            'exclude_avoid': bool(self.exclude_avoid.get()),
            'probed_only': bool(self.probed_only.get()),
            'exclude_compromised': bool(self.exclude_compromised.get()),
            'country_codes': self._get_selected_country_codes(),
            'advanced_mode': bool(self.is_advanced_mode),
        }

    def _apply_filter_state(self, state: Dict[str, Any]) -> None:
        """Apply a saved filter state to UI and refresh results."""
        self.search_text.set(state.get('search_text', ''))
        self.date_filter.set(state.get('date_filter', 'All'))
        self.shares_filter.set(bool(state.get('shares_filter', False)))
        self.favorites_only.set(bool(state.get('favorites_only', False)))
        self.exclude_avoid.set(bool(state.get('exclude_avoid', False)))
        self.probed_only.set(bool(state.get('probed_only', False)))
        self.exclude_compromised.set(bool(state.get('exclude_compromised', False)))

        desired_mode = bool(state.get('advanced_mode', False))
        if self.is_advanced_mode != desired_mode:
            self._set_mode(desired_mode)

        codes = state.get('country_codes', []) or []
        if self.country_listbox and self.country_code_list:
            self.country_listbox.selection_clear(0, tk.END)
            for idx, code in enumerate(self.country_code_list):
                if code in codes:
                    self.country_listbox.selection_set(idx)

        self._apply_filters(force=True)

    def _on_filter_template_selected(self) -> None:
        """Handle selection from filter template dropdown."""
        label = self.filter_template_var.get()
        if label == self.FILTER_TEMPLATE_PLACEHOLDER:
            self._selected_filter_template_slug = None
            return

        slug = self._filter_template_label_to_slug.get(label)
        self._selected_filter_template_slug = slug
        if not slug:
            return

        template = self.filter_template_store.load_template(slug)
        if not template:
            messagebox.showwarning("Filter Template", "Template could not be loaded.", parent=self.window)
            return

        self._set_last_filter_template_slug(slug)
        self._apply_filter_state(template.form_state or {})

    def _on_save_filter_template(self) -> None:
        """Prompt for a template name and save current filters."""
        initial_name = None
        label = self.filter_template_var.get()
        if label and label != self.FILTER_TEMPLATE_PLACEHOLDER:
            initial_name = label

        name = simpledialog.askstring(
            "Save Filter Template",
            "Template name:",
            parent=self.window,
            initialvalue=initial_name or ""
        )
        if not name:
            return
        name = name.strip()
        if not name:
            messagebox.showwarning("Save Filter Template", "Template name cannot be empty.", parent=self.window)
            return

        slug = TemplateStore.slugify(name)
        existing = self.filter_template_store.load_template(slug)
        if existing:
            overwrite = messagebox.askyesno(
                "Overwrite Template",
                f"A template named '{name}' already exists. Overwrite it?",
                parent=self.window
            )
            if not overwrite:
                return

        form_state = self._capture_filter_state()
        template = self.filter_template_store.save_template(name, form_state)
        self._set_last_filter_template_slug(template.slug)
        self._refresh_filter_templates(select_slug=template.slug)
        messagebox.showinfo("Template Saved", f"Template '{name}' saved.", parent=self.window)

    def _refresh_data(self) -> None:
        """Refresh data from database."""
        self._load_data()

    def _close_window(self) -> None:
        """Close the server list window."""
        # Do not stop active jobs or destroy child dialogs; simply hide this window
        # so background tasks and pop-outs can continue running.
        if self.window and self.window.winfo_exists():
            # Release modal grab before hiding to prevent blocking parent window
            try:
                self.window.grab_release()
            except tk.TclError:
                pass  # Already released or widget destroyed
            self.window.withdraw()

    def restore_and_focus(self) -> None:
        """Restore hidden window and set focus. Called when reopening existing window."""
        if self.window and self.window.winfo_exists():
            # Release any stuck grab first
            try:
                self.window.grab_release()
            except tk.TclError:
                pass  # Already released or widget destroyed

            # Show and focus
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()

            # Re-apply modal grab
            try:
                self.window.grab_set()
            except tk.TclError:
                pass  # Widget destroyed or parent unavailable

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
                           window_data: Dict[str, Any] = None, settings_manager = None) -> 'ServerListWindow':
    """
    Open server list browser window.

    Args:
        parent: Parent widget
        db_reader: Database reader instance
        window_data: Optional data for window initialization
        settings_manager: Optional settings manager for favorites functionality

    Returns:
        ServerListWindow instance for tracking and reuse
    """
    return ServerListWindow(parent, db_reader, window_data, settings_manager)
