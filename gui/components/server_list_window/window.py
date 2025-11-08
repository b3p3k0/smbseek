"""
Main Server List Window

Orchestrates all server list functionality using extracted modules.
Maintains all shared state and coordinates between components.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Dict, List, Any, Optional
import os
import sys

# Add utils to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'utils'))

try:
    from gui.utils.database_access import DatabaseReader
    from gui.utils.style import get_theme
    from gui.utils.data_export_engine import get_export_engine
    from gui.utils.scan_manager import get_scan_manager
except ImportError:
    # Handle relative imports when running from gui directory
    from utils.database_access import DatabaseReader
    from utils.style import get_theme
    from utils.data_export_engine import get_export_engine
    from utils.scan_manager import get_scan_manager

# Import modular components
from . import export, details, filters, table
from gui.utils import probe_cache, probe_patterns


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

        # Date filtering state
        self.filter_recent = self.window_data.get("filter_recent", False)
        self.last_scan_time = None

        # Data management
        self.all_servers = []
        self.filtered_servers = []
        self.selected_servers = []

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

        # Pack table frame
        self.table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    def _create_button_panel(self) -> None:
        """Create bottom button panel with actions."""
        self.button_frame = tk.Frame(self.window)
        self.theme.apply_to_widget(self.button_frame, "main_window")
        self.button_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        # Left side - selection info
        self.selection_label = self.theme.create_styled_label(
            self.button_frame,
            "No selection",
            "small"
        )
        self.selection_label.pack(side=tk.LEFT)

        # Right side - action buttons
        button_container = tk.Frame(self.button_frame)
        self.theme.apply_to_widget(button_container, "main_window")
        button_container.pack(side=tk.RIGHT)

        # Server details button
        details_button = tk.Button(
            button_container,
            text="📋 View Details",
            command=self._view_server_details
        )
        self.theme.apply_to_widget(details_button, "button_secondary")
        details_button.pack(side=tk.LEFT, padx=(0, 5))

        # Export selected button
        export_selected_button = tk.Button(
            button_container,
            text="📤 Export Selected",
            command=self._export_selected_servers
        )
        self.theme.apply_to_widget(export_selected_button, "button_secondary")
        export_selected_button.pack(side=tk.LEFT, padx=(0, 5))

        # Export all button
        export_all_button = tk.Button(
            button_container,
            text="📊 Export All",
            command=self._export_all_servers
        )
        self.theme.apply_to_widget(export_all_button, "button_primary")
        export_all_button.pack(side=tk.LEFT)

    def _setup_event_handlers(self) -> None:
        """Setup event handlers for the window."""
        # Window close event
        self.window.protocol("WM_DELETE_WINDOW", self._close_window)

        # Keyboard shortcuts
        self.window.bind("<Control-a>", self._select_all)
        self.window.bind("<Control-e>", lambda e: self._export_selected_servers())
        self.window.bind("<Escape>", lambda e: self._close_window())
        self.window.bind("<F5>", lambda e: self._refresh_data())

    def _apply_filters(self) -> None:
        """Apply current filters to server list using filter module functions."""
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
            'clean': '△',
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
