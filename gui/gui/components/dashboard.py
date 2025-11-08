"""
SMBSeek Mission Control Dashboard

Implements the main dashboard with all critical information in a single view.
Provides key metrics cards, progress display, top findings, and summary breakdowns
with drill-down capabilities to detailed windows.

Design Decision: Single-panel "mission control" layout provides situation awareness
while drill-down buttons allow detailed exploration without losing overview context.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import tkinter.font as tkfont
import threading
import time
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import sys
import os
import queue
from collections import deque
import re

# Add utils to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'utils'))

from database_access import DatabaseReader
from backend_interface import BackendInterface
from style import get_theme, apply_theme_to_window
from scan_manager import get_scan_manager
from scan_dialog import show_scan_dialog
from scan_results_dialog import show_scan_results_dialog


class DashboardWidget:
    """
    Main dashboard displaying key SMBSeek metrics and status.
    
    Implements mission control pattern with:
    - Key metrics cards (clickable for drill-down)
    - Real-time scan progress display
    - Top security findings summary
    - Country and activity breakdowns
    - Quick scan interface
    
    Design Pattern: Single view with progressive disclosure through drill-down
    windows activated by clicking on metric cards and summary sections.
    """
    
    def __init__(self, parent: tk.Widget, db_reader: DatabaseReader, 
                 backend_interface: BackendInterface, config_path: str = None):
        """
        Initialize dashboard widget.
        
        Args:
            parent: Parent tkinter widget
            db_reader: Database access instance
            backend_interface: Backend communication interface
            config_path: Path to SMBSeek configuration file (optional)
            
        Design Decision: Dependency injection allows easy testing with mock
        objects and clear separation of concerns.
        """
        self.parent = parent
        self.db_reader = db_reader
        self.backend_interface = backend_interface
        self.theme = get_theme()
        
        # Dashboard state
        self.current_scan = None
        self.last_update = None
        
        # Scan management
        self.scan_manager = get_scan_manager()
        self.config_path = config_path
        
        # UI components
        self.main_frame = None
        self.progress_frame = None
        self.metrics_frame = None
        self.scan_button = None
        self.status_bar = None
        self.update_time_label = None
        self.status_message = None
        
        # Progress tracking
        self.current_progress_summary = ""
        self.status_text = tk.StringVar(value="Loading dashboard summary...")
        self._status_static_mode = True  # Keep status label static post-initialization
        self._status_summary_initialized = False

        # Live log viewer state
        self.log_queue: "queue.Queue[str]" = queue.Queue()
        self.log_history = deque(maxlen=500)
        self.log_text_widget: Optional[tk.Text] = None
        self.log_autoscroll = True
        self._log_placeholder_visible = True
        self.log_processing_job = None
        self.log_jump_button = None
        self.log_bg_color = "#111418"
        self.log_fg_color = "#f5f5f5"
        self.log_placeholder_color = "#9ea4b3"

        # ANSI parsing helpers for preserving backend colors
        self._ansi_pattern = re.compile(r"\x1b\[([\d;]*)m")
        self._ansi_color_tag_map = {
            "30": "ansi_fg_black",
            "31": "ansi_fg_red",
            "32": "ansi_fg_green",
            "33": "ansi_fg_yellow",
            "34": "ansi_fg_blue",
            "35": "ansi_fg_magenta",
            "36": "ansi_fg_cyan",
            "37": "ansi_fg_white",
            "90": "ansi_fg_bright_black",
            "91": "ansi_fg_bright_red",
            "92": "ansi_fg_bright_green",
            "93": "ansi_fg_bright_yellow",
            "94": "ansi_fg_bright_blue",
            "95": "ansi_fg_bright_magenta",
            "96": "ansi_fg_bright_cyan",
            "97": "ansi_fg_bright_white"
        }
        self._ansi_color_tags = set(self._ansi_color_tag_map.values())
        self.log_placeholder_text = "Scan output will appear here once a scan starts."
        
        # Scan button state management
        self.scan_button_state = "idle"  # idle, disabled_external, scanning, stopping, error
        self.external_scan_pid = None
        
        # Callbacks
        self.drill_down_callback = None
        self.config_editor_callback = None
        self.size_enforcement_callback = None
        
        self._build_dashboard()
        
        # Initial data load
        self._refresh_dashboard_data()
    
    def set_drill_down_callback(self, callback: Callable[[str, Dict], None]) -> None:
        """
        Set callback for opening drill-down windows.
        
        Args:
            callback: Function to call with (window_type, data) for drill-downs
        """
        self.drill_down_callback = callback
    
    def set_config_editor_callback(self, callback: Callable[[str], None]) -> None:
        """
        Set callback for opening configuration editor.
        
        Args:
            callback: Function to call with config file path
        """
        self.config_editor_callback = callback
    
    def set_size_enforcement_callback(self, callback: Callable[[], None]) -> None:
        """
        Set callback for enforcing window size after operations that might trigger auto-resize.
        
        Args:
            callback: Function to call to enforce intended window dimensions
        """
        self.size_enforcement_callback = callback
    
    def _build_dashboard(self) -> None:
        """
        Build the complete dashboard layout.
        
        Design Decision: Vertical layout with sections allows natural reading
        flow and responsive behavior on different screen sizes.
        """
        # Main container with scrolling capability
        self.main_frame = tk.Frame(self.parent)
        self.theme.apply_to_widget(self.main_frame, "main_window")
        self.main_frame.pack(fill=tk.BOTH, expand=False, padx=8, pady=5)
        
        # Build sections in order
        self._build_header_section()
        self._build_progress_section()
        self._build_status_bar()
        
        # Initial scan state check and data load
        self._check_external_scans()
        self._refresh_dashboard_data()
        self._process_log_queue()
    
    def _build_header_section(self) -> None:
        """Build responsive two-line header with title and action buttons."""
        header_frame = tk.Frame(self.main_frame)
        self.theme.apply_to_widget(header_frame, "main_window")
        header_frame.pack(fill=tk.X, pady=(0, 10))

        # Line 1: Title only
        title_label = self.theme.create_styled_label(
            header_frame,
            "SMBSeek Security Toolkit",
            "title"
        )
        title_label.pack(anchor=tk.W, pady=(0, 5))

        # Line 2: Action buttons with natural sizing
        actions_frame = tk.Frame(header_frame)
        self.theme.apply_to_widget(actions_frame, "main_window")
        actions_frame.pack(anchor=tk.W)

        # Start Scan button (preserve state management)
        self.scan_button = tk.Button(
            actions_frame,
            text="🔍 Start Scan",
            command=self._handle_scan_button_click
        )
        self.theme.apply_to_widget(self.scan_button, "button_primary")
        self.scan_button.pack(side=tk.LEFT, padx=(0, 5))

        # Servers button (existing functionality)
        servers_button = tk.Button(
            actions_frame,
            text="📋 Servers",
            command=lambda: self._open_drill_down("server_list")
        )
        self.theme.apply_to_widget(servers_button, "button_secondary")
        servers_button.pack(side=tk.LEFT, padx=(0, 5))

        # Config button (existing functionality)
        config_button = tk.Button(
            actions_frame,
            text="⚙ Config",
            command=self._open_config_editor
        )
        self.theme.apply_to_widget(config_button, "button_secondary")
        config_button.pack(side=tk.LEFT)
        
    
    def _build_progress_section(self) -> None:
        """Build persistent progress display that's always visible."""
        self.progress_frame = tk.Frame(self.main_frame)
        self.theme.apply_to_widget(self.progress_frame, "card")
        self.progress_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))

        self._build_log_viewer()
        self._build_status_footer()

    def _configure_log_tags(self) -> None:
        """Configure text tags used for ANSI-colored output."""
        if not self.log_text_widget:
            return

        mono_font = self.theme.fonts["mono"]
        bold_font = (mono_font[0], mono_font[1], "bold")
        self.log_text_widget.tag_configure("ansi_bold", font=bold_font)

        color_map = {
            "ansi_fg_black": "#7f8796",
            "ansi_fg_red": "#ff7676",
            "ansi_fg_green": "#7dd87d",
            "ansi_fg_yellow": "#ffd666",
            "ansi_fg_blue": "#76b9ff",
            "ansi_fg_magenta": "#d692ff",
            "ansi_fg_cyan": "#4dd0e1",
            "ansi_fg_white": self.log_fg_color,
            "ansi_fg_bright_black": "#a0a7b4",
            "ansi_fg_bright_red": "#ff8b8b",
            "ansi_fg_bright_green": "#8ef79a",
            "ansi_fg_bright_yellow": "#ffe082",
            "ansi_fg_bright_blue": "#90c8ff",
            "ansi_fg_bright_magenta": "#f78bff",
            "ansi_fg_bright_cyan": "#6fe8ff",
            "ansi_fg_bright_white": "#ffffff"
        }

        for tag, color in color_map.items():
            self.log_text_widget.tag_configure(tag, foreground=color)

        self.log_text_widget.tag_configure(
            "log_placeholder",
            foreground=self.log_placeholder_color
        )

    def _render_log_placeholder(self) -> None:
        """Display placeholder text when no log output is available."""
        if not self.log_text_widget:
            return

        self.log_text_widget.configure(state=tk.NORMAL)
        self.log_text_widget.delete("1.0", tk.END)
        self.log_text_widget.insert(
            tk.END,
            f"{self.log_placeholder_text}\n",
            ("log_placeholder",)
        )
        self.log_text_widget.configure(state=tk.DISABLED)
        self._log_placeholder_visible = True
        self.log_autoscroll = True
        self._hide_log_jump_button()

    def _reset_log_output(self, country: Optional[str]) -> None:
        """Clear log output and add a friendly header for the new scan."""
        self._clear_log_output()
        target = country or "global"
        self._append_log_line(f"GUI: awaiting backend output for {target} scan...")

    def _append_log_line(self, line: str) -> None:
        """Append a raw CLI line to the text widget preserving ANSI colors."""
        if not self.log_text_widget or line is None:
            return

        previous_len = len(self.log_history)
        self.log_history.append(line)

        self.log_text_widget.configure(state=tk.NORMAL)
        if self._log_placeholder_visible:
            self.log_text_widget.delete("1.0", tk.END)
            self._log_placeholder_visible = False

        segments = self._parse_ansi_segments(line)
        if not segments:
            segments = [(line, ())]

        for segment_text, tags in segments:
            if segment_text:
                self.log_text_widget.insert(tk.END, segment_text, tags)
        self.log_text_widget.insert(tk.END, "\n")

        if previous_len == self.log_history.maxlen:
            self.log_text_widget.delete("1.0", "2.0")

        self.log_text_widget.configure(state=tk.DISABLED)

        if self.log_autoscroll:
            self.log_text_widget.see(tk.END)

        self._update_log_autoscroll_state()

    def _parse_ansi_segments(self, text: str) -> List[tuple]:
        """Split text into (segment, tags) respecting ANSI escape codes."""
        segments = []
        last_end = 0
        active_tags: List[str] = []

        for match in self._ansi_pattern.finditer(text):
            start, end = match.span()
            if start > last_end:
                segments.append((text[last_end:start], tuple(active_tags)))

            codes = match.group(1).split(";") if match.group(1) else ["0"]
            active_tags = self._apply_ansi_codes(active_tags, codes)
            last_end = end

        if last_end < len(text):
            segments.append((text[last_end:], tuple(active_tags)))

        return segments

    def _apply_ansi_codes(self, active_tags: List[str], codes: List[str]) -> List[str]:
        """Update active tag list based on ANSI code sequence."""
        tags = list(active_tags)
        for code in codes:
            if not code:
                code = "0"

            if code == "0":
                tags.clear()
            elif code == "1":
                if "ansi_bold" not in tags:
                    tags.append("ansi_bold")
            elif code in self._ansi_color_tag_map:
                tags = [t for t in tags if t not in self._ansi_color_tags]
                tags.append(self._ansi_color_tag_map[code])

        return tags

    def _handle_scan_log_line(self, line: str) -> None:
        """Queue log lines coming from background scan threads."""
        if line is None:
            return
        self.log_queue.put(line)

    def _process_log_queue(self) -> None:
        """Drain queued log lines on the Tk thread."""
        if not self.parent or not self.parent.winfo_exists():
            return

        try:
            while True:
                line = self.log_queue.get_nowait()
                self._append_log_line(line)
        except queue.Empty:
            pass

        self.log_processing_job = self.parent.after(150, self._process_log_queue)

    def _update_log_autoscroll_state(self, *_args) -> None:
        """Detect whether the viewer is scrolled to the bottom."""
        if not self.log_text_widget:
            return

        at_bottom = self._is_log_at_bottom()
        self.log_autoscroll = at_bottom

        if at_bottom:
            self._hide_log_jump_button()
        else:
            self._show_log_jump_button()

    def _is_log_at_bottom(self) -> bool:
        """Return True if the viewer is scrolled to the bottom."""
        if not self.log_text_widget:
            return True
        start, end = self.log_text_widget.yview()
        return end >= 0.995

    def _scroll_log_to_latest(self) -> None:
        """Scroll the viewer to the most recent line and resume autoscroll."""
        if not self.log_text_widget:
            return
        self.log_text_widget.see(tk.END)
        self.log_autoscroll = True
        self._hide_log_jump_button()

    def _show_log_jump_button(self) -> None:
        """Display the jump-to-latest helper."""
        if self.log_jump_button and not self.log_jump_button.winfo_ismapped():
            self.log_jump_button.pack(side=tk.RIGHT, padx=(5, 0))

    def _hide_log_jump_button(self) -> None:
        """Hide the jump-to-latest helper."""
        if self.log_jump_button and self.log_jump_button.winfo_ismapped():
            self.log_jump_button.pack_forget()

    def _copy_log_output(self) -> None:
        """Copy current log contents to clipboard."""
        if not self.log_history:
            return
        try:
            self.parent.clipboard_clear()
            self.parent.clipboard_append("\n".join(self.log_history))
        except tk.TclError:
            pass

    def _clear_log_output(self) -> None:
        """Clear log viewer and reset placeholder."""
        self.log_history.clear()
        self._render_log_placeholder()

    def _build_log_viewer(self) -> None:
        """Create expanded live output viewer."""
        log_container = tk.Frame(
            self.progress_frame,
            bg=self.theme.colors["card_bg"],
            highlightthickness=0
        )
        log_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 14))

        header_frame = tk.Frame(log_container, bg=self.theme.colors["card_bg"])
        header_frame.pack(fill=tk.X, pady=(0, 6))

        header_label = tk.Label(
            header_frame,
            text="Live Scan Output",
            bg=self.theme.colors["card_bg"],
            fg=self.theme.colors["text"],
            font=self.theme.fonts["heading"]
        )
        header_label.pack(side=tk.LEFT)

        self.log_jump_button = tk.Button(
            header_frame,
            text="Jump to Latest",
            command=self._scroll_log_to_latest
        )
        self.theme.apply_to_widget(self.log_jump_button, "button_secondary")
        self.log_jump_button.pack(side=tk.RIGHT, padx=(5, 0))
        self.log_jump_button.pack_forget()  # hidden until user scrolls away

        text_frame = tk.Frame(log_container, bg=self.log_bg_color)
        text_frame.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        base_log_lines = 10
        extra_log_height_px = 300  # 150px original bump + 150px new request
        expanded_lines = base_log_lines + self._pixels_to_text_lines(extra_log_height_px)
        self.log_text_widget = tk.Text(
            text_frame,
            height=expanded_lines,
            wrap=tk.NONE,
            bg=self.log_bg_color,
            fg=self.log_fg_color,
            font=self.theme.fonts["mono"],
            state=tk.DISABLED,
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            insertbackground=self.log_fg_color
        )
        self.log_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.log_text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.configure(command=self.log_text_widget.yview)

        # Track manual scrolling to toggle autoscroll state
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>", "<ButtonRelease-1>", "<Shift-MouseWheel>"):
            self.log_text_widget.bind(sequence, self._update_log_autoscroll_state, add="+")

        self._configure_log_tags()
        self._render_log_placeholder()
    
    def _build_status_footer(self) -> None:
        """Place status summary + clipboard controls below the console."""
        footer = tk.Frame(
            self.progress_frame,
            bg=self.theme.colors["card_bg"],
            highlightthickness=0
        )
        footer.pack(fill=tk.X, padx=10, pady=(0, 12))
        footer.columnconfigure(0, weight=1)
        footer.columnconfigure(1, weight=0)

        status_summary_label = tk.Label(
            footer,
            textvariable=self.status_text,
            anchor="w",
            justify="left",
            bg=self.theme.colors["card_bg"],
            fg=self.theme.colors["text_secondary"],
            font=self.theme.fonts["status"],
            wraplength=520
        )
        status_summary_label.grid(row=0, column=0, sticky="w")

        self.update_time_label = tk.Label(
            footer,
            text="",
            anchor="w",
            bg=self.theme.colors["card_bg"],
            fg=self.theme.colors["text_secondary"],
            font=self.theme.fonts["status"]
        )
        self.update_time_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        button_frame = tk.Frame(
            footer,
            bg=self.theme.colors["card_bg"]
        )
        button_frame.grid(row=0, column=1, rowspan=2, sticky="se", padx=(10, 0))

        copy_button = tk.Button(
            button_frame,
            text="Copy All",
            command=self._copy_log_output
        )
        self.theme.apply_to_widget(copy_button, "button_secondary")
        copy_button.pack(side=tk.LEFT, padx=(0, 5))

        clear_button = tk.Button(
            button_frame,
            text="Clear",
            command=self._clear_log_output
        )
        self.theme.apply_to_widget(clear_button, "button_secondary")
        clear_button.pack(side=tk.LEFT)
    
    def _pixels_to_text_lines(self, pixels: int) -> int:
        """
        Convert a pixel delta into Tk Text height units (lines).
        
        Text widgets size their height in lines (TkDocs Text tutorial),
        so we translate requested padding into line counts using the active
        monospace font metrics. This avoids fragile hard-coded guesses.
        """
        if pixels <= 0:
            return 0
        try:
            log_font = tkfont.Font(font=self.theme.fonts["mono"])
            line_height = max(1, log_font.metrics("linespace"))
        except tk.TclError:
            # Safe fallback during shutdown/detached widgets
            line_height = 14
        extra_lines = pixels // line_height
        if pixels % line_height:
            extra_lines += 1
        return extra_lines
    
    def _update_progress_summary(self, summary: Optional[str], detail: Optional[str] = None) -> None:
        """Cache scan progress summary for dialogs; UI status label stays static."""
        summary_text = summary.strip() if isinstance(summary, str) else (summary or "")
        detail_text = detail.strip() if isinstance(detail, str) else (detail or "")
        parts = []
        if summary_text:
            parts.append(summary_text)
        if detail_text:
            parts.append(detail_text)
        status_body = " - ".join(parts) if parts else "In progress"
        self.current_progress_summary = status_body
    
    def _log_status_event(self, message: str) -> None:
        """Append controller-level status lines to the console output."""
        if not message:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[status {timestamp}] {message}"
        try:
            self.log_queue.put(entry)
        except Exception:
            # Fallback if queue is unavailable (e.g., during shutdown)
            try:
                self._append_log_line(entry)
            except Exception:
                pass
    
    def _reset_scan_status(self) -> None:
        """Return dashboard status indicators to the ready state."""
        self.current_progress_summary = ""
    
    def _refresh_dashboard_data(self) -> None:
        """
        Refresh all dashboard data from database.
        
        Design Decision: Single refresh method ensures consistent data state
        across all dashboard components and handles errors gracefully.
        """
        try:
            # Get dashboard summary
            summary = self.db_reader.get_dashboard_summary()
            
            # Update status
            self.last_update = datetime.now()
            self._update_status_display(summary)
            
            # Enforce window size after data refresh to prevent auto-resizing
            if self.size_enforcement_callback:
                self.size_enforcement_callback()
            
        except Exception as e:
            self._handle_refresh_error(e)

    def _refresh_after_scan_completion(self) -> None:
        """
        Refresh dashboard after scan completion with cache invalidation.
        
        Ensures fresh data is loaded by clearing cache before refresh,
        which is critical for displaying updated Recent Discoveries count.
        """
        try:
            self._unlock_status_updates()
            # Clear cache to force fresh database queries
            self.db_reader.clear_cache()
            
            # Refresh dashboard with new data
            self._refresh_dashboard_data()
        except Exception as e:
            print(f"Dashboard refresh error after scan completion: {e}")
            # Continue anyway
        finally:
            self._lock_status_updates()
            self._status_refresh_pending = False

    def _update_status_display(self, summary: Dict[str, Any]) -> None:
        """Update status bar information."""
        if self._status_static_mode and self._status_summary_initialized:
            return

        # Main status
        total_servers = summary.get("total_servers", 0)
        servers_with_accessible_shares = summary.get("servers_with_accessible_shares", 0)
        total_shares = summary.get("total_shares", 0)
        last_scan = summary.get("last_scan", "Never")

        if last_scan != "Never":
            # Format last scan time
            try:
                scan_time = datetime.fromisoformat(last_scan.replace("Z", "+00:00"))
                formatted_time = scan_time.strftime("%Y-%m-%d %H:%M")
            except:
                formatted_time = "Unknown"
        else:
            formatted_time = "Never"

        status_text = (
            f"Last Scan: {formatted_time} | "
            f"DB: {total_servers:,} servers, {servers_with_accessible_shares:,} with accessible shares, "
            f"{total_shares:,} total shares"
        )
        self.status_text.set(status_text)
        self._status_summary_initialized = True
        
        # Update time
        if self.last_update:
            update_text = f"Updated: {self.last_update.strftime('%H:%M:%S')}"
            self.update_time_label.configure(text=update_text)
    
    def _handle_refresh_error(self, error: Exception) -> None:
        """Handle dashboard refresh errors gracefully."""
        error_message = f"Dashboard refresh failed: {str(error)}"
        self.status_text.set(f"Error: {error_message}")
        self._status_summary_initialized = False
        
        # If database is unavailable, enable mock mode
        if "Database" in str(error) or "database" in str(error):
            try:
                self.db_reader.enable_mock_mode()
                self._refresh_dashboard_data()  # Retry with mock data
                self.status_text.set("Using mock data - database unavailable")
            except:
                self.status_text.set("Dashboard unavailable - check backend")

    def _schedule_post_scan_refresh(self, delay_ms: int = 2000) -> None:
        """Schedule a status-refreshing dashboard update after scans finish."""
        if self._status_refresh_pending:
            return
        self._status_refresh_pending = True
        self.parent.after(delay_ms, self._refresh_after_scan_completion)

    def _unlock_status_updates(self) -> None:
        """Allow status summary text to update on next refresh."""
        self._status_static_mode = False
        self._status_summary_initialized = False

    def _lock_status_updates(self) -> None:
        """Freeze status summary text until explicitly unlocked."""
        self._status_static_mode = True

    
    def start_scan_progress(self, scan_type: str, countries: List[str]) -> None:
        """
        Start displaying scan progress.

        Args:
            scan_type: Type of scan being performed
            countries: Countries being scanned
        """
        countries_text = ", ".join(countries) if countries else "global"
        summary = f"Starting {scan_type} scan"
        detail = f"Countries: {countries_text}"
        self._update_progress_summary(summary, detail)
        self._log_status_event(f"{summary} for {countries_text}")
    
    def update_scan_progress(self, percentage: Optional[float], message: str) -> None:
        """
        Update scan progress display.

        Args:
            percentage: Progress percentage (0-100) or None for status-only update
            message: Progress message to display
        """
        if percentage is not None:
            summary = f"{percentage:.0f}% complete"
            detail = message if message else None
        else:
            summary = message if message else "Processing..."
            detail = None

        self._update_progress_summary(summary, detail)

        # Force UI update without triggering window auto-resize
        # Using update() instead of update_idletasks() to prevent geometry recalculation
        try:
            self.parent.update()
            # Enforce window size after UI update to prevent auto-resizing
            if self.size_enforcement_callback:
                self.size_enforcement_callback()
        except tk.TclError:
            # UI may be destroyed, ignore
            pass
    
    def finish_scan_progress(self, success: bool, results: Dict[str, Any]) -> None:
        """
        Finish scan progress display.

        Args:
            success: Whether scan completed successfully
            results: Scan results dictionary
        """
        if success:
            successful = results.get("successful_auth", 0)
            total = results.get("hosts_tested", 0)
            summary = f"Scan complete: {successful}/{total} servers accessible"
            self._update_progress_summary(summary, "Refreshing dashboard...")
            self._log_status_event(summary)

            # Refresh dashboard with new data (clear cache for fresh Recent Discoveries count)
            self._schedule_post_scan_refresh(delay_ms=2000)
        else:
            summary = "Scan failed - check backend connection"
            self._update_progress_summary(summary, None)
            self._log_status_event(summary)
            self._schedule_post_scan_refresh(delay_ms=2000)

        # Return to ready state after giving the user time to read the summary
        self.parent.after(5000, self._reset_scan_status)
    
    def _show_quick_scan_dialog(self) -> None:
        """Show scan configuration dialog and start scan."""
        # Check if scan is already active
        if self.scan_manager.is_scan_active():
            messagebox.showwarning(
                "Scan in Progress",
                "A scan is already running. Please wait for it to complete before starting another scan."
            )
            return
        
        # Show scan dialog
        result = show_scan_dialog(
            parent=self.parent,
            config_path=self.config_path,
            config_editor_callback=self._open_config_editor_from_scan,
            scan_start_callback=self._start_new_scan,
            backend_interface=self.backend_interface,
            settings_manager=getattr(self, 'settings_manager', None)
        )
    
    def _open_config_editor_from_scan(self, config_path: str) -> None:
        """Open configuration editor from scan dialog."""
        if self.config_editor_callback:
            self.config_editor_callback(config_path)
    
    def _start_new_scan(self, scan_options: dict) -> None:
        """Start new scan with specified options."""
        try:
            # Final check for external scans before starting
            self._check_external_scans()
            if self.scan_button_state != "idle":
                return  # External scan detected, don't proceed

            # Get backend path for external SMBSeek installation
            backend_path = getattr(self.backend_interface, "backend_path", "./smbseek")
            backend_path = str(backend_path)

            # Start scan via scan manager with new options
            success = self.scan_manager.start_scan(
                scan_options=scan_options,
                backend_path=backend_path,
                progress_callback=self._handle_scan_progress,
                log_callback=self._handle_scan_log_line
            )
            
            if success:
                # Reset viewer and note which scan is running
                self._reset_log_output(scan_options.get('country'))

                # Update button state to scanning
                self._update_scan_button_state("scanning")
                
                # Show progress display
                country = scan_options.get('country')
                self._show_scan_progress(country)
                
                # Start monitoring scan completion
                self._monitor_scan_completion()
            else:
                # Get more specific error information
                error_details = []
                
                # Check if backend path exists
                if not os.path.exists(backend_path):
                    error_details.append(f"• Backend path not found: {backend_path}")
                
                # Check if SMBSeek executable exists
                smbseek_cli = os.path.join(backend_path, "smbseek.py")
                if not os.path.exists(smbseek_cli):
                    error_details.append(f"• SMBSeek CLI not found: {smbseek_cli}")
                
                # Check scan manager state
                if self.scan_manager.is_scanning:
                    error_details.append("• Scan manager reports scan already in progress")
                
                # Check for lock file
                lock_file_path = os.path.join(os.path.dirname(__file__), '..', '..', '.scan_lock')
                if os.path.exists(lock_file_path):
                    error_details.append("• Lock file exists, indicating another scan may be running")
                
                if error_details:
                    detailed_msg = "Failed to start scan. Issues detected:\n\n" + "\n".join(error_details)
                    detailed_msg += "\n\nPlease ensure SMBSeek is properly installed and configured."
                else:
                    detailed_msg = "Failed to start scan. Another scan may already be running."
                
                messagebox.showerror("Scan Error", detailed_msg)
        except Exception as e:
            error_msg = str(e)
            
            # Provide specific guidance based on error type
            if "backend" in error_msg.lower() or "not found" in error_msg.lower():
                detailed_msg = (
                    f"Backend interface error: {error_msg}\n\n"
                    "This usually indicates:\n"
                    "• SMBSeek backend is not installed or not in expected location\n"
                    "• Backend CLI is not executable\n"
                    "• Configuration file is missing\n\n"
                    "Please ensure the backend is properly installed and configured."
                )
            elif "lock" in error_msg.lower():
                detailed_msg = (
                    f"Scan coordination error: {error_msg}\n\n"
                    "Another scan may already be running. Please wait for it to complete\n"
                    "or restart the application if the scan appears to be stuck."
                )
            else:
                detailed_msg = (
                    f"Scan initialization failed: {error_msg}\n\n"
                    "Please try again or check the configuration settings."
                )
            
            messagebox.showerror("Scan Error", detailed_msg)
    
    def _handle_scan_progress(self, percentage: float, status: str, phase: str) -> None:
        """Handle progress updates from scan manager."""
        try:
            # Update status text with phase/percentage info
            detail_text = status if status else None
            if phase:
                phase_display = phase.replace("_", " ").title()
                if percentage is not None:
                    progress_text = f"{phase_display}: {percentage:.0f}%"
                else:
                    progress_text = phase_display
            else:
                if percentage is not None:
                    progress_text = f"{percentage:.0f}% complete"
                else:
                    progress_text = None

            if not progress_text:
                progress_text = detail_text if detail_text else "Processing..."
                detail_text = None

            self._update_progress_summary(progress_text, detail_text)

            # Force UI update safely without triggering window auto-resize
            # Using update() instead of update_idletasks() to prevent geometry recalculation
            try:
                self.parent.update()
                # Enforce window size after UI update to prevent auto-resizing
                if self.size_enforcement_callback:
                    self.size_enforcement_callback()
            except tk.TclError:
                # UI may be destroyed, ignore
                pass

        except Exception as e:
            # Log error but don't interrupt scan
            print(f"Progress update error: {e}")  # In production, use proper logging
    
    def _show_scan_progress(self, country: Optional[str]) -> None:
        """Transition progress display to active scanning state."""
        scan_target = country if country else "global"
        summary = f"Initializing {scan_target} scan"
        self._update_progress_summary(summary, "Setting up scan parameters...")
        self._log_status_event(summary)
    
    def _monitor_scan_completion(self) -> None:
        """Monitor scan for completion and show results."""
        def check_completion():
            try:
                if not self.scan_manager.is_scanning:
                    # Get results first to check status
                    results = self.scan_manager.get_scan_results()

                    # Reset button state to idle
                    self._update_scan_button_state("idle")

                    # Handle cancelled scans differently
                    if results and results.get("status") == "cancelled":
                        # Show lightweight info message for cancelled scan
                        try:
                            import tkinter.messagebox as msgbox
                            msgbox.showinfo(
                                "Scan Cancelled",
                                "Scan was cancelled by user request."
                            )
                        except Exception:
                            # Fallback - just print message
                            print("Scan cancelled by user")
                        self._log_status_event("Scan cancelled by user request")
                        self._reset_scan_status()
                    elif results:
                        # Show normal results dialog for completed/failed scans
                        self._show_scan_results(results)
                        try:
                            self.parent.after(5000, self._reset_scan_status)
                        except tk.TclError:
                            pass
                    else:
                        self._reset_scan_status()
                    # If no results, scan may have been cancelled before any results were recorded

                    # Refresh dashboard data with cache invalidation
                    try:
                        self._refresh_after_scan_completion()
                    except Exception as e:
                        print(f"Dashboard refresh error after scan: {e}")
                        # Continue anyway
                else:
                    # Check again in 1 second
                    try:
                        self.parent.after(1000, check_completion)
                    except tk.TclError:
                        # UI destroyed, stop monitoring
                        pass
                        
            except Exception as e:
                # Critical error in monitoring, show error and stop
                try:
                    messagebox.showerror(
                        "Scan Monitoring Error",
                        f"Error monitoring scan progress: {str(e)}\n\n"
                        "The scan may still be running in the background.\n"
                        "Please check the scan results manually."
                    )
                except:
                    # Even error dialog failed, just stop monitoring
                    pass
                
                # Try to clean up
                try:
                    self._reset_scan_status()
                except:
                    pass
        
        # Start monitoring with error protection
        try:
            self.parent.after(1000, check_completion)
        except tk.TclError:
            # UI not available
            pass
    
    def _show_scan_results(self, results: Dict[str, Any]) -> None:
        """Show scan results dialog."""
        try:
            def view_details_callback():
                try:
                    # Open server list with date filter
                    if self.drill_down_callback:
                        self.drill_down_callback("server_list", {"filter_recent": True})
                except Exception as e:
                    messagebox.showerror(
                        "View Details Error",
                        f"Failed to open detailed results:\n{str(e)}"
                    )
            
            # Show results dialog
            show_scan_results_dialog(
                parent=self.parent,
                scan_results=results,
                view_details_callback=view_details_callback
            )
            
        except Exception as e:
            # Fallback to simple message box if results dialog fails
            status = results.get("status", "unknown")
            hosts_scanned = results.get("hosts_scanned", 0)
            accessible_hosts = results.get("accessible_hosts", 0)
            
            fallback_message = (
                f"Scan completed with status: {status}\n\n"
                f"Results:\n"
                f"• Hosts scanned: {hosts_scanned}\n"
                f"• Accessible hosts: {accessible_hosts}\n\n"
                f"Note: Full results dialog could not be displayed due to error:\n{str(e)}"
            )
            
            messagebox.showinfo("Scan Results", fallback_message)
    
    def _open_config_editor(self) -> None:
        """Open application configuration dialog."""
        if self.drill_down_callback:
            self.drill_down_callback("app_config", {})
    
    
    def _open_drill_down(self, window_type: str) -> None:
        """
        Open drill-down window.
        
        Args:
            window_type: Type of drill-down window to open
        """
        if self.drill_down_callback:
            self.drill_down_callback(window_type, {})
    
    def enable_mock_mode(self) -> None:
        """Enable mock mode for testing."""
        self.db_reader.enable_mock_mode()
        self.backend_interface.enable_mock_mode()
        self._refresh_dashboard_data()
    
    def disable_mock_mode(self) -> None:
        """Disable mock mode."""
        self.db_reader.disable_mock_mode()
        self.backend_interface.disable_mock_mode()
        self._refresh_dashboard_data()
    
    # ===== SCAN BUTTON STATE MANAGEMENT =====
    
    def _build_status_bar(self) -> None:
        """Build status bar for external scan notifications."""
        self.status_bar = tk.Frame(self.main_frame)
        self.theme.apply_to_widget(self.status_bar, "status_bar")
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
        
        # Status message label (initially hidden)
        self.status_message = tk.Label(
            self.status_bar,
            text="",
            font=self.theme.fonts["small"]
        )
        self.theme.apply_to_widget(self.status_message, "status_bar")
        
        # Start hidden
        self._hide_status_bar()
    
    def _show_status_bar(self, message: str) -> None:
        """Show status bar with message."""
        self.status_message.config(text=message)
        self.status_message.pack(padx=10, pady=5)
        self.status_bar.pack(fill=tk.X, pady=(10, 0))
    
    def _hide_status_bar(self) -> None:
        """Hide status bar."""
        self.status_message.pack_forget()
        self.status_bar.pack_forget()
    
    def _handle_scan_button_click(self) -> None:
        """Handle scan button click based on current state."""
        if self.scan_button_state == "idle":
            self._check_external_scans()  # Check again before starting
            if self.scan_button_state == "idle":  # Still idle after check
                self._show_quick_scan_dialog()
        elif self.scan_button_state == "scanning":
            self._show_stop_confirmation()
        elif self.scan_button_state == "disabled_external":
            # Show info about external scan
            messagebox.showinfo(
                "Scan In Progress",
                f"Another scan is currently running (PID: {self.external_scan_pid}). "
                "Please wait for it to complete or stop it from that application."
            )
        # Other states (stopping, error) don't respond to clicks
    
    def _update_scan_button_state(self, new_state: str) -> None:
        """Update scan button state and appearance."""
        self.scan_button_state = new_state
        
        if new_state == "idle":
            self._set_button_to_start()
            self._hide_status_bar()
        elif new_state == "disabled_external":
            self._set_button_to_disabled()
            self._show_status_bar(f"Scan running by PID: {self.external_scan_pid} - Please wait")
        elif new_state == "scanning":
            self._set_button_to_stop()
            self._hide_status_bar()
        elif new_state == "stopping":
            self._set_button_to_stopping()
        elif new_state == "error":
            self._set_button_to_error()
    
    def _set_button_to_start(self) -> None:
        """Configure button for start state."""
        self.scan_button.config(
            text="🔍 Start Scan",
            state="normal"
        )
        self.theme.apply_to_widget(self.scan_button, "button_primary")
    
    def _set_button_to_stop(self) -> None:
        """Configure button for stop state."""
        self.scan_button.config(
            text="⬛ Stop Scan",
            state="normal"
        )
        self.theme.apply_to_widget(self.scan_button, "button_danger")
    
    def _set_button_to_disabled(self) -> None:
        """Configure button for disabled state (external scan)."""
        self.scan_button.config(
            text="🔍 Scan Running",
            state="disabled"
        )
        self.theme.apply_to_widget(self.scan_button, "button_disabled")
    
    def _set_button_to_stopping(self) -> None:
        """Configure button for stopping state with warning color."""
        self.scan_button.config(
            text="⏳ Stopping...",
            state="disabled"
        )
        # Apply secondary theme first, then override with warning color
        self.theme.apply_to_widget(self.scan_button, "button_secondary")
        self.scan_button.config(bg=self.theme.colors["warning"])
    
    def _set_button_to_error(self) -> None:
        """Configure button for error state."""
        self.scan_button.config(
            text="⬛ Stop Failed",
            state="normal"
        )
        self.theme.apply_to_widget(self.scan_button, "button_danger")
    
    # ===== LOCK FILE MANAGEMENT =====
    
    def _check_external_scans(self) -> None:
        """Check for external scans using lock file system."""
        try:
            if self.scan_manager.is_scan_active():
                # Get lock file info
                lock_file_path = os.path.join(os.path.dirname(__file__), '..', '..', '.scan_lock')
                if os.path.exists(lock_file_path):
                    import json
                    with open(lock_file_path, 'r') as f:
                        lock_data = json.load(f)
                    
                    # Check if it's our own scan or external
                    lock_pid = lock_data.get('process_id')
                    current_pid = os.getpid()
                    
                    if lock_pid != current_pid:
                        # External scan detected
                        if self._validate_external_process(lock_pid):
                            self.external_scan_pid = lock_pid
                            self._update_scan_button_state("disabled_external")
                            return
                        else:
                            # Stale lock file - clean it up
                            self.scan_manager._cleanup_stale_locks()
                    else:
                        # Our own scan is running
                        if self.scan_manager.is_scanning:
                            self._update_scan_button_state("scanning")
                        else:
                            # Scan completed, update state
                            self._update_scan_button_state("idle")
                        return
            
            # No active scans detected
            self._update_scan_button_state("idle")
            
        except Exception as e:
            print(f"Error checking external scans: {e}")
            # Fallback to idle state
            self._update_scan_button_state("idle")
    
    def _validate_external_process(self, pid: int) -> bool:
        """Validate that external process is actually running."""
        try:
            # Try psutil first (more reliable)
            try:
                import psutil
                return psutil.pid_exists(pid)
            except ImportError:
                # Fallback to os.kill method
                import signal
                os.kill(pid, 0)  # Doesn't actually kill, just checks existence
                return True
        except (OSError, ProcessLookupError):
            return False
        except Exception:
            # Unknown error, assume process exists to be safe
            return True
    
    # ===== STOP CONFIRMATION DIALOG =====
    
    def _show_stop_confirmation(self) -> None:
        """Show confirmation dialog for stopping scan."""
        # Custom dialog for stop options
        dialog = tk.Toplevel(self.parent)
        dialog.title("Stop Scan")
        dialog.geometry("400x250")
        dialog.minsize(300, 200)
        dialog.transient(self.parent)
        dialog.grab_set()
        
        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (dialog.winfo_width() // 2)
        y = (dialog.winfo_screenheight() // 2) - (dialog.winfo_height() // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Apply theme
        self.theme.apply_to_widget(dialog, "main_window")
        
        # Header
        header_label = self.theme.create_styled_label(
            dialog,
            "⚠️ Stop Scan Confirmation",
            "heading"
        )
        header_label.pack(pady=(20, 10))
        
        # Warning message
        warning_text = (
            "Stopping the scan may result in incomplete data collection.\n"
            "Choose how you would like to stop the scan:"
        )
        warning_label = self.theme.create_styled_label(
            dialog,
            warning_text,
            "body",
            justify="center"
        )
        warning_label.pack(pady=(0, 20), padx=20)
        
        # Progress context (if available)
        current_progress = getattr(self, "current_progress_summary", "")
        if current_progress:
            progress_label = self.theme.create_styled_label(
                dialog,
                f"Current: {current_progress}",
                "small",
                fg=self.theme.colors["text_secondary"]
            )
            progress_label.pack(pady=(0, 20))
        
        # Buttons frame
        buttons_frame = tk.Frame(dialog)
        self.theme.apply_to_widget(buttons_frame, "main_window")
        buttons_frame.pack(pady=20)
        
        # Stop now button
        stop_now_btn = tk.Button(
            buttons_frame,
            text="Stop Now",
            command=lambda: self._handle_stop_choice(dialog, "immediate")
        )
        self.theme.apply_to_widget(stop_now_btn, "button_danger")
        stop_now_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Stop after host button
        stop_after_btn = tk.Button(
            buttons_frame,
            text="Stop After Current Host",
            command=lambda: self._handle_stop_choice(dialog, "graceful")
        )
        self.theme.apply_to_widget(stop_after_btn, "button_secondary")
        stop_after_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Cancel button
        cancel_btn = tk.Button(
            buttons_frame,
            text="Cancel",
            command=dialog.destroy
        )
        self.theme.apply_to_widget(cancel_btn, "button_secondary")
        cancel_btn.pack(side=tk.LEFT, padx=(10, 0))
        
        # Handle window close
        dialog.protocol("WM_DELETE_WINDOW", dialog.destroy)
    
    def _handle_stop_choice(self, dialog: tk.Toplevel, choice: str) -> None:
        """Handle user's stop choice."""
        dialog.destroy()
        
        if choice == "immediate":
            self._stop_scan_immediate()
        elif choice == "graceful":
            self._stop_scan_after_host()
    
    # ===== SCAN STOP FUNCTIONALITY =====
    
    def _stop_scan_immediate(self) -> None:
        """Stop scan immediately."""
        self._update_scan_button_state("stopping")
        
        try:
            success = self.scan_manager.interrupt_scan()
            
            if success:
                # Scan stopped successfully
                self._update_scan_button_state("idle")
                messagebox.showinfo(
                    "Scan Stopped",
                    "Scan has been stopped successfully."
                )
            else:
                # Stop failed
                self._handle_stop_error("Failed to interrupt scan - scan may not be active")
                
        except Exception as e:
            self._handle_stop_error(f"Error stopping scan: {str(e)}")
    
    def _stop_scan_after_host(self) -> None:
        """Stop scan after current host completes."""
        # For now, implement as immediate stop with different message
        # Future enhancement: could add graceful stopping to scan manager
        self._update_scan_button_state("stopping")
        
        try:
            success = self.scan_manager.interrupt_scan()
            
            if success:
                self._update_scan_button_state("idle")
                messagebox.showinfo(
                    "Scan Stopping",
                    "Scan will stop after the current host completes processing."
                )
            else:
                self._handle_stop_error("Failed to schedule graceful stop")
                
        except Exception as e:
            self._handle_stop_error(f"Error scheduling graceful stop: {str(e)}")
    
    def _handle_stop_error(self, error_message: str) -> None:
        """Handle scan stop error."""
        # Double-check actual scan state
        if not self.scan_manager.is_scanning:
            # Scan actually stopped despite error
            self._update_scan_button_state("idle")
            messagebox.showinfo(
                "Scan Stopped",
                "Scan has stopped (despite error in communication)."
            )
        else:
            # Scan still running, show error state
            self._update_scan_button_state("error")
            messagebox.showerror(
                "Stop Failed",
                f"Failed to stop scan: {error_message}\n\n"
                "Click 'Stop Scan' again to retry."
            )
