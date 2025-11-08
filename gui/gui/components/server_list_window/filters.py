"""
Server List Filter Operations

Handles filter UI creation and pure filtering logic.
Uses callback pattern for event wiring to prevent tight coupling.
"""

import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable


def create_filter_panel(parent, theme, filter_vars, callbacks):
    """
    Create filtering controls panel.

    Args:
        parent: Parent widget for the filter panel
        theme: Theme object for styling
        filter_vars: Dict of tkinter variables for filter state
        callbacks: Dict of callback functions for filter events

    Returns:
        tuple: (filter_frame, widget_refs) for parent access
    """
    # Filter container (initially hidden for simple mode)
    filter_frame = tk.Frame(parent)
    theme.apply_to_widget(filter_frame, "card")

    # Search box (always visible)
    search_frame = tk.Frame(filter_frame)
    theme.apply_to_widget(search_frame, "card")
    search_frame.pack(fill=tk.X, padx=10, pady=5)

    search_label = theme.create_styled_label(
        search_frame,
        "🔍 Search:",
        "body"
    )
    search_label.pack(side=tk.LEFT, padx=(0, 5))

    search_entry = tk.Entry(
        search_frame,
        textvariable=filter_vars['search_text'],
        width=30
    )
    search_entry.pack(side=tk.LEFT, padx=(0, 10))
    search_entry.bind("<KeyRelease>", lambda e: callbacks['on_search_changed']())

    # Clear search button
    clear_button = tk.Button(
        search_frame,
        text="Clear",
        command=callbacks['on_clear_search']
    )
    theme.apply_to_widget(clear_button, "button_secondary")
    clear_button.pack(side=tk.LEFT, padx=(0, 10))

    # Favorites only filter checkbox
    favorites_checkbox = tk.Checkbutton(
        search_frame,
        text="Favorites only",
        variable=filter_vars['favorites_only'],
        command=callbacks['on_favorites_only_changed']
    )
    theme.apply_to_widget(favorites_checkbox, "checkbox")
    favorites_checkbox.pack(side=tk.LEFT, padx=(0, 10))

    # Avoid only filter checkbox
    avoid_checkbox = tk.Checkbutton(
        search_frame,
        text="Avoid only",
        variable=filter_vars['avoid_only'],
        command=callbacks['on_avoid_only_changed']
    )
    theme.apply_to_widget(avoid_checkbox, "checkbox")
    avoid_checkbox.pack(side=tk.LEFT, padx=(0, 10))

    # Show all results toggle (if callback provided)
    show_all_button = None
    if 'on_show_all_toggle' in callbacks:
        show_all_button = tk.Button(
            search_frame,
            text="📈 Show All Results",
            command=callbacks['on_show_all_toggle']
        )
        theme.apply_to_widget(show_all_button, "button_primary")
        show_all_button.pack(side=tk.LEFT)

    # Advanced filters (hidden initially)
    advanced_filters_frame = tk.Frame(filter_frame)
    theme.apply_to_widget(advanced_filters_frame, "card")

    # Accessible shares filter (checkbox) - simplified filtering
    shares_filter_frame = tk.Frame(advanced_filters_frame)
    theme.apply_to_widget(shares_filter_frame, "card")
    shares_filter_frame.pack(side=tk.LEFT, padx=10, pady=5)

    shares_filter_checkbox = tk.Checkbutton(
        shares_filter_frame,
        text="Show only servers with accessible shares > 0",
        variable=filter_vars['shares_filter'],
        command=callbacks['on_shares_filter_changed']
    )
    shares_filter_checkbox.pack()

    # Date filter
    date_frame = tk.Frame(advanced_filters_frame)
    theme.apply_to_widget(date_frame, "card")
    date_frame.pack(side=tk.LEFT, padx=10, pady=5)

    date_label = theme.create_styled_label(
        date_frame,
        "Discovery Date:",
        "small"
    )
    date_label.pack()

    date_combo = ttk.Combobox(
        date_frame,
        textvariable=filter_vars['date_filter'],
        values=["All", "Since Last Scan", "Last 24 Hours", "Last 7 Days", "Last 30 Days"],
        width=15,
        state="readonly"
    )
    date_combo.set("All")
    date_combo.pack()
    date_combo.bind("<<ComboboxSelected>>", lambda e: callbacks['on_date_filter_changed']())

    # Reset filters button
    reset_button = tk.Button(
        advanced_filters_frame,
        text="Reset Filters",
        command=callbacks['on_reset_filters']
    )
    theme.apply_to_widget(reset_button, "button_secondary")
    reset_button.pack(side=tk.RIGHT, padx=10, pady=5)

    # Widget references for parent access
    widget_refs = {
        'advanced_filters_frame': advanced_filters_frame,
        'search_entry': search_entry,
        'date_combo': date_combo,
        'shares_filter_checkbox': shares_filter_checkbox,
        'favorites_checkbox': favorites_checkbox,
        'avoid_checkbox': avoid_checkbox
    }

    if show_all_button:
        widget_refs['show_all_button'] = show_all_button

    return filter_frame, widget_refs


def apply_search_filter(servers: List[Dict[str, Any]], search_term: str) -> List[Dict[str, Any]]:
    """
    Apply search filter to server list.

    Args:
        servers: List of servers to filter
        search_term: Search term to match against IP and shares

    Returns:
        Filtered list of servers
    """
    if not search_term:
        return servers

    search_term = search_term.lower()
    filtered = []

    for server in servers:
        # Search in IP address and accessible shares list
        if (search_term in server.get("ip_address", "").lower() or
            search_term in server.get("accessible_shares_list", "").lower()):
            filtered.append(server)

    return filtered


def apply_date_filter(servers: List[Dict[str, Any]], filter_type: str, last_scan_time) -> List[Dict[str, Any]]:
    """
    Apply date-based filtering to server list.

    Args:
        servers: List of servers to filter
        filter_type: Type of date filter to apply
        last_scan_time: Last scan time for "Since Last Scan" filter

    Returns:
        Filtered list of servers
    """
    if not filter_type or filter_type == "All":
        return servers

    now = datetime.now()
    cutoff_time = None

    if filter_type == "Since Last Scan" and last_scan_time:
        cutoff_time = last_scan_time
    elif filter_type == "Last 24 Hours":
        cutoff_time = now - timedelta(hours=24)
    elif filter_type == "Last 7 Days":
        cutoff_time = now - timedelta(days=7)
    elif filter_type == "Last 30 Days":
        cutoff_time = now - timedelta(days=30)

    if not cutoff_time:
        return servers

    filtered = []
    for server in servers:
        # Check various date fields that might be available
        server_date = None

        # Try different date field names
        for date_field in ["first_seen", "last_seen", "discovery_date", "created_at"]:
            if date_field in server and server[date_field]:
                try:
                    server_date = datetime.fromisoformat(server[date_field].replace("Z", "+00:00"))
                    break
                except (ValueError, AttributeError):
                    continue

        # If we found a valid date, compare it
        if server_date and server_date >= cutoff_time:
            filtered.append(server)
        elif not server_date:
            # If no date available and we're filtering for recent items, exclude
            # But if filtering "Since Last Scan" and no date, include (assume old data)
            if filter_type == "Since Last Scan":
                filtered.append(server)

    return filtered


def apply_shares_filter(servers: List[Dict[str, Any]], shares_only: bool) -> List[Dict[str, Any]]:
    """
    Apply accessible shares filter to server list.

    Args:
        servers: List of servers to filter
        shares_only: If True, only show servers with accessible shares > 0

    Returns:
        Filtered list of servers
    """
    if not shares_only:
        return servers

    return [server for server in servers if server.get("accessible_shares", 0) > 0]


def apply_favorites_filter(servers: List[Dict[str, Any]], favorites_only: bool, settings_manager) -> List[Dict[str, Any]]:
    """
    Apply favorites filter to server list.

    Args:
        servers: List of servers to filter
        favorites_only: If True, only show favorite servers
        settings_manager: Settings manager for favorite IPs lookup

    Returns:
        Filtered list of servers
    """
    if not favorites_only or not settings_manager:
        return servers

    favorite_ips = settings_manager.get_favorite_servers()
    return [server for server in servers if server.get("ip_address") in favorite_ips]


def apply_avoid_filter(servers: List[Dict[str, Any]], avoid_only: bool, settings_manager) -> List[Dict[str, Any]]:
    """
    Apply avoid filter to server list.

    Args:
        servers: List of servers to filter
        avoid_only: If True, only show servers marked to avoid
        settings_manager: Settings manager for avoid IPs lookup

    Returns:
        Filtered list of servers
    """
    if not avoid_only or not settings_manager:
        return servers

    avoid_ips = settings_manager.get_avoid_servers()
    return [server for server in servers if server.get("ip_address") in avoid_ips]


def update_mode_display(advanced_filters_frame, is_advanced_mode: bool):
    """
    Update display based on current mode.

    Args:
        advanced_filters_frame: Advanced filters frame widget
        is_advanced_mode: Whether advanced mode is active
    """
    if is_advanced_mode:
        advanced_filters_frame.pack(fill=tk.X, pady=(5, 0))
    else:
        advanced_filters_frame.pack_forget()