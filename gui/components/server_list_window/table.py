"""
Server List Table Operations

Handles TreeView setup, display logic, sorting, and selection events.
Uses callback pattern for event delegation to prevent tight coupling.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from typing import Dict, List, Any, Callable, Optional, Tuple
import re


def create_server_table(parent, theme, callbacks):
    """
    Create server data table with scrollbars.

    Args:
        parent: Parent widget for the table
        theme: Theme object for styling
        callbacks: Dict of callback functions for table events

    Returns:
        tuple: (table_frame, tree_widget, scrollbar_v, scrollbar_h)
    """
    # Table container
    table_frame = tk.Frame(parent)
    theme.apply_to_widget(table_frame, "main_window")

    # Define columns - updated for enhanced share tracking with favorites and avoid
    columns = (
        "favorite",
        "avoid",
        "probe",
        "extracted",
        "IP Address",
        "Shares",
        "Accessible",
        "Denied",
        "Last Seen",
        "Country"
    )

    # Create treeview
    tree = ttk.Treeview(
        table_frame,
        columns=columns,
        show="tree headings",
        selectmode="extended"
    )

    # Configure columns - optimized dimensions for enhanced share tracking with favorites and avoid
    tree.column("#0", width=0, stretch=False)  # Hide tree column
    tree.column("favorite", width=40, anchor="center")  # Favorite star column
    tree.column("avoid", width=40, anchor="center")  # Avoid skull column
    tree.column("probe", width=50, anchor="center")
    tree.column("extracted", width=60, anchor="center")
    tree.column("IP Address", width=160, anchor="w")
    tree.column("Shares", width=100, anchor="center")
    tree.column("Accessible", width=520, anchor="w")  # reclaim space for denied column
    tree.column("Denied", width=110, anchor="center")
    tree.column("Last Seen", width=150, anchor="w")
    tree.column("Country", width=100, anchor="w", stretch=True)  # Flexible width

    # Configure headings (use clear labels to reduce ambiguity)
    heading_labels = {
        "favorite": "Favorite",
        "avoid": "Avoid",
        "probe": "Probed",
        "extracted": "Extracted"
    }
    for col in columns:
        label = heading_labels.get(col, col)
        tree.heading(col, text=label, command=lambda c=col: callbacks.get('on_sort_column', lambda x: None)(c))

    # Add scrollbars
    scrollbar_v = ttk.Scrollbar(
        table_frame,
        orient="vertical",
        command=tree.yview
    )
    scrollbar_h = ttk.Scrollbar(
        table_frame,
        orient="horizontal",
        command=tree.xview
    )

    tree.configure(yscrollcommand=scrollbar_v.set)
    tree.configure(xscrollcommand=scrollbar_h.set)

    # Pack components
    tree.grid(row=0, column=0, sticky="nsew")
    scrollbar_v.grid(row=0, column=1, sticky="ns")
    scrollbar_h.grid(row=1, column=0, sticky="ew")

    # Configure grid weights
    table_frame.grid_rowconfigure(0, weight=1)
    table_frame.grid_columnconfigure(0, weight=1)

    # Bind events
    tree.bind("<<TreeviewSelect>>", lambda e: callbacks.get('on_selection_changed', lambda: None)())
    tree.bind("<Double-1>", lambda e: callbacks.get('on_double_click', lambda x: None)(e))
    tree.bind("<Button-1>", lambda e: callbacks.get('on_treeview_click', lambda x: None)(e))

    return table_frame, tree, scrollbar_v, scrollbar_h


def update_table_display(tree, filtered_servers: List[Dict[str, Any]], settings_manager=None):
    """
    Update table display with filtered data.

    Args:
        tree: TreeView widget to update
        filtered_servers: List of server dictionaries to display
        settings_manager: Optional settings manager for favorites/avoid status
    """
    # Clear existing items
    for item in tree.get_children():
        tree.delete(item)

    # Add filtered servers
    for server in filtered_servers:
        # Format display values - updated for enhanced share tracking
        ip_addr = server.get("ip_address", "")
        shares_count = str(server.get("accessible_shares", 0))
        denied_count = str(server.get("denied_shares_count", 0))
        accessible_shares = server.get("accessible_shares_list", "")
        last_seen = server.get("last_seen", "Never")
        country = server.get("country", "Unknown")

        # Format last seen date
        if last_seen and last_seen != "Never":
            try:
                date_obj = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                last_seen = date_obj.strftime("%Y-%m-%d %H:%M")
            except:
                pass

        # Format accessible shares list (ensure no spaces after commas)
        if accessible_shares:
            # Remove any spaces after commas and ensure clean formatting
            accessible_shares = ",".join([share.strip() for share in accessible_shares.split(",") if share.strip()])

        # Determine favorite star
        if settings_manager and settings_manager.is_favorite_server(ip_addr):
            star = "★"
        else:
            star = "☆"

        # Determine avoid skull
        if settings_manager and settings_manager.is_avoid_server(ip_addr):
            skull = "☠"
        else:
            skull = "💀"

        probe_emoji = server.get("probe_status_emoji", "⚪")
        extracted_emoji = server.get("extract_status_emoji", "○")

        # Insert row with new column structure including favorite, avoid, probe columns
        item_id = tree.insert(
            "",
            "end",
            values=(star, skull, probe_emoji, extracted_emoji, ip_addr, shares_count, accessible_shares, denied_count, last_seen, country)
        )

        # Add visual indicators for shares count
        share_count = server.get("accessible_shares", 0)
        if share_count > 0:
            tree.set(item_id, "Shares", f"📁 {shares_count}")
        else:
            tree.set(item_id, "Shares", shares_count)

        tree.set(item_id, "Denied", denied_count)


def get_selected_server_data(tree, filtered_servers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Get data for currently selected servers.

    Args:
        tree: TreeView widget
        filtered_servers: List of server dictionaries currently displayed

    Returns:
        List of selected server dictionaries
    """
    selected_items = tree.selection()
    selected_ips = []

    for item in selected_items:
        values = tree.item(item)["values"]
        if len(values) >= 5:
            selected_ips.append(values[4])  # IP address now at index 4 (after favorite/avoid/probe/extracted)

    selected_servers = [
        server for server in filtered_servers
        if server.get("ip_address") in selected_ips
    ]

    return selected_servers


def sort_table_by_column(tree, column: str, current_sort_column: Optional[str],
                        current_sort_direction: Optional[str], original_headers: Dict[str, str],
                        default_sort_directions: Dict[str, str]) -> Tuple[str, str]:
    """
    Sort table by specified column with bidirectional toggle support.

    Args:
        tree: TreeView widget to sort
        column: Column name to sort by
        current_sort_column: Currently sorted column
        current_sort_direction: Current sort direction
        original_headers: Cache of original column text
        default_sort_directions: Default sort direction for each column

    Returns:
        tuple: (new_sort_column, new_sort_direction)
    """
    # Short-circuit for favorite/avoid/extracted columns - no meaningful sort order
    if column in ("favorite", "avoid", "extracted"):
        return current_sort_column, current_sort_direction

    # Cache original header text on first access to this column
    if column not in original_headers:
        # Get current header text (remove any existing indicators)
        current_text = tree.heading(column)["text"]
        # Clean text by removing any existing indicators
        clean_text = current_text.replace(" (↑)", "").replace(" (↓)", "")
        original_headers[column] = clean_text

    # Determine sort direction
    if current_sort_column == column:
        # Same column clicked - toggle direction
        new_sort_direction = "asc" if current_sort_direction == "desc" else "desc"
    else:
        # Different column clicked - use default direction for this column
        new_sort_direction = default_sort_directions.get(column, "desc")

        # Clear previous column's indicator if there was one
        if current_sort_column and current_sort_column in original_headers:
            _set_header_text(tree, current_sort_column, original_headers[current_sort_column])

    # Preserve selection and focus before sorting
    selected_items = list(tree.selection())
    focused_item = tree.focus()

    # Get current data with sort key
    data_with_keys = []

    for item in tree.get_children():
        values = tree.item(item)["values"]

        # Determine sort key based on column
        try:
            col_index = tree["columns"].index(column)
            sort_key = values[col_index]
        except (ValueError, IndexError):
            continue

        # Convert to appropriate type for sorting
        if column == "Shares":
            # Extract number from string (remove emojis)
            numbers = re.findall(r'\d+', str(sort_key))
            sort_key = int(numbers[0]) if numbers else 0
        elif column == "Last Seen":
            # Sort by date
            try:
                sort_key = datetime.strptime(sort_key, "%Y-%m-%d %H:%M")
            except:
                sort_key = datetime.min
        elif column == "Accessible":
            # Sort by length of accessible shares list (number of shares)
            sort_key = len(str(sort_key).split(",")) if str(sort_key).strip() else 0
        elif column == "Denied":
            try:
                sort_key = int(sort_key)
            except (TypeError, ValueError):
                sort_key = 0

        data_with_keys.append((sort_key, item, values))

    # Sort with correct direction
    reverse_sort = (new_sort_direction == "desc")
    data_with_keys.sort(key=lambda x: x[0], reverse=reverse_sort)

    # Rearrange items in tree
    for index, (_, item, _) in enumerate(data_with_keys):
        tree.move(item, "", index)

    # Update header with visual indicator
    indicator = " (↓)" if new_sort_direction == "desc" else " (↑)"
    _set_header_text(tree, column, f"{original_headers[column]}{indicator}")

    # Restore selection and focus
    if selected_items:
        # Filter out any items that no longer exist
        valid_items = [item for item in selected_items if tree.exists(item)]
        if valid_items:
            tree.selection_set(valid_items)

    if focused_item and tree.exists(focused_item):
        tree.focus(focused_item)

    return column, new_sort_direction


def handle_treeview_click(tree, event, settings_manager, callbacks):
    """
    Handle treeview clicks, specifically for favorite and avoid column toggles.

    Args:
        tree: TreeView widget
        event: Click event
        settings_manager: Settings manager for favorites/avoid operations
        callbacks: Dict of callbacks for re-applying filters

    Returns:
        str or None: "break" if event was consumed, None otherwise
    """
    column = tree.identify_column(event.x)
    item = tree.identify_row(event.y)

    if not item or not settings_manager:
        return None

    values = tree.item(item)["values"]
    if not values or len(values) < 5:
        return None

    ip_address = values[4]  # IP is now at index 4

    # Handle favorite column clicks (#1, since #0 hidden)
    if column == '#1':
        # Toggle favorite status
        is_now_favorite = settings_manager.toggle_favorite_server(ip_address)
        try:
            if callbacks.get('on_favorite_toggle'):
                callbacks['on_favorite_toggle'](ip_address, is_now_favorite)
        except Exception:
            pass
        star = "★" if is_now_favorite else "☆"
        tree.set(item, "favorite", star)

        # Re-apply filters if favorites-only is enabled
        if callbacks.get('on_favorites_filter_changed'):
            callbacks['on_favorites_filter_changed']()

        # Maintain focus/selection only if row still exists (filters may remove it)
        if tree.exists(item):
            tree.selection_set(item)
            tree.focus(item)

        return "break"  # Only consume event when we actually toggled

    # Handle avoid column clicks (#2)
    elif column == '#2':
        # Toggle avoid status
        is_now_avoided = settings_manager.toggle_avoid_server(ip_address)
        try:
            if callbacks.get('on_avoid_toggle'):
                callbacks['on_avoid_toggle'](ip_address, is_now_avoided)
        except Exception:
            pass
        skull = "☠" if is_now_avoided else "💀"
        tree.set(item, "avoid", skull)

        # Re-apply filters if avoid-only is enabled
        if callbacks.get('on_avoid_filter_changed'):
            callbacks['on_avoid_filter_changed']()

        # Maintain focus/selection only if row still exists (filters may remove it)
        if tree.exists(item):
            tree.selection_set(item)
            tree.focus(item)

        return "break"  # Only consume event when we actually toggled

    return None


def handle_double_click(tree, event, filtered_servers: List[Dict[str, Any]], detail_callback: Callable, parent_window=None):
    """
    Handle double-click on table row - equivalent to select + View Details button.

    Args:
        tree: TreeView widget
        event: Double-click event
        filtered_servers: List of currently displayed servers
        detail_callback: Callback function to show server details
        parent_window: Optional parent window for messageboxes

    Returns:
        bool: True if handled successfully, False otherwise
    """
    # Check if the double-click was on a header - if so, ignore to prevent popup interference
    region = tree.identify_region(event.x, event.y)
    if region == "heading":
        return False

    # File browser UX: identify exactly which row was double-clicked
    clicked_item = tree.identify_row(event.y)

    if not clicked_item:
        # Error handling: double-click didn't hit a valid data row
        messagebox.showwarning("Invalid Selection", "Please double-click on a server entry to view details.", parent=parent_window)
        return False

    # File browser UX: select the double-clicked row for visual feedback
    tree.selection_set(clicked_item)

    # Use identical logic as "View Details" button - get data from clicked row
    values = tree.item(clicked_item)["values"]
    if not values or len(values) < 5:
        messagebox.showerror("Error", "Unable to retrieve server data.", parent=parent_window)
        return False

    ip_address = values[4]  # IP Address now at index 4 (fav/avoid/probe/extracted columns)

    # Same data lookup as working "View Details" button
    server_data = next(
        (server for server in filtered_servers if server.get("ip_address") == ip_address),
        None
    )

    if not server_data:
        # Same error message as "View Details" button for consistency
        messagebox.showerror("Error", "Server data not found.", parent=parent_window)
        return False

    # Call the detail callback
    detail_callback(server_data)
    return True


def select_all_items(tree):
    """Select all items in table."""
    tree.selection_set(tree.get_children())


def _set_header_text(tree, column: str, text: str):
    """Helper to update column header text."""
    tree.heading(column, text=text)
