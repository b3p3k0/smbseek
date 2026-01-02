"""
Dialog helper utilities for consistent window management.

This module provides utility functions for managing Tkinter dialogs and popup
windows, particularly focusing on ensuring proper focus and z-order behavior
in VM and multi-monitor environments.
"""

import tkinter as tk


def ensure_dialog_focus(dialog_window, parent=None):
    """
    Ensure dialog window appears on top and gains focus.

    This function is critical for VM environments where dialogs may appear
    behind their parent windows, creating a false impression that the
    application has hung (since other windows become unresponsive due to
    modal grab_set() behavior).

    The function uses multiple techniques to ensure the dialog is visible:
    1. Processes pending geometry updates
    2. Lifts window to front of window stack
    3. Forces keyboard focus to the dialog
    4. Temporarily sets topmost attribute (platform-specific)

    Args:
        dialog_window: The Toplevel window to bring to front
        parent: Optional parent window to explicitly lift above

    Usage:
        # In dialog creation code:
        dialog = tk.Toplevel(parent)
        dialog.title("My Dialog")
        dialog.transient(parent)
        dialog.grab_set()

        # ... build dialog UI ...

        # Call this as final step to ensure visibility
        ensure_dialog_focus(dialog, parent)

    Notes:
        - This should be called AFTER the dialog UI is fully built
        - This should be called AFTER .transient() and .grab_set()
        - The parent parameter is optional but recommended for nested dialogs
    """
    # Ensure all pending geometry updates are processed first
    # This is critical - without it, lift/focus may not work correctly
    dialog_window.update_idletasks()

    # Bring window to front of window stack
    dialog_window.lift()

    # If parent specified, ensure we're explicitly above that parent
    # This is important for nested dialogs (dialog spawning another dialog)
    if parent:
        dialog_window.lift(parent)

    # Force keyboard focus to this window
    # This ensures the dialog can receive keyboard input immediately
    dialog_window.focus_force()

    # Additional platform-specific handling for stubborn window managers
    # The topmost trick temporarily marks window as always-on-top, then
    # removes that flag. This forces some window managers to re-evaluate
    # the window's z-order position.
    try:
        dialog_window.attributes('-topmost', True)
        dialog_window.attributes('-topmost', False)
    except tk.TclError:
        # Some platforms don't support -topmost attribute
        # This is fine - the lift() and focus_force() should be sufficient
        pass
