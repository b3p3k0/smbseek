"""
Non-modal status dialog for Pry runs.
"""

import tkinter as tk
from tkinter import ttk
from pathlib import Path
from typing import Callable, Optional


class PryStatusDialog:
    """Lightweight status window that can be hidden and reopened."""

    def __init__(
        self,
        parent: tk.Toplevel,
        theme,
        *,
        host: str,
        username: str,
        share: str,
        wordlist_path: str,
        on_cancel: Callable[[], None],
    ):
        self.parent = parent
        self.theme = theme
        self.on_cancel = on_cancel

        self.window = tk.Toplevel(parent)
        self.window.title("Pry Status")
        self.window.transient(parent)

        if self.theme:
            self.theme.apply_to_widget(self.window, "main_window")

        self.host_var = tk.StringVar(value=host or "-")
        self.user_var = tk.StringVar(value=username or "-")
        self.share_var = tk.StringVar(value=share or "-")
        self.wordlist_var = tk.StringVar(value=Path(wordlist_path).name if wordlist_path else "-")
        self.attempts_var = tk.StringVar(value="0/?")
        self.last_event_var = tk.StringVar(value="Starting…")
        self.status_var = tk.StringVar(value="Running")

        self._cancel_button: Optional[tk.Button] = None
        self._hide_button: Optional[tk.Button] = None

        self._build_layout()

        self.window.protocol("WM_DELETE_WINDOW", self.hide)
        self.show()

    # Layout helpers -----------------------------------------------------
    def _build_layout(self) -> None:
        main = tk.Frame(self.window)
        main.pack(fill=tk.BOTH, expand=True, padx=14, pady=12)

        def row(label_text: str, var: tk.StringVar):
            row_frame = tk.Frame(main)
            row_frame.pack(fill=tk.X, pady=2)
            tk.Label(row_frame, text=label_text, width=14, anchor="w").pack(side=tk.LEFT)
            ttk.Label(row_frame, textvariable=var).pack(side=tk.LEFT, fill=tk.X, expand=True)

        row("Host", self.host_var)
        row("Username", self.user_var)
        row("Share", self.share_var)
        row("Wordlist", self.wordlist_var)
        row("Attempts", self.attempts_var)
        row("Status", self.status_var)

        event_frame = tk.Frame(main)
        event_frame.pack(fill=tk.X, pady=(8, 4))
        tk.Label(event_frame, text="Last event", anchor="w").pack(side=tk.TOP, anchor="w")
        ttk.Label(event_frame, textvariable=self.last_event_var, wraplength=420, justify="left").pack(
            side=tk.TOP, anchor="w", fill=tk.X, expand=True
        )

        btn_frame = tk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        self._hide_button = tk.Button(btn_frame, text="Hide", command=self.hide)
        self._cancel_button = tk.Button(btn_frame, text="Cancel", command=self.on_cancel)
        if self.theme:
            self.theme.apply_to_widget(self._hide_button, "button_secondary")
            self.theme.apply_to_widget(self._cancel_button, "button_primary")
        self._cancel_button.pack(side=tk.RIGHT, padx=(6, 0))
        self._hide_button.pack(side=tk.RIGHT, padx=(0, 6))

    # Public API ---------------------------------------------------------
    def show(self) -> None:
        if not self.window:
            return
        try:
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
        except Exception:
            pass

    def hide(self) -> None:
        if not self.window:
            return
        try:
            self.window.withdraw()
        except Exception:
            pass

    def destroy(self) -> None:
        if not self.window:
            return
        try:
            self.window.destroy()
        except Exception:
            pass
        self.window = None

    def update_progress(self, attempts: int, total: Optional[int], message: Optional[str] = None) -> None:
        total_display = total if total and total > 0 else "?"
        self.attempts_var.set(f"{attempts}/{total_display}")
        if message:
            self.last_event_var.set(message)

    def mark_finished(self, status: str, notes: str) -> None:
        self.status_var.set(status.title())
        if notes:
            self.last_event_var.set(notes)
        if self._cancel_button:
            self._cancel_button.configure(state=tk.DISABLED)
        if self._hide_button:
            self._hide_button.configure(text="Close")

    def is_visible(self) -> bool:
        if not self.window:
            return False
        return bool(self.window.state() != "withdrawn")


__all__ = ["PryStatusDialog"]
