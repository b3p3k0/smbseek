"""
SMBSeek GUI Styling and Theme Management

Provides consistent styling, colors, and theme management across all GUI components.
Implements cross-platform styling with accessibility considerations.

Design Decision: Centralized styling ensures consistent appearance and makes
theme changes easy to implement across the entire application.
"""

import tkinter as tk
from tkinter import ttk
from typing import Dict, Any, Optional
import sys


class SMBSeekTheme:
    """
    Theme manager for SMBSeek GUI.
    
    Provides consistent colors, fonts, and styling across all components.
    Handles platform-specific adjustments and accessibility options.
    
    Design Decision: Centralized theme management allows easy customization
    and ensures visual consistency throughout the application.
    """
    
    def __init__(self, use_dark_mode: bool = False):
        """
        Initialize theme manager.
        
        Args:
            use_dark_mode: Whether to use dark theme (future enhancement)
        """
        self.use_dark_mode = use_dark_mode
        self.platform = sys.platform
        
        # Color palette - inspired by security tool interfaces
        self.colors = self._define_colors()
        self.fonts = self._define_fonts()
        self.styles = self._define_component_styles()
    
    def _define_colors(self) -> Dict[str, str]:
        """
        Define color palette for the application.
        
        Returns:
            Dictionary mapping color names to hex values
            
        Design Decision: Professional security tool aesthetic with
        high contrast for accessibility and clear status indication.
        """
        if self.use_dark_mode:
            return {
                # Dark theme (future enhancement)
                "primary_bg": "#2d2d2d",
                "secondary_bg": "#3d3d3d",
                "text": "#ffffff",
                "success": "#4caf50",
                "warning": "#ff9800",
                "error": "#f44336",
                "info": "#2196f3",
                "accent": "#673ab7"
            }
        else:
            return {
                # Light theme - current implementation
                "primary_bg": "#ffffff",
                "secondary_bg": "#f5f5f5",
                "card_bg": "#fafafa",
                "border": "#e0e0e0",
                "text": "#212121",
                "text_secondary": "#666666",
                "success": "#4caf50",
                "warning": "#ff9800",
                "error": "#f44336",
                "info": "#2196f3",
                "critical": "#d32f2f",
                "high": "#f57c00",
                "medium": "#fbc02d",
                "low": "#689f38",
                "accent": "#1976d2",
                "hover": "#e3f2fd",
                # Log viewer colors (dark terminal-style background)
                "log_bg": "#111418",
                "log_fg": "#f5f5f5",
                "log_placeholder": "#9ea4b3",
                # ANSI terminal colors for log output
                "ansi_black": "#7f8796",
                "ansi_red": "#ff7676",
                "ansi_green": "#7dd87d",
                "ansi_yellow": "#ffd666",
                "ansi_blue": "#76b9ff",
                "ansi_magenta": "#d692ff",
                "ansi_cyan": "#4dd0e1",
                "ansi_white": "#f5f5f5",
                "ansi_bright_black": "#a0a7b4",
                "ansi_bright_red": "#ff8b8b",
                "ansi_bright_green": "#8ef79a",
                "ansi_bright_yellow": "#ffe082",
                "ansi_bright_blue": "#90c8ff",
                "ansi_bright_magenta": "#f78bff",
                "ansi_bright_cyan": "#6fe8ff",
                "ansi_bright_white": "#ffffff"
            }
    
    def _define_fonts(self) -> Dict[str, tuple]:
        """
        Define font families and sizes.
        
        Returns:
            Dictionary mapping font purposes to (family, size, weight) tuples
            
        Design Decision: Platform-appropriate fonts with good readability
        for security data and sufficient size hierarchy.
        """
        # Platform-specific font preferences
        if self.platform == "darwin":  # macOS
            default_family = "SF Pro Display"
            mono_family = "SF Mono"
        elif self.platform == "win32":  # Windows
            default_family = "Segoe UI"
            mono_family = "Consolas"
        else:  # Linux and others
            default_family = "Ubuntu"
            mono_family = "Ubuntu Mono"
        
        return {
            "title": (default_family, 18, "bold"),
            "heading": (default_family, 14, "bold"),
            "body": (default_family, 10, "normal"),
            "small": (default_family, 9, "normal"),
            "mono": (mono_family, 10, "normal"),
            "mono_small": (mono_family, 9, "normal"),
            "button": (default_family, 10, "normal"),
            "status": (default_family, 9, "normal")
        }
    
    def _define_component_styles(self) -> Dict[str, Dict[str, Any]]:
        """
        Define styling for specific component types.
        
        Returns:
            Dictionary mapping component types to style dictionaries
        """
        return {
            "main_window": {
                "bg": self.colors["primary_bg"],
                "relief": "flat"
            },
            "card": {
                "bg": self.colors["card_bg"],
                "relief": "solid",
                "borderwidth": 1
            },
            "metric_card": {
                "bg": self.colors["card_bg"],
                "relief": "solid",
                "borderwidth": 1,
                "padx": 15,
                "pady": 15,
                "cursor": "hand2"
            },
            "button_primary": {
                "bg": self.colors["accent"],
                "fg": "white",
                "relief": "flat",
                "borderwidth": 0,
                "cursor": "hand2",
                "font": self.fonts["button"]
            },
            "button_secondary": {
                "bg": self.colors["secondary_bg"],
                "fg": self.colors["text"],
                "relief": "solid",
                "borderwidth": 1,
                "cursor": "hand2",
                "font": self.fonts["button"]
            },
            "button_danger": {
                "bg": self.colors["error"],
                "fg": "white",
                "relief": "flat",
                "borderwidth": 0,
                "cursor": "hand2",
                "font": self.fonts["button"]
            },
            "button_disabled": {
                "bg": "#cccccc",
                "fg": "#666666",
                "relief": "flat",
                "borderwidth": 0,
                "cursor": "arrow",
                "font": self.fonts["button"]
            },
            "status_bar": {
                "bg": self.colors["secondary_bg"],
                "fg": self.colors["text_secondary"],
                "relief": "sunken",
                "borderwidth": 1,
                "font": self.fonts["status"]
            },
            "progress_bar": {
                "troughcolor": self.colors["secondary_bg"],
                "background": self.colors["accent"],
                "borderwidth": 0,
                "relief": "flat"
            }
        }
    
    def apply_to_widget(self, widget: tk.Widget, style_name: str) -> None:
        """
        Apply named style to a widget.
        
        Args:
            widget: Tkinter widget to style
            style_name: Name of style from styles dictionary
        """
        if style_name in self.styles:
            style_dict = self.styles[style_name].copy()
            widget_type = widget.winfo_class() if hasattr(widget, 'winfo_class') else type(widget).__name__

            # Special handling for Toplevel windows
            if widget_type in ["Toplevel", "Tk"]:
                # Only set background color for window
                bg = style_dict.get("bg") or style_dict.get("background")
                if bg:
                    try:
                        widget.configure(background=bg)
                    except Exception:
                        try:
                            widget['background'] = bg
                        except Exception:
                            pass
                return

            # Remove options that don't apply to all widgets
            if widget_type == "Frame":
                style_dict.pop("fg", None)
            # ...existing code for other widget types...
            try:
                widget.configure(**style_dict)
            except tk.TclError as e:
                for key, value in style_dict.items():
                    try:
                        widget.configure(**{key: value})
                    except tk.TclError:
                        continue
    
    def get_severity_color(self, severity: str) -> str:
        """
        Get color for security vulnerability severity.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            Hex color code for the severity level
        """
        severity_lower = severity.lower()
        if severity_lower in self.colors:
            return self.colors[severity_lower]
        else:
            return self.colors["text_secondary"]  # Default for unknown
    
    def get_status_color(self, is_success: bool) -> str:
        """
        Get color for status indication.
        
        Args:
            is_success: Whether status represents success or failure
            
        Returns:
            Hex color code for status
        """
        return self.colors["success"] if is_success else self.colors["error"]
    
    def create_hover_effect(self, widget: tk.Widget, hover_bg: Optional[str] = None) -> None:
        """
        Add hover effect to a widget.
        
        Args:
            widget: Widget to add hover effect to
            hover_bg: Background color on hover (default: theme hover color)
        """
        original_bg = widget.cget("bg")
        hover_color = hover_bg or self.colors["hover"]
        
        def on_enter(event):
            widget.configure(bg=hover_color)
        
        def on_leave(event):
            widget.configure(bg=original_bg)
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
    
    def setup_ttk_styles(self, root: tk.Tk) -> None:
        """
        Configure ttk styles for themed widgets.
        
        Args:
            root: Root tkinter window
            
        Design Decision: Use ttk for progress bars and other complex widgets
        that benefit from native theming while maintaining custom colors.
        """
        style = ttk.Style(root)
        
        # Configure progress bar style
        style.theme_use('clam')  # Use clam theme as base
        
        style.configure(
            "SMBSeek.Horizontal.TProgressbar",
            **self.styles["progress_bar"]
        )
        
        # Configure button styles
        style.configure(
            "SMBSeek.TButton",
            background=self.colors["accent"],
            foreground="white",
            borderwidth=0,
            focuscolor="none"
        )
        
        style.map(
            "SMBSeek.TButton",
            background=[("active", self.colors["info"])]
        )
    
    def get_icon_symbol(self, icon_type: str) -> str:
        """
        Get Unicode symbol for common icons.
        
        Args:
            icon_type: Type of icon needed
            
        Returns:
            Unicode symbol string
            
        Design Decision: Use Unicode symbols instead of image files
        for simplicity and cross-platform compatibility.
        """
        icons = {
            "success": "✓",
            "error": "✗",
            "warning": "⚠",
            "info": "ℹ",
            "scan": "🔍",
            "database": "🗄",
            "settings": "⚙",
            "report": "📊",
            "server": "🖥",
            "share": "📁",
            "vulnerability": "🔴",
            "country": "🌍",
            "time": "⏰",
            "arrow_right": "→",
            "arrow_down": "↓",
            "refresh": "🔄"
        }
        
        return icons.get(icon_type, "•")
    
    def create_separator(self, parent: tk.Widget, orientation: str = "horizontal") -> ttk.Separator:
        """
        Create styled separator widget.
        
        Args:
            parent: Parent widget
            orientation: "horizontal" or "vertical"
            
        Returns:
            Configured separator widget
        """
        separator = ttk.Separator(parent, orient=orientation)
        return separator
    
    def create_styled_label(self, parent: tk.Widget, text: str, 
                           style_type: str = "body", **kwargs) -> tk.Label:
        """
        Create label with theme styling.
        
        Args:
            parent: Parent widget
            text: Label text
            style_type: Font style type from fonts dictionary
            **kwargs: Additional label options
            
        Returns:
            Configured label widget
        """
        font_config = self.fonts.get(style_type, self.fonts["body"])
        
        # Extract fg from kwargs if present, otherwise use theme default
        fg_color = kwargs.pop("fg", self.colors["text"])
        
        label = tk.Label(
            parent,
            text=text,
            font=font_config,
            bg=self.colors["primary_bg"],
            fg=fg_color,
            **kwargs
        )
        
        return label
    
    def create_metric_card_frame(self, parent: tk.Widget) -> tk.Frame:
        """
        Create styled frame for metric cards.
        
        Args:
            parent: Parent widget
            
        Returns:
            Configured frame widget for metric display
        """
        frame = tk.Frame(parent)
        self.apply_to_widget(frame, "metric_card")
        self.create_hover_effect(frame)
        
        return frame


# Global theme instance
theme = SMBSeekTheme()


def get_theme() -> SMBSeekTheme:
    """Get the global theme instance."""
    return theme


def apply_theme_to_window(window: tk.Tk) -> None:
    """
    Apply theme to main window.
    
    Args:
        window: Main application window
    """
    theme.apply_to_widget(window, "main_window")
    theme.setup_ttk_styles(window)