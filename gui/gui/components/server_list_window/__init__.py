"""
Server List Window Package

Re-exports ServerListWindow and compatibility function for clean imports
while maintaining modular internal structure.
"""

from .window import ServerListWindow, open_server_list_window

__all__ = ['ServerListWindow', 'open_server_list_window']