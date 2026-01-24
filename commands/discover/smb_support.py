"""
Shared SMB protocol imports for discovery authentication routines.
"""

try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.exceptions import SMBException
    SMB_AVAILABLE = True
except ImportError:
    Connection = None
    Session = None
    SMBException = None
    SMB_AVAILABLE = False

__all__ = ["Connection", "Session", "SMBException", "SMB_AVAILABLE"]
