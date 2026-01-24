"""
Shared SMB protocol availability check for access operations.
"""

SMB_AVAILABLE = False
try:
    from smbprotocol.connection import Connection
    from smbprotocol.session import Session
    from smbprotocol.tree import TreeConnect
    from smbprotocol.open import Open, CreateDisposition, ImpersonationLevel, FileAttributes, ShareAccess
    from smbprotocol.exceptions import SMBException
    import uuid
    SMB_AVAILABLE = True
except ImportError:
    Connection = None  # type: ignore
    Session = None  # type: ignore
    TreeConnect = None  # type: ignore
    Open = None  # type: ignore
    CreateDisposition = None  # type: ignore
    ImpersonationLevel = None  # type: ignore
    FileAttributes = None  # type: ignore
    ShareAccess = None  # type: ignore
    SMBException = None  # type: ignore
    uuid = None  # type: ignore

__all__ = [
    "Connection",
    "Session",
    "TreeConnect",
    "Open",
    "CreateDisposition",
    "ImpersonationLevel",
    "FileAttributes",
    "ShareAccess",
    "SMBException",
    "uuid",
    "SMB_AVAILABLE",
]
