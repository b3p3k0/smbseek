"""
SMBSeek Safety and Sanitization Utilities

Input sanitization and validation helpers implementing the security audit requirements.
Provides defense against malicious input from SMB servers and user-supplied data.
"""

import re
import string
from typing import Optional, Union, List


def strip_control(text: str) -> str:
    """
    Strip control characters, NULs, and ANSI escape sequences from text.
    
    This function implements the audit requirement for control character
    stripping to prevent terminal injection and parsing attacks.
    
    Args:
        text: Input text that may contain control characters
        
    Returns:
        Sanitized text with control characters removed
    """
    if not isinstance(text, str):
        return str(text)
    
    # First remove ANSI escape sequences before filtering characters
    # Match \x1B[ followed by numbers/semicolons, ending with a letter
    ansi_escape = re.compile(r'\x1B\[[0-9;]*[A-Za-z]')
    cleaned = ansi_escape.sub('', text)
    
    # Remove NULL bytes and other control characters (except newline, tab, carriage return)
    printable_chars = set(string.printable)
    allowed_control = {'\n', '\t', '\r'}
    
    # Second pass: remove dangerous control characters
    cleaned = ''.join(
        char for char in cleaned 
        if char in printable_chars or char in allowed_control
    )
    
    # Remove any remaining dangerous sequences
    # Bell character, backspace, form feed, vertical tab
    dangerous_chars = ['\x07', '\x08', '\x0c', '\x0b']
    for char in dangerous_chars:
        cleaned = cleaned.replace(char, '')
    
    return cleaned


def validate_share_name(name: str, max_len: int = 80) -> bool:
    """
    Validate SMB share name for safety and reasonableness.
    
    Implements audit requirements for share name validation to prevent
    parser abuse and path traversal attacks.
    
    Args:
        name: Share name to validate
        max_len: Maximum allowed length
        
    Returns:
        True if share name is valid and safe
    """
    if not isinstance(name, str):
        return False
    
    if not name or len(name) > max_len:
        return False
    
    # Only allow printable ASCII characters (excludes control chars)  
    if not all(32 <= ord(c) <= 126 for c in name):
        return False
    
    # Disallow dangerous characters that could cause issues
    dangerous_chars = ['/', '\\', ':', '*', '?', '"', '<', '>', '|', '\0']
    if any(char in name for char in dangerous_chars):
        return False
    
    # Disallow names that could cause path traversal
    if name in ['.', '..'] or name.startswith('.'):
        return False
    
    # Disallow Windows reserved names
    reserved_names = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    if name.upper() in reserved_names:
        return False
    
    return True


def sanitize_csv_cell(value: str) -> str:
    """
    Sanitize CSV cell value to prevent formula injection attacks.
    
    Implements audit requirements for CSV export security by prefixing
    cells that start with formula characters.
    
    Args:
        value: Cell value to sanitize
        
    Returns:
        Sanitized cell value safe for CSV export
    """
    if not isinstance(value, str):
        value = str(value)
    
    # Strip control characters first
    value = strip_control(value)
    
    # Formula injection characters that could be interpreted by Excel/Calc
    formula_chars = ['=', '+', '-', '@', '\t', '\r']
    
    # Prefix with single quote if starts with dangerous character
    if value and value[0] in formula_chars:
        return "'" + value
    
    return value


def sanitize_hostname(hostname: str) -> Optional[str]:
    """
    Sanitize and validate hostname for network operations.
    
    Args:
        hostname: Hostname or IP address to validate
        
    Returns:
        Sanitized hostname or None if invalid
    """
    if not isinstance(hostname, str):
        return None
    
    hostname = hostname.strip()
    
    # Check for control characters before stripping (more strict)
    if any(ord(c) < 32 or ord(c) > 126 for c in hostname):
        return None
    
    hostname = strip_control(hostname)
    
    if not hostname or len(hostname) > 253:
        return None
    
    # Basic hostname/IP validation (not exhaustive, but catches obvious attacks)
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        return None
    
    # Reject obviously malicious patterns
    if '..' in hostname or '--' in hostname:
        return None
    
    if hostname.startswith('.') or hostname.endswith('.'):
        return None
    
    return hostname


def sanitize_log_message(message: str, max_length: int = 1000) -> str:
    """
    Sanitize log message to prevent log injection attacks.
    
    Args:
        message: Log message to sanitize
        max_length: Maximum allowed message length
        
    Returns:
        Sanitized log message
    """
    if not isinstance(message, str):
        message = str(message)
    
    # Strip control characters to prevent terminal injection
    message = strip_control(message)
    
    # Truncate if too long
    if len(message) > max_length:
        message = message[:max_length] + "... [TRUNCATED]"
    
    # Replace newlines with spaces to prevent log splitting
    message = re.sub(r'[\r\n]+', ' ', message)
    
    return message


def validate_port_number(port: Union[str, int]) -> Optional[int]:
    """
    Validate and sanitize port number.
    
    Args:
        port: Port number as string or int
        
    Returns:
        Valid port number or None if invalid
    """
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return port_num
    except (ValueError, TypeError):
        pass
    
    return None


def enforce_string_limits(
    value: str,
    max_length: int,
    name: str = "value",
    truncate: bool = True
) -> str:
    """
    Enforce string length limits with optional truncation.
    
    Args:
        value: String value to check
        max_length: Maximum allowed length
        name: Name of the value for error messages
        truncate: If True, truncate; if False, raise exception
        
    Returns:
        Original or truncated string
        
    Raises:
        ValueError: If string too long and truncate=False
    """
    if not isinstance(value, str):
        value = str(value)
    
    if len(value) <= max_length:
        return value
    
    if truncate:
        return value[:max_length] + "..."
    else:
        raise ValueError(f"{name} exceeds maximum length of {max_length} characters")


def sanitize_sql_like_pattern(pattern: str) -> str:
    """
    Sanitize user input for SQL LIKE patterns.
    
    Args:
        pattern: User-provided pattern
        
    Returns:
        Escaped pattern safe for SQL LIKE operations
    """
    if not isinstance(pattern, str):
        pattern = str(pattern)
    
    # Strip control characters
    pattern = strip_control(pattern)
    
    # Escape SQL special characters for LIKE
    pattern = pattern.replace('\\', '\\\\')  # Escape backslashes first
    pattern = pattern.replace('%', '\\%')    # Escape percent
    pattern = pattern.replace('_', '\\_')    # Escape underscore
    pattern = pattern.replace("'", "''")     # Escape single quotes
    
    return pattern


def is_safe_filename(filename: str, max_length: int = 255) -> bool:
    """
    Check if filename is safe for file operations.
    
    Args:
        filename: Filename to validate
        max_length: Maximum filename length
        
    Returns:
        True if filename is safe
    """
    if not isinstance(filename, str):
        return False
    
    if not filename or len(filename) > max_length:
        return False
    
    # Check for path traversal attempts
    if '..' in filename or '/' in filename or '\\' in filename:
        return False
    
    # Check for control characters
    if any(ord(c) < 32 for c in filename):
        return False
    
    # Check for dangerous characters
    dangerous = ['<', '>', ':', '"', '|', '?', '*', '\0']
    if any(char in filename for char in dangerous):
        return False
    
    # Check for Windows reserved names
    base_name = filename.split('.')[0].upper()
    reserved = {
        'CON', 'PRN', 'AUX', 'NUL',
        'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
        'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
    }
    if base_name in reserved:
        return False
    
    return True


class SecurityLimits:
    """
    Centralized security limits for SMBSeek operations.
    
    This class provides constants for the audit-required limits
    and validation methods.
    """
    
    # Process limits
    MAX_PROCESS_TIMEOUT = 600  # 10 minutes
    MAX_OUTPUT_SIZE = 100_000_000  # 100MB
    DEFAULT_TIMEOUT = 30
    DEFAULT_OUTPUT_SIZE = 50_000
    
    # SMB limits  
    MAX_SHARES_PER_HOST = 256
    MAX_SHARE_NAME_LENGTH = 80
    MAX_PDU_SIZE = 65536
    
    # String limits
    MAX_HOSTNAME_LENGTH = 253
    MAX_LOG_MESSAGE_LENGTH = 1000
    MAX_FILENAME_LENGTH = 255
    
    # Database limits
    MAX_SQL_QUERY_LENGTH = 10000
    MAX_BATCH_SIZE = 1000
    
    @classmethod
    def validate_limits(cls, **kwargs) -> dict:
        """
        Validate multiple limits at once.
        
        Returns:
            Dictionary of validation results
        """
        results = {}
        
        if 'timeout' in kwargs:
            results['timeout'] = 1 <= kwargs['timeout'] <= cls.MAX_PROCESS_TIMEOUT
            
        if 'output_size' in kwargs:
            results['output_size'] = 1 <= kwargs['output_size'] <= cls.MAX_OUTPUT_SIZE
            
        if 'share_count' in kwargs:
            results['share_count'] = 0 <= kwargs['share_count'] <= cls.MAX_SHARES_PER_HOST
            
        if 'share_name' in kwargs:
            results['share_name'] = validate_share_name(
                kwargs['share_name'], cls.MAX_SHARE_NAME_LENGTH
            )
        
        return results