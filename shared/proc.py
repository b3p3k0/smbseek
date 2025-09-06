"""
SMBSeek Safe Process Execution

Centralized safe subprocess execution with strict security controls.
Implements the security requirements from the audit for process hardening.
"""

import subprocess
import time
from typing import List, Dict, Optional, NamedTuple, Any


class CompletedProcessLike(NamedTuple):
    """
    Standardized process result structure.
    
    Mimics subprocess.CompletedProcess but with additional safety guarantees.
    """
    returncode: int
    stdout: str
    stderr: str
    timeout_exceeded: bool = False
    output_truncated: bool = False
    original_stdout_size: int = 0


class ProcessExecutionError(Exception):
    """Raised when process execution fails security validation."""
    pass


class ProcessTimeoutError(Exception):
    """Raised when process exceeds timeout limits."""
    pass


class ProcessOutputError(Exception):
    """Raised when process output exceeds size limits."""
    pass


def run_safe(
    argv: List[str],
    timeout: int,
    max_stdout_bytes: int,
    env: Optional[Dict[str, str]] = None,
    stdin_data: Optional[str] = None,
    check_returncode: bool = False
) -> CompletedProcessLike:
    """
    Execute subprocess with strict security controls.
    
    Security features:
    - Never uses shell=True (argv list only)
    - Enforces timeout limits  
    - Caps stdout size with truncation
    - Sets secure environment defaults
    - Prevents stdin injection attacks
    
    Args:
        argv: Command and arguments as list (never uses shell)
        timeout: Maximum execution time in seconds
        max_stdout_bytes: Maximum stdout size before truncation
        env: Environment variables (defaults to secure minimal set)
        stdin_data: Optional data to send to stdin
        check_returncode: Raise exception on non-zero return codes
        
    Returns:
        CompletedProcessLike with results and safety metadata
        
    Raises:
        ProcessExecutionError: Invalid arguments or security violation
        ProcessTimeoutError: Process exceeded timeout
        ProcessOutputError: Output exceeded size limits
        FileNotFoundError: Command not found
    """
    # Validate arguments
    if not argv or not isinstance(argv, list):
        raise ProcessExecutionError("argv must be a non-empty list")
    
    if not isinstance(argv[0], str) or not argv[0].strip():
        raise ProcessExecutionError("Command cannot be empty")
    
    if timeout <= 0 or timeout > 600:  # Max 10 minutes
        raise ProcessExecutionError("Timeout must be between 1-600 seconds")
    
    if max_stdout_bytes <= 0 or max_stdout_bytes > 100_000_000:  # Max 100MB
        raise ProcessExecutionError("max_stdout_bytes must be between 1-100MB")
    
    # Set secure environment defaults
    if env is None:
        env = {}
    
    secure_env = {
        'LC_ALL': 'C',
        'PATH': '/usr/bin:/bin',
        'LANG': 'C',
        'HOME': '/tmp',
        'USER': 'nobody'
    }
    secure_env.update(env)
    
    # Prepare stdin
    stdin_input = None if stdin_data is None else stdin_data.encode('utf-8')
    
    start_time = time.time()
    timeout_exceeded = False
    output_truncated = False
    original_stdout_size = 0
    
    try:
        # Execute with security controls
        process = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
            env=secure_env,
            shell=False,  # NEVER use shell=True
            text=True,
            encoding='utf-8',
            errors='replace'  # Handle encoding errors gracefully
        )
        
        # Communicate with timeout
        try:
            stdout, stderr = process.communicate(
                input=stdin_input.decode('utf-8') if stdin_input else None,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            # Kill process and collect partial output
            process.kill()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                # Force termination
                process.terminate()
                stdout, stderr = "", "Process forcefully terminated due to timeout"
            timeout_exceeded = True
        
        # Check output size and truncate if necessary
        original_stdout_size = len(stdout.encode('utf-8'))
        if original_stdout_size > max_stdout_bytes:
            # Truncate to max size with warning
            stdout_bytes = stdout.encode('utf-8')[:max_stdout_bytes]
            stdout = stdout_bytes.decode('utf-8', errors='replace')
            stdout += f"\n[OUTPUT TRUNCATED: {original_stdout_size} bytes > {max_stdout_bytes} limit]"
            output_truncated = True
        
        # Truncate stderr similarly (smaller limit)
        stderr_limit = min(max_stdout_bytes // 4, 10000)  # Quarter of stdout limit or 10KB
        if len(stderr.encode('utf-8')) > stderr_limit:
            stderr_bytes = stderr.encode('utf-8')[:stderr_limit]
            stderr = stderr_bytes.decode('utf-8', errors='replace')
            stderr += "\n[STDERR TRUNCATED]"
        
        execution_time = time.time() - start_time
        
        # Create result object
        result = CompletedProcessLike(
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr,
            timeout_exceeded=timeout_exceeded,
            output_truncated=output_truncated,
            original_stdout_size=original_stdout_size
        )
        
        # Check for timeout violation
        if timeout_exceeded:
            raise ProcessTimeoutError(f"Process exceeded timeout of {timeout} seconds")
        
        # Check for output size violation (if strict checking requested)
        if output_truncated and max_stdout_bytes < 50000:  # Strict mode for small limits
            raise ProcessOutputError(
                f"Process output {original_stdout_size} bytes exceeded limit {max_stdout_bytes}"
            )
        
        # Check return code if requested
        if check_returncode and process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, argv, stdout, stderr
            )
        
        return result
        
    except (ProcessTimeoutError, ProcessOutputError):
        # Re-raise our specific exceptions
        raise
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Command not found: {argv[0]}") from e
    except OSError as e:
        raise ProcessExecutionError(f"OS error executing command: {e}") from e
    except Exception as e:
        raise ProcessExecutionError(f"Unexpected error: {e}") from e


def run_smbclient_safe(
    host: str,
    share: Optional[str] = None,
    username: str = "",
    password: str = "",
    additional_options: Optional[List[str]] = None,
    timeout: int = 30,
    max_output_bytes: int = 50000,
    list_shares: bool = True
) -> CompletedProcessLike:
    """
    Execute smbclient with security hardening for SMBSeek operations.
    
    This function implements the audit requirements for SMB client execution:
    - Enforces protocol pinning (SMB2/3 by default, NT1 for SMB1 mode)
    - Requires signing where applicable
    - Uses safe subprocess execution
    - Implements timeout and output limits
    
    Args:
        host: Target hostname or IP address
        share: Share name (optional, for share-specific operations)
        username: Username for authentication (empty for anonymous)
        password: Password for authentication (empty for no password)
        additional_options: Extra smbclient options
        timeout: Command timeout in seconds
        max_output_bytes: Maximum output size in bytes
        list_shares: If True, list shares (-L option)
        
    Returns:
        CompletedProcessLike with smbclient results
        
    Raises:
        ProcessExecutionError: Invalid parameters
        ProcessTimeoutError: Command timeout exceeded  
        ProcessOutputError: Output size exceeded
    """
    if not host or not isinstance(host, str):
        raise ProcessExecutionError("Host must be a non-empty string")
    
    # Build smbclient command with security hardening
    cmd = ["smbclient"]
    
    if list_shares:
        cmd.extend(["-L", f"//{host}"])
    elif share:
        cmd.extend([f"//{host}/{share}"])
    else:
        raise ProcessExecutionError("Must specify either list_shares=True or share name")
    
    # Authentication
    if not username:
        cmd.append("-N")  # No password prompt for anonymous
    else:
        cmd.extend(["-U", f"{username}%{password}"])
    
    # Security hardening - default to SMB2/3 with signing
    default_options = [
        "--option=client min protocol=SMB2",
        "--option=client max protocol=SMB3", 
        "--option=client signing=required"
    ]
    
    cmd.extend(default_options)
    
    # Add any additional options (for SMB1 mode override)
    if additional_options:
        cmd.extend(additional_options)
    
    # Add standard options for automation
    cmd.extend([
        "-g",  # Grepable output
        "-t", str(min(timeout, 30))  # Connection timeout
    ])
    
    return run_safe(
        argv=cmd,
        timeout=timeout,
        max_stdout_bytes=max_output_bytes,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}
    )


def test_command_availability(command: str, timeout: int = 5) -> bool:
    """
    Test if a command is available on the system.
    
    Args:
        command: Command name to test
        timeout: Test timeout in seconds
        
    Returns:
        True if command is available and responds to --help
    """
    try:
        result = run_safe(
            argv=[command, "--help"],
            timeout=timeout,
            max_stdout_bytes=1000
        )
        return result.returncode == 0
    except (ProcessExecutionError, ProcessTimeoutError, FileNotFoundError):
        return False