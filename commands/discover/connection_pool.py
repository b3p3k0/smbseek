import threading
import time


class SMBConnectionPool:
    """
    Connection pool for SMB connections to improve performance.

    Caches successful connections per host to avoid repeated handshakes
    when testing multiple authentication methods.
    """

    def __init__(self, max_connections_per_host: int = 1, idle_timeout: int = 30):
        """
        Initialize connection pool.

        Args:
            max_connections_per_host: Maximum connections to cache per host
            idle_timeout: Seconds before closing idle connections
        """
        self._pools = {}  # ip -> list of connection info
        self._locks = {}  # ip -> threading.Lock
        self._last_used = {}  # ip -> timestamp
        self.max_connections_per_host = max_connections_per_host
        self.idle_timeout = idle_timeout
        self._global_lock = threading.Lock()

    def get_connection(self, ip: str, cautious_mode: bool = False):
        """
        Get cached connection or create new one.

        Args:
            ip: IP address
            cautious_mode: Security hardening flag

        Returns:
            Connection object or None if not available
        """
        # For now, return None to force new connections each time
        # Connection pooling with smbprotocol requires careful session management
        # This is a placeholder for future enhancement
        return None

    def return_connection(self, ip: str, connection, session=None):
        """
        Return connection to pool or clean up.

        Args:
            ip: IP address
            connection: Connection object
            session: Session object (optional)
        """
        # Clean up connections immediately for safety
        try:
            if session:
                session.disconnect()
            if connection:
                connection.disconnect()
        except:
            pass  # Ignore cleanup errors

    def cleanup_idle_connections(self):
        """Clean up idle connections that have exceeded timeout."""
        current_time = time.time()
        with self._global_lock:
            for ip in list(self._pools.keys()):
                last_used = self._last_used.get(ip, 0)
                if current_time - last_used > self.idle_timeout:
                    # Clean up idle connections for this host
                    connections = self._pools.pop(ip, [])
                    self._last_used.pop(ip, None)
                    if ip in self._locks:
                        del self._locks[ip]

                    # Clean up the actual connections
                    for conn_info in connections:
                        try:
                            if 'session' in conn_info and conn_info['session']:
                                conn_info['session'].disconnect()
                            if 'connection' in conn_info and conn_info['connection']:
                                conn_info['connection'].disconnect()
                        except:
                            pass  # Ignore cleanup errors
