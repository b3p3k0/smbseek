"""
Lightweight, idempotent database migrations for SMBSeek.

Currently installs:
- share_credentials: stores per-share credentials discovered via Pry (or future sources).
"""

import sqlite3
from pathlib import Path
from typing import Optional


def run_migrations(db_path: str) -> None:
    """
    Run required migrations against the SQLite database.

    Args:
        db_path: Path to the SQLite database file.
    """
    if not db_path:
        return

    path_obj = Path(db_path)
    # Ensure parent directory exists to avoid sqlite 'unable to open database file'
    path_obj.parent.mkdir(parents=True, exist_ok=True)

    conn: Optional[sqlite3.Connection] = None
    try:
        conn = sqlite3.connect(str(path_obj))
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS share_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id INTEGER NOT NULL,
                share_name TEXT NOT NULL,
                username TEXT,
                password TEXT,
                source TEXT DEFAULT 'pry',
                session_id INTEGER,
                last_verified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES smb_servers(id) ON DELETE CASCADE,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE SET NULL
            )
            """
        )

        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_share_credentials_server_share_source
            ON share_credentials (server_id, share_name, source)
            """
        )

        conn.commit()
    finally:
        if conn:
            conn.close()


__all__ = ["run_migrations"]
