"""
Lightweight regression guard for database bootstrap behavior.

Run with: python3 tools/db_bootstrap_smoketest.py
"""

import sqlite3
import tempfile
import os

from db_manager import DatabaseManager, REQUIRED_TABLES


def main():
    tmp = tempfile.NamedTemporaryFile(delete=False)
    db_path = tmp.name
    tmp.close()

    try:
        DatabaseManager(db_path)  # Should initialize schema even if file exists
        conn = sqlite3.connect(db_path)
        try:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
            }
        finally:
            conn.close()

        missing = REQUIRED_TABLES - tables
        if missing:
            raise SystemExit(f"Missing required tables after bootstrap: {missing}")

        print("✅ Bootstrap smoke test passed")
    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


if __name__ == "__main__":
    main()

