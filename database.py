"""SQLite persistence layer for user records.

Stores salt and hash as hex strings (TEXT) — same on-disk shape as the
old JSON version, just with SQL guarantees around uniqueness and atomicity.
"""

import sqlite3
from pathlib import Path

DB_FILE = Path(__file__).resolve().parent / "users.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE,
    salt        TEXT    NOT NULL,
    hash        TEXT    NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT username, salt, hash, created_at FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def create_user(username: str, salt_hex: str, hash_hex: str) -> bool:
    """Insert a new user. Returns False if the username is already taken."""
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO users (username, salt, hash) VALUES (?, ?, ?)",
                (username, salt_hex, hash_hex),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def user_count() -> int:
    with _connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
