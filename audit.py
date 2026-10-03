"""Tamper-evident audit log.

Every security-relevant action (sign-ins, approvals, unblocks, settings and
data changes) is appended to a separate SQLite database (default audit.db).
Each entry stores a SHA-256 hash of its contents plus the previous entry's
hash, so editing or deleting a past entry breaks the chain and verify()
reports where.

The log is kept apart from the threat database so clearing threat data
never clears the audit trail.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

AUDIT_DB_ENV = "AUTODEFENDER_AUDIT_DB"
DEFAULT_AUDIT_DB = "audit.db"
GENESIS_HASH = "0" * 64

_lock = threading.Lock()


def audit_db_path() -> str:
    return os.getenv(AUDIT_DB_ENV, DEFAULT_AUDIT_DB)


def _connect() -> sqlite3.Connection:
    path = audit_db_path()
    is_new = not os.path.exists(path)
    conn = sqlite3.connect(path, timeout=10)
    if is_new and os.name == "posix":
        os.chmod(path, 0o600)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL
        )
    """)
    return conn


def _entry_hash(timestamp: str, username: str, action: str, details: str, prev_hash: str) -> str:
    payload = json.dumps([timestamp, username, action, details, prev_hash], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def record(username: str, action: str, details: Optional[dict] = None) -> None:
    """Append an entry to the audit log. Never raises; failures are logged."""
    try:
        details_text = json.dumps(details or {}, sort_keys=True, default=str)[:4000]
        timestamp = datetime.now(timezone.utc).isoformat()
        with _lock:
            conn = _connect()
            try:
                row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
                prev_hash = row[0] if row else GENESIS_HASH
                entry_hash = _entry_hash(timestamp, username, action, details_text, prev_hash)
                conn.execute(
                    "INSERT INTO audit_log (timestamp, username, action, details, prev_hash, hash) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (timestamp, username, action, details_text, prev_hash, entry_hash),
                )
                conn.commit()
            finally:
                conn.close()
    except Exception as e:
        logger.error(f"Could not write audit log entry for {action}: {e}")


def entries(limit: int = 500) -> List[dict]:
    """Return the most recent audit entries, newest first."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, timestamp, username, action, details FROM audit_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        finally:
            conn.close()
    return [
        {"id": r[0], "timestamp": r[1], "username": r[2], "action": r[3], "details": r[4]}
        for r in rows
    ]


def verify() -> Tuple[bool, Optional[int]]:
    """Check the hash chain. Returns (True, None) or (False, id of the first bad entry)."""
    with _lock:
        conn = _connect()
        try:
            rows = conn.execute(
                "SELECT id, timestamp, username, action, details, prev_hash, hash FROM audit_log ORDER BY id"
            ).fetchall()
        finally:
            conn.close()
    prev_hash = GENESIS_HASH
    for row_id, timestamp, username, action, details, stored_prev, stored_hash in rows:
        if stored_prev != prev_hash or _entry_hash(timestamp, username, action, details, prev_hash) != stored_hash:
            return False, row_id
        prev_hash = stored_hash
    return True, None
