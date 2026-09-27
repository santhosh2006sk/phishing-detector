"""
Persistent storage for scan history using SQLite.
Creates scans.db automatically on first run - no setup needed.
"""

import sqlite3
from datetime import datetime, timezone

DB_FILE = "scans.db"


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            hostname TEXT,
            ml_probability REAL,
            risk_score INTEGER,
            risk_level TEXT,
            reasons TEXT,
            scanned_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(result: dict):
    conn = sqlite3.connect(DB_FILE)
    conn.execute(
        """INSERT INTO scans (url, hostname, ml_probability, risk_score, risk_level, reasons, scanned_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            result["url"],
            result.get("hostname", ""),
            result["ml_probability"],
            result["risk_score"],
            result["risk_level"],
            " | ".join(result.get("reasons", [])),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 50):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]
