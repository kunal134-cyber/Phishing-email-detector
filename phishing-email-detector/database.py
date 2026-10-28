"""
SQLite Database Module for Scan History & Audit Logs.
Stores past email analysis results securely in a local database.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "scan_history.db")


def get_db_connection():
    """Create and return a database connection with dict-like row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables for scan history."""
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                classification TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                overall_score REAL NOT NULL,
                ml_probability REAL NOT NULL,
                url_count INTEGER DEFAULT 0,
                suspicious_url_count INTEGER DEFAULT 0,
                header_issues_count INTEGER DEFAULT 0,
                summary TEXT
            )
        """)
    conn.close()


def save_scan_result(
    sender: str,
    subject: str,
    classification: str,
    risk_level: str,
    overall_score: float,
    ml_probability: float,
    url_count: int,
    suspicious_url_count: int,
    header_issues_count: int,
    summary: str
) -> int:
    """Inserts a new scan result into the database and returns the generated ID."""
    conn = get_db_connection()
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_logs (
                timestamp, sender, subject, classification, risk_level,
                overall_score, ml_probability, url_count, suspicious_url_count,
                header_issues_count, summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp_str,
                (sender[:150] if sender else "None specified"),
                (subject[:200] if subject else "No Subject"),
                classification,
                risk_level,
                round(overall_score, 1),
                round(ml_probability, 3),
                url_count,
                suspicious_url_count,
                header_issues_count,
                summary[:500] if summary else ""
            )
        )
        record_id = cursor.lastrowid
    conn.close()
    return record_id


def get_recent_scans(limit: int = 25) -> list[dict]:
    """Retrieve the most recent scan records."""
    conn = get_db_connection()
    cursor = conn.execute(
        """
        SELECT id, timestamp, sender, subject, classification, risk_level,
               overall_score, ml_probability, url_count, suspicious_url_count,
               header_issues_count, summary
        FROM scan_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def clear_history() -> bool:
    """Clear all records from scan history."""
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM scan_logs")
    conn.close()
    return True
