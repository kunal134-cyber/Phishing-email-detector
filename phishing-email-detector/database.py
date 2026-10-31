"""
Database Persistence Module for Scan History & Audit Logs.
Supports:
1. PostgreSQL (Neon, Supabase) via DATABASE_URL environment variable (recommended for Vercel)
2. SQLite (local development and fallback with read-only filesystem protection)
"""

import os
import sqlite3
import tempfile
from datetime import datetime

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

# Check for PostgreSQL configuration
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()


def is_postgres() -> bool:
    """Returns True if a PostgreSQL connection URL is configured and psycopg2 is installed."""
    return bool(DATABASE_URL and PSYCOPG2_AVAILABLE)


def get_sqlite_path() -> str:
    """
    Determines safe SQLite file path.
    On Vercel/serverless environments where the root is read-only, routes to /tmp.
    """
    if os.getenv("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return os.path.join(tempfile.gettempdir(), "scan_history.db")
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_history.db")


def get_db_connection():
    """
    Creates and returns a database connection (PostgreSQL or SQLite).
    Normalizes postgres:// to postgresql:// for compatibility.
    """
    global DATABASE_URL
    if is_postgres():
        conn_url = DATABASE_URL
        if conn_url.startswith("postgres://"):
            conn_url = conn_url.replace("postgres://", "postgresql://", 1)
        # Ensure sslmode=require for Neon / Supabase unless specified
        if "sslmode=" not in conn_url and "?" not in conn_url:
            conn_url += "?sslmode=require"
        return psycopg2.connect(conn_url)
    else:
        conn = sqlite3.connect(get_sqlite_path())
        conn.row_factory = sqlite3.Row
        return conn


def init_db():
    """
    Initializes database tables.
    Gracefully catches read-only filesystem errors so serverless cold starts never crash.
    """
    try:
        if is_postgres():
            conn = get_db_connection()
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS scan_logs (
                            id SERIAL PRIMARY KEY,
                            timestamp VARCHAR(64) NOT NULL,
                            sender VARCHAR(255),
                            subject VARCHAR(255),
                            classification VARCHAR(64) NOT NULL,
                            risk_level VARCHAR(64) NOT NULL,
                            overall_score DOUBLE PRECISION NOT NULL,
                            ml_probability DOUBLE PRECISION NOT NULL,
                            url_count INTEGER DEFAULT 0,
                            suspicious_url_count INTEGER DEFAULT 0,
                            header_issues_count INTEGER DEFAULT 0,
                            summary TEXT
                        );
                    """)
            conn.close()
            print("[+] PostgreSQL database initialized successfully.")
        else:
            db_path = get_sqlite_path()
            conn = sqlite3.connect(db_path)
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
                    );
                """)
            conn.close()
            print(f"[+] SQLite database initialized successfully at: {db_path}")
    except Exception as e:
        print(f"[!] Warning: Database initialization skipped or read-only ({e}). "
              "App will function normally with in-memory threat analysis.")


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
) -> int | None:
    """
    Inserts a new scan result into PostgreSQL or SQLite.
    Returns generated record ID on success, or None if the database write is not supported.
    NEVER raises unhandled exceptions that could crash the scan response.
    """
    timestamp_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sanitized_sender = (sender[:150] if sender else "None specified")
    sanitized_subject = (subject[:200] if subject else "No Subject")
    sanitized_summary = (summary[:500] if summary else "")

    try:
        if is_postgres():
            conn = get_db_connection()
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO scan_logs (
                            timestamp, sender, subject, classification, risk_level,
                            overall_score, ml_probability, url_count, suspicious_url_count,
                            header_issues_count, summary
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (
                            timestamp_str,
                            sanitized_sender,
                            sanitized_subject,
                            classification,
                            risk_level,
                            round(overall_score, 1),
                            round(ml_probability, 3),
                            url_count,
                            suspicious_url_count,
                            header_issues_count,
                            sanitized_summary
                        )
                    )
                    record_id = cur.fetchone()[0]
            conn.close()
            return record_id
        else:
            db_path = get_sqlite_path()
            conn = sqlite3.connect(db_path)
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
                        sanitized_sender,
                        sanitized_subject,
                        classification,
                        risk_level,
                        round(overall_score, 1),
                        round(ml_probability, 3),
                        url_count,
                        suspicious_url_count,
                        header_issues_count,
                        sanitized_summary
                    )
                )
                record_id = cursor.lastrowid
            conn.close()
            return record_id
    except sqlite3.OperationalError as oe:
        # Handles 'attempt to write a readonly database' safely
        print(f"[!] Warning: SQLite write prevented by filesystem ({oe}). Scan was analyzed but not stored.")
        return None
    except Exception as ex:
        print(f"[!] Warning: Database write failed ({ex}). Scan was analyzed but not stored.")
        return None


def get_recent_scans(limit: int = 25) -> list[dict]:
    """
    Retrieves the most recent scan records from PostgreSQL or SQLite.
    Returns empty list cleanly if database cannot be queried.
    """
    try:
        if is_postgres():
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, timestamp, sender, subject, classification, risk_level,
                           overall_score, ml_probability, url_count, suspicious_url_count,
                           header_issues_count, summary
                    FROM scan_logs
                    ORDER BY id DESC
                    LIMIT %s;
                    """,
                    (limit,)
                )
                rows = [dict(row) for row in cur.fetchall()]
            conn.close()
            return rows
        else:
            db_path = get_sqlite_path()
            if not os.path.exists(db_path):
                return []
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
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
    except Exception as e:
        print(f"[!] Notice: Could not read scan history ({e}). Returning empty list.")
        return []


def clear_history() -> bool:
    """
    Clears all records from scan history.
    Returns True on success, False if operation failed.
    """
    try:
        if is_postgres():
            conn = get_db_connection()
            with conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM scan_logs;")
            conn.close()
            return True
        else:
            db_path = get_sqlite_path()
            if not os.path.exists(db_path):
                return True
            conn = sqlite3.connect(db_path)
            with conn:
                conn.execute("DELETE FROM scan_logs;")
            conn.close()
            return True
    except Exception as e:
        print(f"[!] Notice: Could not clear scan history ({e}).")
        return False
