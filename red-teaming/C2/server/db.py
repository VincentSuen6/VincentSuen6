import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent / "c2.db"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS beacons (
                beacon_id  TEXT PRIMARY KEY,
                hostname   TEXT NOT NULL,
                username   TEXT NOT NULL,
                os         TEXT NOT NULL,
                pid        INTEGER NOT NULL,
                last_seen  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tasks (
                task_id    TEXT PRIMARY KEY,
                beacon_id  TEXT NOT NULL,
                type       TEXT NOT NULL,
                params     TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'pending'
            );

            CREATE TABLE IF NOT EXISTS results (
                result_id    TEXT PRIMARY KEY,
                task_id      TEXT NOT NULL,
                beacon_id    TEXT NOT NULL,
                status       TEXT NOT NULL,
                output       TEXT NOT NULL DEFAULT '',
                telemetry    TEXT NOT NULL DEFAULT '{}',
                completed_at TEXT NOT NULL
            );
        """)
