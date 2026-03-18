import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "proxy.db"


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS proxy_history (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp        TEXT    NOT NULL,
            method           TEXT    NOT NULL,
            scheme           TEXT    NOT NULL,
            host             TEXT    NOT NULL,
            path             TEXT    NOT NULL,
            query            TEXT    NOT NULL DEFAULT '',
            request_headers  TEXT    NOT NULL DEFAULT '{}',
            request_body     TEXT    NOT NULL DEFAULT '',
            status_code      INTEGER,
            response_headers TEXT             DEFAULT '{}',
            response_body    TEXT             DEFAULT '',
            content_type     TEXT             DEFAULT '',
            flagged          INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()
    return conn
