"""
mitmproxy addon — intercepts all HTTP/HTTPS traffic and stores it in SQLite.

Started automatically by the API via:
    mitmdump --listen-host 127.0.0.1 --listen-port 8080 \
             -s proxy/interceptor.py --set block_global=false --quiet
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "proxy.db"


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
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
    conn.close()


_init_db()


class InterceptorAddon:
    def __init__(self):
        self._pending: dict = {}

    def request(self, flow):  # noqa: F821 – mitmproxy injects flow type at runtime
        req = flow.request
        try:
            body = req.get_text(strict=False) or ""
        except Exception:
            body = "<binary>"
        self._pending[flow.id] = {
            "ts":      datetime.now(timezone.utc).isoformat(),
            "method":  req.method,
            "scheme":  req.scheme,
            "host":    req.pretty_host,
            "path":    req.path.split("?")[0],
            "query":   req.query_string.decode(errors="replace") if req.query_string else "",
            "headers": json.dumps(dict(req.headers)),
            "body":    body,
        }

    def response(self, flow):
        p = self._pending.pop(flow.id, None)
        if p is None:
            return
        resp = flow.response
        try:
            rbody = resp.get_text(strict=False) or ""
        except Exception:
            rbody = "<binary>"
        ctype = resp.headers.get("content-type", "")

        conn = sqlite3.connect(str(DB_PATH))
        try:
            conn.execute("""
                INSERT INTO proxy_history
                    (timestamp, method, scheme, host, path, query,
                     request_headers, request_body,
                     status_code, response_headers, response_body, content_type)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                p["ts"], p["method"], p["scheme"], p["host"],
                p["path"], p["query"], p["headers"], p["body"],
                resp.status_code,
                json.dumps(dict(resp.headers)),
                rbody[:65536],
                ctype,
            ))
            conn.commit()
        finally:
            conn.close()


addons = [InterceptorAddon()]
