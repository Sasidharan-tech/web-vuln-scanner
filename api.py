#!/usr/bin/env python3
"""
Unified FastAPI Backend for Web Vulnerability Scanner
Exposes two scanner modes:
  * Native Scanner  - Python-native modules (SQL, XSS, Cmd, LFI, ...) via SSE
  * GitHub Scanner  - Static code analysis of GitHub repositories via SSE
"""

import asyncio
import json
import queue
import re
import hashlib
import hmac
import os
import secrets
import sqlite3
import subprocess
import sys
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Native scanner imports
# ---------------------------------------------------------------------------
from crawler.spider import WebCrawler
from scanner.sql_injection import SQLInjectionScanner
from scanner.xss import XSSScanner
from scanner.command_injection import CommandInjectionScanner
from scanner.file_inclusion import FileInclusionScanner
from scanner.open_redirect import OpenRedirectScanner
from scanner.headers import HeadersScanner
from scanner.cookies import CookieScanner
from database.session import ScanSession

# ---------------------------------------------------------------------------
# GitHub scanner import
# ---------------------------------------------------------------------------
from scanner.github_scanner import GitHubScanner, parse_github_url

# ---------------------------------------------------------------------------
# Proxy DB import
# ---------------------------------------------------------------------------
from proxy.proxy_db import get_conn as proxy_get_conn

# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------
native_scan_state: Dict = {
    "running": False,
    "stop_requested": False,
    "thread": None,
}

github_scan_state: Dict = {
    "running": False,
    "stop_requested": False,
    "thread": None,
}

_proxy_proc: Optional[subprocess.Popen] = None
_proxy_state: Dict = {"running": False, "pid": None, "port": 8080}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ProxyReplayRequest(BaseModel):
    method: str
    url: str
    headers: Dict[str, str] = {}
    body: str = ""

    @field_validator("url")
    @classmethod
    def url_safe(cls, v: str) -> str:
        v = v.strip()
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must start with http:// or https://")
        if not parsed.netloc:
            raise ValueError("URL must have a valid hostname")
        return v


class GitHubScanRequest(BaseModel):
    repo_url: str
    token: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_valid(cls, v: str) -> str:
        v = v.strip()
        if len(v) < 3 or len(v) > 32:
            raise ValueError("Username must be 3–32 characters")
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError("Username may only contain letters, numbers, _ and -")
        return v

    @field_validator("password")
    @classmethod
    def password_valid(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password too long")
        return v


class LoginRequest(BaseModel):
    username: str
    password: str


# ---------------------------------------------------------------------------
# Auth DB helpers
# ---------------------------------------------------------------------------

_AUTH_DB_PATH = Path("database/users.db")


def _get_auth_conn() -> sqlite3.Connection:
    """Return a SQLite connection to the users database, creating tables if needed."""
    _AUTH_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_AUTH_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            email    TEXT,
            salt     TEXT    NOT NULL,
            pw_hash  TEXT    NOT NULL,
            created_at TEXT  NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token      TEXT PRIMARY KEY,
            username   TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def _hash_password(password: str, salt: bytes) -> str:
    """PBKDF2-HMAC-SHA256 password hash — returns hex string."""
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return dk.hex()


def _verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    candidate = _hash_password(password, salt)
    return hmac.compare_digest(candidate, stored_hash)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("Starting Unified Web Vulnerability Scanner API...")
    yield
    print("Shutting down...")


app = FastAPI(
    title="Web Vulnerability Scanner API",
    description=(
        "Unified API combining a Python-native black-box scanner "
        "and OSTE Meta-Scan (Wapiti, ZAP, Nuclei, Nikto, Skipfish)"
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
# NATIVE SCANNER - SSE streaming
# ===========================================================================

class ScanEventQueue:
    """Thread-safe queue for scan events."""

    def __init__(self):
        self._q: queue.Queue = queue.Queue()
        self.closed = False

    def put(self, event):
        if not self.closed:
            self._q.put(event)

    def get(self, timeout=1):
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def close(self):
        self.closed = True

    def empty(self):
        return self._q.empty()


def _run_native_scan(target_url, modules, depth, max_urls, timeout, delay, event_queue):
    """Run the native vulnerability scan in a background thread."""
    global native_scan_state

    try:
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "http://" + target_url
            parsed = urlparse(target_url)

        safe_name = re.sub(r"[^\w\-.]", "_", parsed.netloc)
        session_name = f"{safe_name}_{hashlib.md5(target_url.encode()).hexdigest()[:8]}"

        session = ScanSession(session_name)

        event_queue.put({
            "status": "crawling",
            "phase": "Phase 1: Crawling",
            "progress": 5,
            "log": f"[INFO] Starting scan on: {target_url}",
        })

        event_queue.put({"log": f"[INFO] Starting crawl from: {target_url}"})

        crawler = WebCrawler(
            target_url,
            max_depth=depth,
            max_urls=max_urls,
            timeout=timeout,
            delay=delay,
        )
        crawl_result = crawler.crawl()
        urls = crawl_result.get("urls", [])
        forms = crawl_result.get("forms", [])

        if native_scan_state["stop_requested"]:
            event_queue.put({"status": "idle", "log": "[INFO] Scan stopped by user"})
            return

        session.save_crawl_progress(urls, forms)

        event_queue.put({
            "status": "scanning",
            "phase": "Phase 2: Vulnerability Scanning",
            "progress": 20,
            "urls_found": len(urls),
            "forms_found": len(forms),
            "log": f"[INFO] Crawl complete. Found {len(urls)} URLs, {len(forms)} forms",
        })

        module_list = (
            modules.split(",") if modules
            else ["sql", "xss", "cmd", "lfi", "redirect", "headers", "cookies"]
        )

        scanner_classes = {
            "sql":      (SQLInjectionScanner, "SQL Injection"),
            "xss":      (XSSScanner, "Cross-Site Scripting"),
            "cmd":      (CommandInjectionScanner, "Command Injection"),
            "lfi":      (FileInclusionScanner, "File Inclusion"),
            "redirect": (OpenRedirectScanner, "Open Redirect"),
            "headers":  (HeadersScanner, "Security Headers"),
            "cookies":  (CookieScanner, "Cookie Security"),
        }

        all_vulnerabilities = []
        total_scanners = len([m for m in module_list if m in scanner_classes])
        completed_scanners = 0

        for module in module_list:
            if native_scan_state["stop_requested"]:
                break
            if module not in scanner_classes:
                continue

            scanner_class, scanner_name = scanner_classes[module]
            event_queue.put({"log": f"[INFO] Running {scanner_name} scanner..."})

            try:
                sc = scanner_class(timeout=timeout, delay=delay)
                vulns = sc.scan(urls, forms)

                for vuln in vulns:
                    vuln_data = {
                        "type": vuln.get("type", scanner_name),
                        "severity": vuln.get("severity", "medium"),
                        "url": vuln.get("url", ""),
                        "parameter": vuln.get("parameter", ""),
                        "payload": vuln.get("payload", ""),
                        "description": vuln.get(
                            "description", f"{scanner_name} vulnerability detected"
                        ),
                    }
                    all_vulnerabilities.append(vuln_data)
                    event_queue.put({
                        "vulnerability": vuln_data,
                        "log": (
                            f"[WARNING] [!] {vuln_data['type']} - "
                            f"{vuln_data['url']} (param: {vuln_data['parameter']})"
                        ),
                    })
            except Exception as exc:
                event_queue.put({"log": f"[ERROR] {scanner_name} scanner error: {exc}"})

            completed_scanners += 1
            progress = 20 + int((completed_scanners / total_scanners) * 75)
            event_queue.put({"progress": progress})

        session.save_vulnerabilities(all_vulnerabilities)

        event_queue.put({
            "status": "completed",
            "phase": "Scan Complete",
            "progress": 100,
            "log": f"[INFO] Scan completed. Found {len(all_vulnerabilities)} vulnerabilities.",
        })

    except Exception as exc:
        event_queue.put({"status": "error", "log": f"[ERROR] Scan failed: {exc}"})
    finally:
        native_scan_state["running"] = False
        native_scan_state["stop_requested"] = False


@app.get("/api/scan")
async def start_native_scan(
    url: str,
    modules: str = "sql,xss,cmd,lfi,redirect,headers,cookies",
    depth: int = 2,
    max_urls: int = 100,
    timeout: int = 10,
    delay: float = 0.5,
):
    """Start a native vulnerability scan and stream events via Server-Sent Events."""
    global native_scan_state

    if native_scan_state["running"]:
        raise HTTPException(status_code=400, detail="A scan is already in progress")

    event_queue = ScanEventQueue()
    native_scan_state["running"] = True
    native_scan_state["stop_requested"] = False

    scan_thread = threading.Thread(
        target=_run_native_scan,
        args=(url, modules, depth, max_urls, timeout, delay, event_queue),
        daemon=True,
    )
    scan_thread.start()
    native_scan_state["thread"] = scan_thread

    async def generate():
        try:
            while native_scan_state["running"] or not event_queue.empty():
                event = await asyncio.get_event_loop().run_in_executor(
                    None, event_queue.get, 1
                )
                if event:
                    yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            native_scan_state["stop_requested"] = True
        finally:
            event_queue.close()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.post("/api/scan/stop")
async def stop_native_scan():
    """Stop the running native scan."""
    global native_scan_state
    if native_scan_state["running"]:
        native_scan_state["stop_requested"] = True
        return {"message": "Stop requested"}
    return {"message": "No scan running"}


# ===========================================================================
# PROXY INTERCEPTOR – mitmproxy-based HTTP/HTTPS traffic capture
# ===========================================================================

_MITMDUMP = Path(sys.executable).parent / ("mitmdump.exe" if sys.platform == "win32" else "mitmdump")
_ADDON_PATH = Path(__file__).parent / "proxy" / "interceptor.py"


@app.post("/api/proxy/start")
async def start_proxy(port: int = 8080):
    """Start the mitmproxy intercept proxy on the given port."""
    global _proxy_proc, _proxy_state
    if _proxy_state["running"] and _proxy_proc and _proxy_proc.poll() is None:
        return {"status": "already_running", "port": _proxy_state["port"]}
    if not _MITMDUMP.exists():
        raise HTTPException(
            status_code=503,
            detail=f"mitmdump not found at {_MITMDUMP}. Run: pip install mitmproxy",
        )
    try:
        _proxy_proc = subprocess.Popen(
            [
                str(_MITMDUMP),
                "--listen-host", "127.0.0.1",
                "--listen-port", str(port),
                "-s", str(_ADDON_PATH),
                "--set", "block_global=false",
                "--quiet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        await asyncio.sleep(1.5)
        if _proxy_proc.poll() is not None:
            err = _proxy_proc.stderr.read().decode(errors="replace")
            raise HTTPException(status_code=500, detail=f"Proxy failed to start: {err}")
        _proxy_state = {"running": True, "pid": _proxy_proc.pid, "port": port}
        return {"status": "started", "port": port, "pid": _proxy_proc.pid}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/proxy/stop")
async def stop_proxy():
    """Stop the running intercept proxy."""
    global _proxy_proc, _proxy_state
    if not _proxy_state["running"] or _proxy_proc is None:
        return {"status": "not_running"}
    try:
        if _proxy_proc.poll() is None:
            _proxy_proc.terminate()
            try:
                _proxy_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _proxy_proc.kill()
        _proxy_state = {"running": False, "pid": None, "port": 8080}
        return {"status": "stopped"}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/api/proxy/status")
async def get_proxy_status():
    """Return proxy running state."""
    global _proxy_proc, _proxy_state
    if _proxy_proc and _proxy_proc.poll() is not None:
        _proxy_state = {"running": False, "pid": None, "port": 8080}
    return _proxy_state


@app.get("/api/proxy/history")
async def get_proxy_history(
    limit: int = 100,
    after_id: int = 0,
    host: str = "",
):
    """Return captured requests. Pass after_id for incremental polling."""
    with proxy_get_conn() as conn:
        if host:
            rows = conn.execute(
                "SELECT id,timestamp,method,scheme,host,path,query,status_code,content_type,flagged "
                "FROM proxy_history WHERE id > ? AND host LIKE ? ORDER BY id DESC LIMIT ?",
                (after_id, f"%{host}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id,timestamp,method,scheme,host,path,query,status_code,content_type,flagged "
                "FROM proxy_history WHERE id > ? ORDER BY id DESC LIMIT ?",
                (after_id, limit),
            ).fetchall()
    return {"requests": [dict(r) for r in rows]}


@app.get("/api/proxy/request/{req_id}")
async def get_proxy_request_detail(req_id: int):
    """Return full request + response detail for a captured request."""
    with proxy_get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM proxy_history WHERE id = ?", (req_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    d = dict(row)
    try:
        d["request_headers"] = json.loads(d["request_headers"] or "{}")
    except Exception:
        d["request_headers"] = {}
    try:
        d["response_headers"] = json.loads(d["response_headers"] or "{}")
    except Exception:
        d["response_headers"] = {}
    return d


@app.delete("/api/proxy/history")
async def clear_proxy_history():
    """Delete all captured request history."""
    with proxy_get_conn() as conn:
        conn.execute("DELETE FROM proxy_history")
    return {"status": "cleared"}


@app.post("/api/proxy/replay")
async def replay_proxy_request(req: ProxyReplayRequest):
    """Resend a (possibly modified) request and return the response."""
    import requests as _req
    try:
        resp = _req.request(
            method=req.method,
            url=req.url,
            headers=req.headers,
            data=req.body.encode() if req.body else None,
            timeout=15,
            allow_redirects=False,
            verify=False,
        )
        return {
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:65536],
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/proxy/scan/{req_id}")
async def scan_proxy_request(req_id: int):
    """Run SQLi + XSS scanners against the URL of an intercepted request."""
    with proxy_get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM proxy_history WHERE id = ?", (req_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Request not found")
    d = dict(row)
    target_url = f"{d['scheme']}://{d['host']}{d['path']}"
    if d["query"]:
        target_url += "?" + d["query"]
    results = []
    for ScannerClass, name in [
        (SQLInjectionScanner, "SQL Injection"),
        (XSSScanner, "XSS"),
    ]:
        try:
            sc = ScannerClass(timeout=10, delay=0)
            for vuln in sc.scan([target_url], []):
                vuln["scanner"] = name
                results.append(vuln)
        except Exception as exc:
            results.append({"scanner": name, "error": str(exc)})
    return {"request_id": req_id, "url": target_url, "vulnerabilities": results}


@app.get("/api/proxy/cert")
async def download_proxy_cert():
    """Download the mitmproxy CA certificate (install in browser to intercept HTTPS)."""
    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if not cert_path.exists():
        raise HTTPException(
            status_code=404,
            detail="CA cert not found. Start the proxy first — mitmproxy generates it on first run.",
        )
    return FileResponse(
        str(cert_path),
        media_type="application/x-pem-file",
        filename="mitmproxy-ca-cert.pem",
    )


# ===========================================================================
# GITHUB SCANNER – static code analysis via SSE
# ===========================================================================


def _run_github_scan(repo_url: str, token: Optional[str], event_queue: "ScanEventQueue"):
    """Run the GitHub repository scan in a background thread."""
    global github_scan_state
    try:
        scanner = GitHubScanner(token=token)
        scanner.scan(
            repo_url=repo_url,
            token=token,
            progress_callback=lambda evt: event_queue.put(evt),
            stop_check=lambda: github_scan_state["stop_requested"],
        )
    except Exception as exc:
        event_queue.put({"status": "error", "log": f"[ERROR] GitHub scan failed: {exc}"})
    finally:
        github_scan_state["running"] = False
        github_scan_state["stop_requested"] = False


@app.post("/api/github/scan")
async def start_github_scan(request: GitHubScanRequest):
    """
    Start a GitHub repository code-security scan.
    Streams events via Server-Sent Events (SSE).

    Body:
        repo_url: GitHub repository URL (e.g. https://github.com/owner/repo)
        token:    Optional GitHub Personal Access Token for private repos /
                  higher API rate limits.
    """
    global github_scan_state

    if github_scan_state["running"]:
        raise HTTPException(status_code=400, detail="A GitHub scan is already in progress")

    # Validate URL before starting thread
    if not parse_github_url(request.repo_url):
        raise HTTPException(
            status_code=422,
            detail="Invalid GitHub repository URL. Expected: https://github.com/owner/repo",
        )

    event_queue = ScanEventQueue()
    github_scan_state["running"] = True
    github_scan_state["stop_requested"] = False

    scan_thread = threading.Thread(
        target=_run_github_scan,
        args=(request.repo_url, request.token, event_queue),
        daemon=True,
    )
    scan_thread.start()
    github_scan_state["thread"] = scan_thread

    async def generate():
        try:
            while github_scan_state["running"] or not event_queue.empty():
                event = await asyncio.get_event_loop().run_in_executor(
                    None, event_queue.get, 1
                )
                if event:
                    yield f"data: {json.dumps(event)}\n\n"
        except asyncio.CancelledError:
            github_scan_state["stop_requested"] = True
        finally:
            event_queue.close()

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@app.post("/api/github/scan/stop")
async def stop_github_scan():
    """Stop the running GitHub repository scan."""
    global github_scan_state
    if github_scan_state["running"]:
        github_scan_state["stop_requested"] = True
        return {"message": "Stop requested"}
    return {"message": "No GitHub scan running"}


@app.get("/api/github/report/{report_name}")
async def download_github_report(report_name: str):
    """Download a previously generated GitHub scan HTML report."""
    import re as _re
    from pathlib import Path
    # Sanitise: only allow safe filenames (alphanumeric, dash, underscore, dot)
    if not _re.match(r'^[\w\-.]+\.html$', report_name):
        raise HTTPException(status_code=400, detail="Invalid report name")
    report_path = Path("reports") / "github" / report_name
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(
        str(report_path),
        media_type="text/html",
        filename=report_name,
    )


# ===========================================================================
# AUTH ENDPOINTS
# ===========================================================================


@app.post("/auth/register", status_code=201)
async def auth_register(req: RegisterRequest):
    """Register a new user account."""
    salt = os.urandom(32)
    pw_hash = _hash_password(req.password, salt)
    try:
        with _get_auth_conn() as conn:
            conn.execute(
                "INSERT INTO users (username, email, salt, pw_hash, created_at) VALUES (?,?,?,?,?)",
                (req.username, req.email or "", salt.hex(), pw_hash, datetime.now().isoformat()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Username already taken")
    return {"message": "Account created successfully"}


@app.post("/auth/login")
async def auth_login(req: LoginRequest):
    """Login with username + password; returns a session token."""
    with _get_auth_conn() as conn:
        row = conn.execute(
            "SELECT username, salt, pw_hash FROM users WHERE username = ?",
            (req.username.strip(),),
        ).fetchone()

    if row is None or not _verify_password(req.password, row["salt"], row["pw_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    with _get_auth_conn() as conn:
        conn.execute(
            "INSERT INTO auth_tokens (token, username, created_at) VALUES (?,?,?)",
            (token, row["username"], datetime.now().isoformat()),
        )
    return {"token": token, "username": row["username"]}


@app.post("/auth/logout")
async def auth_logout(authorization: Optional[str] = Header(default=None)):
    """Invalidate the caller's session token."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        with _get_auth_conn() as conn:
            conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
    return {"message": "Logged out"}


@app.get("/auth/me")
async def auth_me(authorization: Optional[str] = Header(default=None)):
    """Return the username for the supplied token (used on page refresh)."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization[7:]
    with _get_auth_conn() as conn:
        row = conn.execute(
            "SELECT username FROM auth_tokens WHERE token = ?", (token,)
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    return {"username": row["username"]}


# ===========================================================================
# SHARED ENDPOINTS
# ===========================================================================


@app.get("/")
async def root():
    return {
        "message": "Web Vulnerability Scanner API",
        "version": "2.0.0",
        "modes": {
            "native": "Python-native black-box scanner (GET /api/scan via SSE)",
            "github": "GitHub repo static code analysis (POST /api/github/scan via SSE)",
        },
    }


@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
