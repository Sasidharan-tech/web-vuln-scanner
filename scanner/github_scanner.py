"""
GitHub Repository Code Scanner

Scans public (or private with a token) GitHub repositories for common
security issues and code errors:
  - Hardcoded credentials / secrets / API keys
  - Private keys and certificates committed to source
  - AWS credentials exposure
  - Dangerous function calls (eval, exec, os.system with shell=True)
  - SQL injection patterns (string concatenation in queries)
  - Potential XSS patterns (unsafe innerHTML / document.write)
  - Weak cryptographic hashing (MD5, SHA1 for passwords)
  - Debug mode left enabled
  - Sensitive data being logged
  - Hardcoded IP addresses
  - Insecure HTTP URLs
  - TODO / FIXME / HACK annotations
"""

import base64
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from reports.github_report import generate_github_html_report

GITHUB_API_BASE = "https://api.github.com"

# File extensions that will be fetched and analysed
CODE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".java",
    ".go", ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".ps1",
    ".html", ".htm", ".xml", ".yaml", ".yml", ".json", ".env",
    ".config", ".conf", ".ini", ".toml", ".tf",
}

# Skip files that are almost certainly not worth analysing
SKIP_PATH_FRAGMENTS = {
    "node_modules/", "vendor/", ".git/", "dist/", "build/",
    "__pycache__/", ".venv/", "venv/", "site-packages/",
    "test/", "tests/", "__tests__/", "spec/",
}

# Maximum raw file size to analyse (100 KB) – avoids fetching giant auto-generated files
MAX_FILE_SIZE = 100 * 1024

# ---------------------------------------------------------------------------
# Security / code-quality patterns
# ---------------------------------------------------------------------------
SECURITY_PATTERNS: List[Dict[str, Any]] = [
    {
        "id": "hardcoded_password",
        "name": "Hardcoded Password",
        "severity": "critical",
        "patterns": [
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
        ],
        "description": (
            "A hardcoded password was found in source code. "
            "Credentials must be stored in environment variables or a secrets manager — "
            "never committed to version control."
        ),
    },
    {
        "id": "hardcoded_secret",
        "name": "Hardcoded Secret / API Key",
        "severity": "critical",
        "patterns": [
            r'(?i)(secret[_\-]?key|api[_\-]?key|api[_\-]?secret|auth[_\-]?token)\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'(?i)(access[_\-]?key|private[_\-]?key|client[_\-]?secret)\s*[=:]\s*["\'][^"\']{8,}["\']',
        ],
        "description": (
            "A hardcoded API key or secret was found. "
            "Secrets must never be committed to source control. "
            "Use environment variables, a vault, or CI/CD secret injection."
        ),
    },
    {
        "id": "aws_credentials",
        "name": "AWS Credentials Exposed",
        "severity": "critical",
        "patterns": [
            r'AKIA[0-9A-Z]{16}',
            r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\'][^"\']+["\']',
        ],
        "description": (
            "An AWS access key ID or secret access key was found in code. "
            "This could allow an attacker full access to AWS resources. "
            "Rotate the key immediately and remove it from the repository."
        ),
    },
    {
        "id": "private_key",
        "name": "Private Key / Certificate in Code",
        "severity": "critical",
        "patterns": [
            r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            r"-----BEGIN CERTIFICATE-----",
        ],
        "description": (
            "A private key or certificate was found in source code. "
            "This is a critical security risk — revoke and regenerate the key immediately."
        ),
    },
    {
        "id": "eval_usage",
        "name": "Dangerous eval() Call",
        "severity": "high",
        "patterns": [
            r'\beval\s*\(',
        ],
        "description": (
            "eval() executes arbitrary code. "
            "If the argument is derived from user input this is a critical code-injection risk."
        ),
    },
    {
        "id": "exec_shell",
        "name": "Shell Command Execution",
        "severity": "high",
        "patterns": [
            r'\bos\.system\s*\(',
            r'\bsubprocess\.call\s*\(.*shell\s*=\s*True',
            r'\bsubprocess\.Popen\s*\(.*shell\s*=\s*True',
            r'\bsubprocess\.run\s*\(.*shell\s*=\s*True',
            r'\bshell_exec\s*\(',
            r'\bpassthru\s*\(',
            r'\bpopen\s*\(',
        ],
        "description": (
            "A shell command is executed directly or with shell=True. "
            "If any argument originates from user input this enables OS command injection. "
            "Use parameterised subprocess calls (list form) and never pass shell=True with user data."
        ),
    },
    {
        "id": "sql_injection_pattern",
        "name": "Potential SQL Injection",
        "severity": "critical",
        "patterns": [
            r'(?i)(execute|cursor\.execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE).*%[s]',
            r'(?i)(execute|cursor\.execute)\s*\(\s*f["\']',
            r'(?i)query\s*=\s*["\'].*SELECT.*["\'\s]*\+',
            r'(?i)query\s*=\s*f["\'].*SELECT',
            r'(?i)\$_(GET|POST|REQUEST)\[.*\].*mysql_query',
            r'(?i)\.format\s*\(.*\)\s*#.*sql',
        ],
        "description": (
            "User-controlled input appears to be concatenated directly into a SQL query. "
            "Always use parameterised queries or prepared statements."
        ),
    },
    {
        "id": "xss_pattern",
        "name": "Potential XSS",
        "severity": "high",
        "patterns": [
            r'innerHTML\s*[+]?=\s*(?!["\']<)',
            r'document\.write\s*\(',
            r'\.html\s*\(\s*(?![\"\'])',
        ],
        "description": (
            "User-controlled data may be inserted into the DOM unsanitised. "
            "Use textContent instead of innerHTML, or sanitise with DOMPurify."
        ),
    },
    {
        "id": "weak_hash",
        "name": "Weak Cryptographic Hash (MD5 / SHA-1)",
        "severity": "medium",
        "patterns": [
            r'\bhashlib\.md5\s*\(',
            r'\bhashlib\.sha1\s*\(',
            r'\bMD5\s*\(',
            r'\bSHA1\s*\(',
        ],
        "description": (
            "MD5 and SHA-1 are cryptographically broken. "
            "Do not use them for passwords (use bcrypt/argon2) or integrity checks (use SHA-256+)."
        ),
    },
    {
        "id": "debug_enabled",
        "name": "Debug Mode Enabled",
        "severity": "medium",
        "patterns": [
            r'(?i)\bDEBUG\s*=\s*True\b',
            r'(?i)app\.debug\s*=\s*True',
            r'(?i)FLASK_ENV\s*=\s*["\']development["\']',
        ],
        "description": (
            "Debug mode is enabled. In production this can expose stack traces, "
            "environment variables, and internal configuration to attackers."
        ),
    },
    {
        "id": "sensitive_logging",
        "name": "Sensitive Data in Logs",
        "severity": "medium",
        "patterns": [
            r'(?i)print\s*\(.*(?:password|secret|token|api.?key|credential)',
            r'(?i)console\.log\s*\(.*(?:password|secret|token|api.?key|credential)',
            r'(?i)logger\.(debug|info|warn)\s*\(.*(?:password|secret|token|api.?key)',
        ],
        "description": (
            "A password, secret, or token appears to be written to a log. "
            "Sensitive data in logs can be exfiltrated through log-aggregation pipelines."
        ),
    },
    {
        "id": "hardcoded_ip",
        "name": "Hardcoded IP Address",
        "severity": "low",
        "patterns": [
            r'\b(?!127\.0\.0\.1|0\.0\.0\.0)(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
            r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
            r'\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        ],
        "description": (
            "A hardcoded IP address was found. "
            "Server addresses should be configurable via environment variables or configuration files."
        ),
    },
    {
        "id": "insecure_http",
        "name": "Insecure HTTP URL",
        "severity": "low",
        "patterns": [
            r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)',
        ],
        "description": (
            "An HTTP (not HTTPS) URL was found. "
            "Data transmitted over plain HTTP is unencrypted and can be intercepted."
        ),
    },
    {
        "id": "todo_fixme",
        "name": "TODO / FIXME / HACK Comment",
        "severity": "info",
        "patterns": [
            r'(?i)\b(TODO|FIXME|HACK|XXX|BUG|SECURITY)\b',
        ],
        "description": (
            "A TODO / FIXME / HACK annotation was found. "
            "These often indicate incomplete, broken, or insecure code paths."
        ),
    },
]

# Pre-compile all regexes once at import time
_COMPILED_PATTERNS: List[Dict[str, Any]] = [
    {**p, "_compiled": [re.compile(r) for r in p["patterns"]]}
    for p in SECURITY_PATTERNS
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_github_url(url: str) -> Optional[Tuple[str, str]]:
    """Return (owner, repo) from a GitHub URL, or None if invalid."""
    url = url.strip().rstrip("/")

    # Shorthand  owner/repo
    if "://" not in url and "github.com" not in url:
        parts = url.split("/")
        if len(parts) == 2:
            return parts[0], parts[1].replace(".git", "")
        return None

    parsed = urlparse(url if "://" in url else "https://" + url)
    if "github.com" not in parsed.netloc:
        return None

    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    if len(path_parts) >= 2:
        return path_parts[0], path_parts[1].replace(".git", "")

    return None


def _should_skip(path: str) -> bool:
    """Return True if the file path should be excluded from scanning."""
    for fragment in SKIP_PATH_FRAGMENTS:
        if fragment in path:
            return True
    return False


def _has_scannable_extension(path: str) -> bool:
    for ext in CODE_EXTENSIONS:
        if path.endswith(ext):
            return True
    return False


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------

class GitHubScanner:
    """
    Fetches and analyses source files from a GitHub repository using
    the GitHub REST API. Works on public repos without authentication;
    supply a personal access token for private repos and higher rate limits.
    """

    def __init__(self, token: Optional[str] = None, timeout: int = 20):
        # (connect_timeout, read_timeout) – avoids hanging on a stalled connection
        self.timeout = (10, timeout)
        self._session = requests.Session()
        self._session.headers.update({
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "WebVulnScanner/1.0",
            # Disable keep-alive to avoid RemoteDisconnected on persistent connections
            "Connection": "close",
        })
        if token:
            self._session.headers["Authorization"] = f"token {token}"

        # Retry up to 3 times on connection errors and 5xx responses
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,          # waits 1 s, 2 s, 4 s between retries
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("https://", adapter)
        self._session.mount("http://",  adapter)

    # ------------------------------------------------------------------
    # GitHub API helpers
    # ------------------------------------------------------------------

    def _get(self, url: str) -> Any:
        try:
            resp = self._session.get(url, timeout=self.timeout)
        except requests.exceptions.ConnectionError as exc:
            msg = str(exc)
            hint = (
                "Tip: This is usually caused by a firewall, antivirus TLS inspection, "
                "or a corporate proxy blocking api.github.com. "
                "Try: (1) temporarily disable antivirus HTTPS scanning, "
                "(2) set HTTPS_PROXY env var if behind a proxy, "
                "(3) check your internet connection."
            )
            raise RuntimeError(
                f"Connection to GitHub API was reset or refused: {msg}\n{hint}"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "GitHub API request timed out. The server may be slow or unreachable."
            ) from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Network error reaching GitHub API: {exc}") from exc

        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 403:
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            raise RuntimeError(
                f"GitHub API rate limit hit or access forbidden "
                f"(X-RateLimit-Remaining: {remaining}). "
                "Provide a GitHub Personal Access Token to raise the limit."
            )
        if resp.status_code == 404:
            raise RuntimeError(
                "Repository not found or is private. "
                "Make sure the URL is correct and supply a token for private repos."
            )
        raise RuntimeError(f"GitHub API returned HTTP {resp.status_code}: {resp.text[:300]}")

    def _get_repo_info(self, owner: str, repo: str) -> Dict:
        return self._get(f"{GITHUB_API_BASE}/repos/{owner}/{repo}")

    def _get_tree(self, owner: str, repo: str, branch: str) -> List[Dict]:
        data = self._get(
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        )
        truncated = data.get("truncated", False)
        files = [f for f in data.get("tree", []) if f.get("type") == "blob"]
        return files, truncated

    def _get_file_content(self, owner: str, repo: str, path: str) -> Optional[str]:
        data = self._get(f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}")
        if isinstance(data, dict) and data.get("encoding") == "base64":
            try:
                return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
            except Exception:
                return None
        return None

    # ------------------------------------------------------------------
    # File analysis
    # ------------------------------------------------------------------

    def analyze_file(self, content: str, filepath: str) -> List[Dict[str, Any]]:
        """Run all security patterns against a single file's content."""
        issues: List[Dict[str, Any]] = []
        lines = content.splitlines()

        for pinfo in _COMPILED_PATTERNS:
            check_id = pinfo["id"]
            for compiled_re in pinfo["_compiled"]:
                for lineno, line in enumerate(lines, 1):
                    if compiled_re.search(line):
                        # Deduplicate: one finding per (check_id, line) per file
                        if any(
                            i["check_id"] == check_id and i["line"] == lineno
                            for i in issues
                        ):
                            continue
                        issues.append({
                            "check_id": check_id,
                            "type": pinfo["name"],
                            "severity": pinfo["severity"],
                            "file": filepath,
                            "line": lineno,
                            "code_snippet": line.strip()[:250],
                            "description": pinfo["description"],
                        })
        return issues

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan(
        self,
        repo_url: str,
        token: Optional[str] = None,
        progress_callback: Optional[Callable[[Dict], None]] = None,
        stop_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """
        Scan a GitHub repository for security and code-quality issues.

        Args:
            repo_url:          GitHub repository URL.
            token:             Optional GitHub Personal Access Token.
            progress_callback: Called with event dicts during the scan (for SSE / WS).
            stop_check:        Called each iteration; return True to abort early.

        Returns:
            Summary dict with ``issues``, ``severity_counts``, ``files_scanned``, etc.
        """
        if token:
            self._session.headers["Authorization"] = f"token {token}"

        def emit(event: Dict) -> None:
            if progress_callback:
                progress_callback(event)

        def should_stop() -> bool:
            return bool(stop_check and stop_check())

        # --- Validate URL ------------------------------------------------
        parsed_repo = parse_github_url(repo_url)
        if not parsed_repo:
            raise ValueError(
                f"'{repo_url}' is not a recognisable GitHub repository URL. "
                "Expected format: https://github.com/owner/repo"
            )
        owner, repo = parsed_repo

        emit({
            "status": "initializing",
            "phase": "Connecting to GitHub API",
            "progress": 5,
            "log": f"[INFO] Scanning GitHub repository: {owner}/{repo}",
        })

        # --- Repo metadata -----------------------------------------------
        repo_info = self._get_repo_info(owner, repo)
        default_branch = repo_info.get("default_branch", "main")
        repo_full_name = repo_info.get("full_name", f"{owner}/{repo}")
        language = repo_info.get("language") or "Unknown"
        stars = repo_info.get("stargazers_count", 0)

        emit({
            "status": "crawling",
            "phase": "Fetching file tree",
            "progress": 10,
            "log": (
                f"[INFO] {repo_full_name} | Language: {language} | "
                f"Stars: {stars} | Branch: {default_branch}"
            ),
        })

        # --- File tree ---------------------------------------------------
        all_blobs, truncated = self._get_tree(owner, repo, default_branch)
        if truncated:
            emit({"log": "[WARNING] Repository tree was truncated by GitHub API (>100k files)."})

        scannable = [
            f for f in all_blobs
            if _has_scannable_extension(f["path"])
            and not _should_skip(f["path"])
            and f.get("size", 0) <= MAX_FILE_SIZE
        ]

        emit({
            "status": "scanning",
            "phase": "Analysing source code",
            "progress": 15,
            "total_files": len(all_blobs),
            "scannable_files": len(scannable),
            "log": (
                f"[INFO] {len(all_blobs)} total files — "
                f"analysing {len(scannable)} code files (skipping binaries, deps, etc.)"
            ),
        })

        # --- Scan loop ---------------------------------------------------
        all_issues: List[Dict[str, Any]] = []
        errors: List[str] = []
        scanned = 0

        for file_info in scannable:
            if should_stop():
                emit({"log": "[INFO] Scan stopped by user.", "status": "idle"})
                break

            filepath = file_info["path"]
            try:
                content = self._get_file_content(owner, repo, filepath)
                if content:
                    issues = self.analyze_file(content, filepath)
                    for issue in issues:
                        all_issues.append(issue)
                        sev_upper = issue["severity"].upper()
                        emit({
                            "vulnerability": issue,
                            "log": (
                                f"[{sev_upper}] {issue['type']} — "
                                f"{filepath}:{issue['line']}"
                            ),
                        })
                # Polite rate-limit pause (GitHub allows 5 000 req/hr with token)
                time.sleep(0.05)
            except Exception as exc:
                errors.append(f"{filepath}: {exc}")
                emit({"log": f"[ERROR] Could not fetch {filepath}: {exc}"})

            scanned += 1
            progress = 15 + int((scanned / max(len(scannable), 1)) * 82)
            emit({
                "progress": progress,
                "files_scanned": scanned,
                "files_total": len(scannable),
                "issues_found": len(all_issues),
            })

        # --- Summary -----------------------------------------------------
        severity_counts: Dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
        }
        for issue in all_issues:
            sev = issue.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        summary = {
            "repo": repo_full_name,
            "language": language,
            "branch": default_branch,
            "files_scanned": scanned,
            "issues_found": len(all_issues),
            "severity_counts": severity_counts,
        }

        # --- Generate HTML report ----------------------------------------
        report_name = None
        try:
            emit({"log": "[INFO] Generating HTML report…"})
            report_path = generate_github_html_report(
                repo=repo_full_name,
                branch=default_branch,
                language=language,
                files_scanned=scanned,
                issues=all_issues,
                severity_counts=severity_counts,
                errors=errors,
                scan_duration="",
            )
            # report_name is the filename without directory, used as the download key
            from pathlib import Path
            report_name = Path(report_path).name
            emit({"log": f"[INFO] Report saved: {report_name}"})
        except Exception as rep_exc:
            emit({"log": f"[WARNING] Could not generate report: {rep_exc}"})

        emit({
            "status": "completed",
            "phase": "Scan Complete",
            "progress": 100,
            "summary": summary,
            "report_name": report_name,
            "log": (
                f"[INFO] GitHub scan complete — "
                f"{len(all_issues)} issues across {scanned} files."
            ),
        })

        return {
            "repo": repo_full_name,
            "branch": default_branch,
            "language": language,
            "files_scanned": scanned,
            "issues": all_issues,
            "severity_counts": severity_counts,
            "errors": errors,
            "report_name": report_name,
        }
