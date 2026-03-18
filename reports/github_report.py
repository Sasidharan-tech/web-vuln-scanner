"""
GitHub Repository Security Report Generator

Produces a self-contained HTML report from the results of GitHubScanner.
"""

import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

_SEVERITY_COLOR = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#17a2b8",
    "info":     "#6c757d",
}

_SEVERITY_TEXT_COLOR = {
    "critical": "#fff",
    "high":     "#fff",
    "medium":   "#333",
    "low":      "#fff",
    "info":     "#fff",
}

_SEVERITY_BORDER = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#17a2b8",
    "info":     "#6c757d",
}

_REMEDIATION = {
    "hardcoded_password":   "Move passwords to environment variables or a secrets manager (e.g. HashiCorp Vault, AWS Secrets Manager). Rotate any exposed credentials immediately.",
    "hardcoded_secret":     "Remove the key from the repository, rotate it immediately, and store it in an environment variable or CI/CD secret store.",
    "aws_credentials":      "Revoke the AWS key in the IAM console immediately. Use IAM roles or AWS Secrets Manager instead of embedding keys in code.",
    "private_key":          "Revoke the private key, generate a new one, and never commit keys to version control. Use a secret manager or encrypted vault.",
    "eval_usage":           "Replace eval() with safe alternatives. If dynamic code execution is truly needed, strictly validate and sanitise all inputs before evaluation.",
    "exec_shell":           "Use subprocess with a list argument (no shell=True) so the OS cannot interpret shell metacharacters. Validate and whitelist any user input that forms part of the command.",
    "sql_injection_pattern":"Use parameterised queries or prepared statements. Never concatenate user input into SQL strings.",
    "xss_pattern":          "Use textContent instead of innerHTML for inserting plain text. If HTML is required, sanitise it with a library such as DOMPurify.",
    "weak_hash":            "Use bcrypt, argon2, or scrypt for password hashing. Use SHA-256 or SHA-3 for data integrity checks.",
    "debug_enabled":        "Set DEBUG=False in production configuration. Use environment-specific config files and never hardcode environment names.",
    "sensitive_logging":    "Remove sensitive data from log calls. If auditing is required, redact or mask the sensitive fields before logging.",
    "hardcoded_ip":         "Move server addresses to environment variables or configuration files so they can be changed without a code deployment.",
    "insecure_http":        "Replace http:// with https:// for all external URLs to ensure data is encrypted in transit.",
    "todo_fixme":           "Review and resolve the annotation before releasing to production. Security-tagged TODOs should be treated as bugs.",
}


def generate_github_html_report(
    *,
    repo: str,
    branch: str,
    language: str,
    files_scanned: int,
    issues: List[Dict[str, Any]],
    severity_counts: Dict[str, int],
    errors: List[str],
    scan_duration: str = "",
    output_path: Optional[str] = None,
) -> str:
    """
    Build a self-contained HTML security report.

    Returns the absolute path to the saved file.
    """
    now = datetime.now()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    safe_repo = repo.replace("/", "_").replace(".", "_")
    file_ts   = now.strftime("%Y%m%d_%H%M%S")

    if output_path is None:
        reports_dir = Path(__file__).parent.parent / "reports" / "github"
        reports_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(reports_dir / f"github_{safe_repo}_{file_ts}.html")

    # Group issues by severity then by file
    by_severity: Dict[str, List[Dict]] = {s: [] for s in _SEVERITY_ORDER}
    for issue in issues:
        sev = issue.get("severity", "info").lower()
        by_severity.setdefault(sev, []).append(issue)

    total = len(issues)
    risk_score = (
        severity_counts.get("critical", 0) * 10 +
        severity_counts.get("high", 0) * 5 +
        severity_counts.get("medium", 0) * 2 +
        severity_counts.get("low", 0) * 1
    )
    if risk_score == 0:
        risk_label, risk_color = "Clean", "#28a745"
    elif risk_score <= 5:
        risk_label, risk_color = "Low Risk", "#17a2b8"
    elif risk_score <= 20:
        risk_label, risk_color = "Medium Risk", "#ffc107"
    elif risk_score <= 50:
        risk_label, risk_color = "High Risk", "#fd7e14"
    else:
        risk_label, risk_color = "Critical Risk", "#dc3545"

    # ------------------------------------------------------------------ HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitHub Security Report – {escape(repo)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#0d1117;color:#c9d1d9;line-height:1.6}}
a{{color:#58a6ff;text-decoration:none}}
a:hover{{text-decoration:underline}}
.wrap{{max-width:1100px;margin:0 auto;padding:24px 16px}}
/* ── header ── */
header{{background:linear-gradient(135deg,#6e40c9 0%,#3b82f6 100%);
        color:#fff;padding:40px 32px;border-radius:12px;margin-bottom:28px}}
header h1{{font-size:1.9rem;margin-bottom:6px}}
header .sub{{opacity:.85;font-size:.95rem}}
.badge{{display:inline-block;padding:4px 14px;border-radius:20px;
         font-size:.8rem;font-weight:700;letter-spacing:.4px}}
.risk-badge{{font-size:1rem;padding:6px 20px;border-radius:24px;
              color:#fff;font-weight:700;background:{risk_color}}}
/* ── cards ── */
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;
        margin-bottom:20px;overflow:hidden}}
.card-head{{background:#21262d;padding:12px 20px;font-weight:600;
             font-size:1rem;border-bottom:1px solid #30363d}}
.card-body{{padding:20px}}
/* ── stat grid ── */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:14px}}
.stat-box{{background:#21262d;border-radius:8px;padding:18px;text-align:center}}
.stat-num{{font-size:2rem;font-weight:700}}
.stat-lbl{{font-size:.8rem;color:#8b949e;margin-top:4px}}
/* ── severity bars ── */
.sev-grid{{display:grid;
           grid-template-columns:repeat(5,1fr);gap:10px;margin-top:16px}}
.sev-box{{border-radius:8px;padding:14px;text-align:center;color:#fff;font-weight:600}}
.sev-box .n{{font-size:1.6rem}}
.sev-box .l{{font-size:.75rem;margin-top:2px;opacity:.9}}
/* ── issue cards ── */
.issue{{border-left:4px solid #30363d;background:#0d1117;border-radius:0 8px 8px 0;
         margin-bottom:12px;padding:14px 16px}}
.issue-head{{display:flex;justify-content:space-between;align-items:flex-start;
              gap:8px;margin-bottom:8px;flex-wrap:wrap}}
.issue-type{{font-weight:600;font-size:.97rem}}
.sev-pill{{padding:3px 12px;border-radius:14px;font-size:.75rem;
            font-weight:700;letter-spacing:.3px}}
.issue-desc{{font-size:.88rem;color:#8b949e;margin-bottom:10px}}
.code-box{{background:#161b22;border:1px solid #30363d;border-radius:6px;
            padding:10px 14px;font-family:'Consolas','Courier New',monospace;
            font-size:.82rem;overflow-x:auto;white-space:pre;color:#e3b341;
            margin-bottom:10px}}
.meta{{font-size:.82rem;color:#8b949e}}
.meta span{{color:#c9d1d9}}
.remed{{background:#122d1e;border:1px solid #1f6335;border-radius:6px;
         padding:10px 14px;font-size:.85rem;color:#3fb950;margin-top:8px}}
.remed strong{{color:#56d364}}
/* ── file path ── */
.filepath{{font-family:monospace;color:#79c0ff;font-size:.85rem}}
/* ── section toggle ── */
.section-title{{cursor:pointer;display:flex;justify-content:space-between;
                 align-items:center;padding:10px 0}}
.section-title:hover{{color:#58a6ff}}
/* ── errors ── */
.err-item{{background:#21262d;border-left:3px solid #f85149;border-radius:4px;
            padding:8px 12px;font-size:.83rem;color:#f85149;margin-bottom:6px;
            font-family:monospace}}
/* ── empty ── */
.empty{{text-align:center;padding:40px 20px;color:#8b949e}}
.empty .icon{{font-size:3rem;margin-bottom:12px}}
/* ── footer ── */
footer{{text-align:center;padding:24px;color:#8b949e;font-size:.85rem;
         border-top:1px solid #30363d;margin-top:28px}}
@media(max-width:600px){{
  .sev-grid{{grid-template-columns:repeat(3,1fr)}}
  header h1{{font-size:1.4rem}}
}}
</style>
</head>
<body>
<div class="wrap">

<!-- ── Header ───────────────────────────────────────────────────────── -->
<header>
  <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px">
    <div>
      <h1>&#x1f512; GitHub Security Report</h1>
      <p class="sub">
        <a href="https://github.com/{escape(repo)}" target="_blank"
           style="color:#fff;font-weight:600">github.com/{escape(repo)}</a>
        &nbsp;&bull;&nbsp; branch: <strong>{escape(branch)}</strong>
        &nbsp;&bull;&nbsp; {escape(language)}
      </p>
      <p class="sub" style="margin-top:6px;font-size:.85rem">
        Scanned: {timestamp}
        {f' &bull; Duration: {escape(scan_duration)}' if scan_duration else ''}
      </p>
    </div>
    <div style="text-align:right">
      <span class="risk-badge">{risk_label}</span>
      <div style="font-size:.8rem;margin-top:6px;opacity:.8">Risk Score: {risk_score}</div>
    </div>
  </div>
</header>

<!-- ── Summary stats ────────────────────────────────────────────────── -->
<div class="card">
  <div class="card-head">&#x1f4ca; Scan Summary</div>
  <div class="card-body">
    <div class="stat-grid">
      <div class="stat-box">
        <div class="stat-num" style="color:#58a6ff">{files_scanned}</div>
        <div class="stat-lbl">Files Scanned</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:{'#f85149' if total else '#3fb950'}">{total}</div>
        <div class="stat-lbl">Issues Found</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#dc3545">{severity_counts.get('critical', 0)}</div>
        <div class="stat-lbl">Critical</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#fd7e14">{severity_counts.get('high', 0)}</div>
        <div class="stat-lbl">High</div>
      </div>
      <div class="stat-box">
        <div class="stat-num" style="color:#ffc107">{severity_counts.get('medium', 0)}</div>
        <div class="stat-lbl">Medium</div>
      </div>
    </div>

    <div class="sev-grid" style="margin-top:20px">
"""

    for sev in _SEVERITY_ORDER:
        count  = severity_counts.get(sev, 0)
        bg     = _SEVERITY_COLOR[sev]
        tc     = _SEVERITY_TEXT_COLOR[sev]
        html += f"""      <div class="sev-box" style="background:{bg};color:{tc}">
        <div class="n">{count}</div>
        <div class="l">{sev.capitalize()}</div>
      </div>\n"""

    html += """    </div>
  </div>
</div>

"""

    # ── Issues by severity ───────────────────────────────────────────────────
    if not issues:
        html += """<div class="card">
  <div class="card-head">&#x1f50d; Issues</div>
  <div class="card-body">
    <div class="empty">
      <div class="icon">&#x2705;</div>
      <p>No security issues were detected in the scanned files.</p>
    </div>
  </div>
</div>
"""
    else:
        for sev in _SEVERITY_ORDER:
            sev_issues = by_severity.get(sev, [])
            if not sev_issues:
                continue
            bg    = _SEVERITY_COLOR[sev]
            tc    = _SEVERITY_TEXT_COLOR[sev]
            border = _SEVERITY_BORDER[sev]
            html += f"""<div class="card">
  <div class="card-head" style="border-left:4px solid {border};padding-left:16px">
    {sev.capitalize()} Severity &nbsp;
    <span class="badge" style="background:{bg};color:{tc}">{len(sev_issues)}</span>
  </div>
  <div class="card-body">
"""
            for issue in sev_issues:
                file_esc    = escape(issue.get("file", ""))
                line        = issue.get("line", "")
                snippet     = escape(issue.get("code_snippet", ""))
                desc        = escape(issue.get("description", ""))
                check_id    = issue.get("check_id", "")
                itype       = escape(issue.get("type", ""))
                remediation = escape(_REMEDIATION.get(check_id, "Review and remediate this finding before deploying to production."))
                pill_style  = f"background:{bg};color:{tc}"
                gh_url      = f"https://github.com/{repo}/blob/{branch}/{issue.get('file', '')}#L{line}"

                html += f"""    <div class="issue" style="border-left-color:{border}">
      <div class="issue-head">
        <span class="issue-type">{itype}</span>
        <span class="sev-pill" style="{pill_style}">{sev.upper()}</span>
      </div>
      <p class="issue-desc">{desc}</p>
      <div class="meta">
        &#x1f4c4; File:&nbsp;<a class="filepath" href="{gh_url}" target="_blank">{file_esc}:{line}</a>
      </div>
"""
                if snippet:
                    html += f"""      <div class="code-box">{snippet}</div>\n"""

                html += f"""      <div class="remed"><strong>&#x2705; Remediation:</strong> {remediation}</div>
    </div>
"""
            html += "  </div>\n</div>\n\n"

    # ── Errors (files we couldn't fetch) ────────────────────────────────────
    if errors:
        html += f"""<div class="card">
  <div class="card-head" style="color:#f85149">&#x26a0;&#xfe0f; Fetch Errors ({len(errors)})</div>
  <div class="card-body">
    <p style="font-size:.85rem;color:#8b949e;margin-bottom:12px">
      The following files could not be fetched (API rate limits, inaccessible paths, etc.):
    </p>
"""
        for err in errors[:50]:
            html += f'    <div class="err-item">{escape(err)}</div>\n'
        if len(errors) > 50:
            html += f'    <div class="err-item">… and {len(errors) - 50} more</div>\n'
        html += "  </div>\n</div>\n\n"

    # ── Footer ───────────────────────────────────────────────────────────────
    html += f"""<footer>
  Generated by <strong>Web Vulnerability Scanner — GitHub Code Scanner</strong>
  &bull; {timestamp}
  &bull; <a href="https://github.com/{escape(repo)}" target="_blank">{escape(repo)}</a>
</footer>

</div>
</body>
</html>
"""

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return str(out)
