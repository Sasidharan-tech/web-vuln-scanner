# Web Vulnerability Scanner — Unified Edition

A **unified web vulnerability scanner** combining two complementary scanning engines into a single dashboard:

- **Native Scanner** — Python-based black-box scanner with real-time SSE streaming (SQL Injection, XSS, Command Injection, LFI, Open Redirect, Security Headers, Cookie analysis)
- **Meta Scanner (OSTE)** — Orchestrates industry-standard tools: Wapiti, OWASP ZAP, Nuclei, Nikto, and Skipfish with weighted result consolidation
- **GitHub Code Scanner** — Static security analysis of GitHub repositories: detects hardcoded secrets, SQL injection patterns, dangerous function calls, weak crypto, debug mode leaks, and more

---

## Quick Start

### Backend
```bash
pip install -r requirements.txt
python api.py          # starts FastAPI server on http://localhost:8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev            # starts Next.js on http://localhost:3000
```

### CLI (native scanner only)
```bash
python main.py --url https://example.com --modules sql,xss,headers
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  FastAPI Backend  (api.py)  port 8000               │
│                                                     │
│  GET  /api/scan           ← SSE stream (native)     │
│  POST /api/scan/stop      ← stop native scan        │
│                                                     │
│  POST /api/meta/scan/start   ← start meta scan      │
│  GET  /api/meta/scan/{id}/status                    │
│  GET  /api/meta/results   ← list saved results      │
│  GET  /api/meta/results/{name}/html ← HTML export   │
│  GET/PUT /api/meta/settings                         │
│  GET/PUT /api/meta/weights                          │
│  WebSocket /ws/{client_id} ← real-time updates      │
│                                                     │
│  POST /api/github/scan       ← GitHub repo scan SSE │
│  POST /api/github/scan/stop  ← stop GitHub scan     │
└─────────────────────────────────────────────────────┘
         ▲                        ▲                  ▲
    NativeScanner           MetaScanner        GitHubScanner
  component (SSE)         component (WS)      component (SSE)
         ▲                        ▲                  ▲
└────────────────────────────────────────────────────────┘
           Next.js Frontend  port 3000
           frontend/src/app/page.tsx  (three-tab UI)
```

### Key Files
| File | Purpose |
|------|---------|
| `api.py` | Unified FastAPI backend |
| `meta_scanner/` | OSTE meta-scanner Python module |
| `scanner/github_scanner.py` | GitHub repository code scanner |
| `weights/weights.json` | Scanner weight configuration |
| `results/` | Meta-scan result storage |
| `frontend/src/app/page.tsx` | Unified two-tab UI |
| `frontend/src/components/native-scanner.tsx` | Native scanner UI |
| `frontend/src/components/meta-scanner.tsx` | OSTE meta-scanner UI |

---

## Meta Scanner: External Tools Setup

The Meta Scanner requires these tools to be installed and on `PATH`:

| Tool | Install |
|------|---------|
| [Wapiti](https://wapiti-scanner.github.io/) | `pip install wapiti3` |
| [Nuclei](https://nuclei.projectdiscovery.io/) | Download from GitHub releases |
| [Nikto](https://github.com/sullo/nikto) | `apt install nikto` / brew / manual |
| [Skipfish](https://github.com/spinkham/skipfish) | Build from source / package manager |
| [OWASP ZAP](https://www.zaproxy.org/) | `pip install zaproxy` (optional) |

Tools are optional — the scanner will skip unavailable tools and aggregate results from the rest.

---

A **black-box web vulnerability scanner** written in Python, inspired by Wapiti. This tool crawls websites, injects payloads, and detects common web vulnerabilities without accessing source code.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Table of Contents

- [Features](#features)
- [How Black-Box Scanning Works](#how-black-box-scanning-works)
- [Installation](#installation)
- [Usage](#usage)
- [Vulnerability Modules](#vulnerability-modules)
- [Project Structure](#project-structure)
- [Reports](#reports)
- [Examples](#examples)
- [Ethical Guidelines](#ethical-guidelines)
- [Contributing](#contributing)

## Features

### Core Capabilities
- **URL Crawler** - Discovers URLs, forms, and parameters automatically
- **Modular Architecture** - Enable/disable specific vulnerability checks
- **Session Management** - Save and resume interrupted scans
- **Multiple Report Formats** - HTML and JSON reports

### Vulnerability Detection
- SQL Injection (Error-based & Time-based)
- Cross-Site Scripting (Reflected XSS)
- OS Command Injection
- Local/Remote File Inclusion (LFI/RFI)
- Open Redirect
- Missing Security Headers
- Insecure Cookie Flags

## How Black-Box Scanning Works

Black-box scanning (also known as "dynamic analysis") tests applications **from the outside**, without access to source code:

```
┌─────────────────────────────────────────────────────────────┐
│                    BLACK-BOX SCANNING                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────┐    HTTP Requests    ┌─────────────────┐       │
│   │         │ ─────────────────▶  │                 │       │
│   │ Scanner │    with payloads    │  Target Website │       │
│   │         │ ◀─────────────────  │                 │       │
│   └─────────┘    HTTP Responses   └─────────────────┘       │
│       │                                   ▲                 │
│       │ Analyze responses for:            │                 │
│       │ - Error messages                  │                 │
│       │ - Response time delays            │ No access to:   │
│       │ - Reflected payloads              │ - Source code   │
│       │ - Abnormal behavior               │ - Database      │
│       ▼                                   │ - Server config │
│   ┌─────────┐                                               │
│   │ Report  │                                               │
│   │ Vulns   │                                               │
│   └─────────┘                                               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### The Process:

1. **Crawling**: The scanner visits the target URL and extracts:
   - Links (`<a href="...">`)
   - Forms (`<form>`) with their input fields
   - URL parameters (`?id=1&name=test`)

2. **Fuzzing**: For each discovered parameter, the scanner:
   - Injects malicious payloads
   - Sends the modified request
   - Analyzes the response

3. **Detection**: Vulnerabilities are identified by:
   - **Error messages** (SQL errors, stack traces)
   - **Time delays** (sleep-based injection)
   - **Payload reflection** (XSS in response)
   - **Behavioral changes** (different responses)

4. **Reporting**: Results are compiled with:
   - Affected URLs and parameters
   - Payloads that triggered vulnerabilities
   - Severity ratings and remediation advice

## Installation

### Requirements
- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. **Clone or download the project:**
```bash
cd web-vuln-scanner
```

2. **Create a virtual environment (recommended):**
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Unix/macOS:
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scan
```bash
python main.py -u http://testphp.vulnweb.com
```

### Specify Modules
```bash
# Only SQL injection and XSS
python main.py -u http://example.com -m sql,xss

# All except headers and cookies
python main.py -u http://example.com -m sql,xss,cmd,lfi,redirect
```

### Customize Crawling
```bash
# Crawl depth of 5, max 200 URLs
python main.py -u http://example.com --depth 5 --max-urls 200
```

### Output Options
```bash
# HTML report only
python main.py -u http://example.com -o my_scan -f html

# JSON report only
python main.py -u http://example.com -o results -f json

# Both formats (default)
python main.py -u http://example.com -o full_report -f both
```

### Resume Interrupted Scan
```bash
# If scan is interrupted, resume with:
python main.py -u http://example.com --resume
```

### Full Options
```bash
python main.py --help
```

```
usage: main.py [-h] -u URL [-m MODULES] [--depth DEPTH] [--max-urls MAX_URLS]
               [--timeout TIMEOUT] [--delay DELAY] [--user-agent USER_AGENT]
               [--resume] [--session-name SESSION_NAME] [-o OUTPUT]
               [-f {html,json,both}] [-v] [-q] [--accept-terms]

Options:
  -u, --url         Target URL to scan (required)
  -m, --modules     Modules to run: sql,xss,cmd,lfi,redirect,headers,cookies
  --depth           Maximum crawl depth (default: 2)
  --max-urls        Maximum URLs to crawl (default: 100)
  --timeout         Request timeout in seconds (default: 10)
  --delay           Delay between requests (default: 0.5)
  --resume          Resume previous scan session
  -o, --output      Output file name (default: scan_report)
  -f, --format      Report format: html, json, both
  -v, --verbose     Enable verbose output
  -q, --quiet       Suppress non-essential output
  --accept-terms    Accept legal disclaimer automatically
```

## Vulnerability Modules

### 1. SQL Injection (`sql`)
Detects SQL injection by injecting payloads and looking for:
- Database error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Time-based delays (SLEEP, WAITFOR, BENCHMARK)

**Severity: Critical**

### 2. Cross-Site Scripting (`xss`)
Detects reflected XSS by:
- Injecting JavaScript payloads
- Checking if payloads appear unencoded in responses
- Testing various encoding bypasses

**Severity: High**

### 3. Command Injection (`cmd`)
Detects OS command injection by:
- Injecting shell commands
- Looking for command output in responses
- Using time-based detection (sleep/ping)

**Severity: Critical**

### 4. File Inclusion (`lfi`)
Detects LFI/RFI by:
- Attempting to include system files (/etc/passwd, etc.)
- Using path traversal techniques
- Testing PHP wrappers

**Severity: Critical**

### 5. Open Redirect (`redirect`)
Detects open redirects by:
- Injecting external URLs
- Checking Location headers
- Testing various bypass techniques

**Severity: Medium**

### 6. Security Headers (`headers`)
Checks for missing security headers:
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security
- And more...

**Severity: Medium/Low**

### 7. Cookie Security (`cookies`)
Checks cookie flags:
- Secure flag (HTTPS only)
- HttpOnly flag (no JS access)
- SameSite attribute (CSRF protection)

**Severity: Medium/Low**

## Project Structure

```
web-vuln-scanner/
├── main.py                 # Main entry point and CLI
├── requirements.txt        # Python dependencies
├── README.md              # This file
│
├── crawler/               # Web crawling module
│   ├── __init__.py
│   └── spider.py          # URL/form discovery
│
├── scanner/               # Vulnerability scanners
│   ├── __init__.py
│   ├── base.py            # Base scanner class
│   ├── sql_injection.py   # SQL injection detection
│   ├── xss.py             # XSS detection
│   ├── command_injection.py
│   ├── file_inclusion.py
│   ├── open_redirect.py
│   ├── headers.py         # Security headers check
│   └── cookies.py         # Cookie security check
│
├── payloads/              # Attack payload files
│   ├── __init__.py
│   ├── sql_injection.txt
│   ├── xss.txt
│   ├── command_injection.txt
│   ├── file_inclusion.txt
│   └── open_redirect.txt
│
├── database/              # Session persistence
│   ├── __init__.py
│   └── session.py         # SQLite session management
│
├── reports/               # Report generation
│   ├── __init__.py
│   └── generator.py       # HTML/JSON reports
│
└── utils/                 # Utilities
    ├── __init__.py
    ├── logger.py          # Logging utilities
    ├── banner.py          # CLI banner/disclaimer
    └── http_helper.py     # HTTP utilities
```

## Reports

### HTML Report
Beautiful, interactive HTML report with:
- Scan summary and statistics
- Severity breakdown (Critical/High/Medium/Low/Info)
- Detailed vulnerability cards
- Remediation recommendations

### JSON Report
Machine-readable JSON format for:
- CI/CD integration
- Custom processing
- Data analysis

## Examples

### Example 1: Quick Security Audit
```bash
# Fast scan with essential modules
python main.py -u https://example.com -m sql,xss,headers --depth 1
```

### Example 2: Deep Scan
```bash
# Comprehensive scan with high depth
python main.py -u https://example.com --depth 5 --max-urls 500 -v
```

### Example 3: Focused Testing
```bash
# Only test for SQL injection with verbose output
python main.py -u https://example.com/search?q=test -m sql -v
```

### Example 4: API Security Check
```bash
# Check security headers and cookies only
python main.py -u https://api.example.com -m headers,cookies
```

### Example 5: Resume Long Scan
```bash
# Start a scan
python main.py -u https://big-site.com --max-urls 1000

# If interrupted, resume:
python main.py -u https://big-site.com --resume
```

## Ethical Guidelines

### Legal Disclaimer

**This tool is intended for AUTHORIZED SECURITY TESTING ONLY.**

Before using this scanner, you MUST:

1. ✅ Have **explicit written permission** from the system owner
2. ✅ Be authorized to perform security assessments
3. ✅ Understand that unauthorized scanning is **ILLEGAL**
4. ✅ Accept full responsibility for your actions

### Unauthorized Testing is Illegal

Scanning systems without permission violates:
- Computer Fraud and Abuse Act (CFAA) - USA
- Computer Misuse Act - UK
- Similar laws in most countries

**Penalties can include:**
- Criminal prosecution
- Heavy fines
- Imprisonment
- Civil liability

### Recommended Test Targets

Practice on intentionally vulnerable applications:
- [DVWA](http://www.dvwa.co.uk/) - Damn Vulnerable Web Application
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [Vulnweb](http://testphp.vulnweb.com/) - Acunetix test site
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

## Contributing

Contributions are welcome! Areas for improvement:
- Additional vulnerability modules
- More payload variations
- Better detection accuracy
- Performance optimization
- Documentation

## License

MIT License - See LICENSE file for details.

## Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGE CAUSED BY THIS PROGRAM. USE RESPONSIBLY AND ETHICALLY.

---

**Remember: With great power comes great responsibility. Always hack ethically! 🔐**
