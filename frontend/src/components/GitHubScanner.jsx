/**
 * GitHubScanner.jsx
 * Scan a GitHub repository for secrets, credentials, and security issues.
 *
 * Features:
 *  - Input for GitHub repo URL + optional personal access token
 *  - Start / stop scan via SSE stream
 *  - Real-time log output
 *  - Progress bar
 *  - Findings list with type/severity/file/match
 *  - Download HTML report
 */
import { useState, useRef, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/** Severity badge */
function SeverityBadge({ severity }) {
  const s = (severity || 'info').toLowerCase();
  const cls = s === 'critical' ? 'critical'
            : s === 'high'     ? 'high'
            : s === 'medium'   ? 'medium'
            : s === 'low'      ? 'low'
            : 'info';
  return <span className={`badge badge-${cls}`}>{severity || 'Info'}</span>;
}

/** A single finding card from the GitHub scan */
function FindingCard({ finding }) {
  const sev = (finding.severity || 'info').toLowerCase();
  const cls = sev === 'critical' ? 'critical'
            : sev === 'high'     ? 'high'
            : sev === 'medium'   ? 'medium'
            : sev === 'low'      ? 'low'
            : 'info';

  return (
    <div className={`finding-card vuln-card ${cls}`}>
      <div className="finding-card-header">
        <span className="vuln-type">{finding.type || finding.rule_id || 'Secret/Credential'}</span>
        <SeverityBadge severity={finding.severity} />
      </div>

      {finding.file && (
        <div style={{ marginBottom: 6 }}>
          <span className="finding-file">📄 {finding.file}{finding.line ? `:${finding.line}` : ''}</span>
        </div>
      )}

      {finding.description && (
        <div className="vuln-description">{finding.description}</div>
      )}

      {finding.match && (
        <div className="finding-match">{finding.match}</div>
      )}

      {finding.recommendation && (
        <div className="vuln-recommendation">💡 {finding.recommendation}</div>
      )}
    </div>
  );
}

export default function GitHubScanner() {
  // Form state
  const [repoUrl, setRepoUrl] = useState('');
  const [token, setToken]     = useState('');

  // Runtime state
  const [scanning, setScanning]     = useState(false);
  const [logs, setLogs]             = useState([]);
  const [findings, setFindings]     = useState([]);
  const [progress, setProgress]     = useState(0);
  const [statusMsg, setStatusMsg]   = useState('');
  const [reportName, setReportName] = useState('');
  const [error, setError]           = useState('');

  // Ref to the EventSource so we can close it on Stop
  const esRef     = useRef(null);
  const logBoxRef = useRef(null);

  // Auto-scroll log
  useEffect(() => {
    if (logBoxRef.current) {
      logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
    }
  }, [logs]);

  /** Start GitHub scan via SSE POST */
  async function startScan() {
    if (!repoUrl.trim()) {
      setError('Please enter a GitHub repository URL.');
      return;
    }
    setError('');
    setLogs([]);
    setFindings([]);
    setProgress(0);
    setStatusMsg('Connecting…');
    setReportName('');
    setScanning(true);

    try {
      // The GitHub scan endpoint is a POST that returns an SSE stream.
      // We use fetch with ReadableStream to consume it.
      const res = await fetch(`${API}/api/github/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo_url: repoUrl.trim(),
          token:    token.trim() || undefined,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Scan failed to start');
      }

      // Read the SSE stream manually
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete line in buffer

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            const raw = line.slice(6).trim();
            if (!raw) continue;
            try {
              const msg = JSON.parse(raw);
              handleMessage(msg);
            } catch {
              appendLog(raw, 'info');
            }
          }
        }
      }
    } catch (err) {
      appendLog(`Error: ${err.message}`, 'error');
      setError(err.message);
    } finally {
      setScanning(false);
      if (statusMsg === 'Connecting…') setStatusMsg('');
    }
  }

  /** Stop a running GitHub scan */
  async function stopScan() {
    try {
      await fetch(`${API}/api/github/scan/stop`, { method: 'POST' });
    } catch { /* ignore */ }
    setScanning(false);
    setStatusMsg('Stopped');
    appendLog('GitHub scan stopped by user.', 'warn');
  }

  /** Process a parsed SSE message */
  function handleMessage(msg) {
    if (!msg) return;

    if (typeof msg.progress === 'number') setProgress(msg.progress);
    if (msg.status) setStatusMsg(msg.status);

    if (msg.message) {
      const cls = msg.type === 'finding' ? 'found'
                : msg.level === 'error'  ? 'error'
                : msg.level === 'warn'   ? 'warn'
                : 'info';
      appendLog(msg.message, cls);
    }

    // Finding object
    if (msg.type === 'finding' || msg.rule_id || msg.match) {
      setFindings(prev => [...prev, msg]);
    }

    // Report file name for download
    if (msg.report) setReportName(msg.report);

    // Scan done
    if (msg.type === 'done' || msg.status === 'complete') {
      setProgress(100);
      setScanning(false);
      appendLog('GitHub scan complete.', 'info');
    }
  }

  function appendLog(text, cls = 'info') {
    setLogs(prev => [...prev, { text, cls, id: Date.now() + Math.random() }]);
  }

  return (
    <div>
      <div className="section-header">
        <h2>🐙 GitHub Security Scanner</h2>
        <p>Scan GitHub repositories for exposed secrets, credentials, and security issues</p>
      </div>

      <div className="scanner-layout">
        {/* ── LEFT: Configuration ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card">
            <div className="card-title">⚙️ Repository Configuration</div>

            {error && <div className="alert alert-error">⚠ {error}</div>}

            {/* Repo URL */}
            <div className="form-group">
              <label className="form-label">GitHub Repository URL *</label>
              <input
                className="form-control"
                type="url"
                placeholder="https://github.com/owner/repo"
                value={repoUrl}
                onChange={e => setRepoUrl(e.target.value)}
                disabled={scanning}
              />
            </div>

            {/* Optional token */}
            <div className="form-group">
              <label className="form-label">
                Personal Access Token
                <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 6 }}>
                  (optional — for private repos)
                </span>
              </label>
              <input
                className="form-control"
                type="password"
                placeholder="ghp_xxxxxxxxxxxx"
                value={token}
                onChange={e => setToken(e.target.value)}
                disabled={scanning}
              />
            </div>

            <div className="alert alert-info" style={{ fontSize: '0.82rem' }}>
              💡 The token is sent to the backend only and is never stored. Use a read-only token with <code>repo</code> scope.
            </div>

            {/* Start / Stop */}
            <div className="flex-row mt-12">
              {!scanning ? (
                <button className="btn btn-primary btn-lg" onClick={startScan} style={{ flex: 1 }}>
                  ▶ Start Scan
                </button>
              ) : (
                <button className="btn btn-danger btn-lg" onClick={stopScan} style={{ flex: 1 }}>
                  ⏹ Stop Scan
                </button>
              )}
            </div>
          </div>

          {/* Progress */}
          {(scanning || progress > 0) && (
            <div className="card">
              <div className="flex-between mb-8">
                <span className="card-title" style={{ marginBottom: 0 }}>
                  <span className={`status-dot ${scanning ? 'running' : 'online'}`} />
                  {statusMsg || 'Scanning…'}
                </span>
                <span className="text-muted" style={{ fontSize: '0.85rem' }}>{progress}%</span>
              </div>
              <div className="progress-bar-outer">
                <div className="progress-bar-inner" style={{ width: `${progress}%` }} />
              </div>
            </div>
          )}

          {/* Download report */}
          {reportName && (
            <div className="card">
              <div className="card-title">📋 Report Ready</div>
              <a
                className="btn btn-primary w-full"
                href={`${API}/api/github/report/${reportName}`}
                download={reportName}
                target="_blank"
                rel="noreferrer"
              >
                📥 Download HTML Report
              </a>
            </div>
          )}
        </div>

        {/* ── RIGHT: Logs + Findings ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Log output */}
          <div className="card">
            <div className="flex-between mb-8">
              <div className="card-title" style={{ marginBottom: 0 }}>📟 Live Output</div>
              {logs.length > 0 && (
                <button className="btn btn-outline btn-sm" onClick={() => setLogs([])}>
                  Clear
                </button>
              )}
            </div>
            <div className="log-box" ref={logBoxRef}>
              {logs.length === 0 ? (
                <span style={{ color: 'var(--text-muted)' }}>Scan output will appear here…</span>
              ) : (
                logs.map(l => (
                  <div key={l.id} className={`log-line ${l.cls}`}>{l.text}</div>
                ))
              )}
            </div>
          </div>

          {/* Findings */}
          <div className="card">
            <div className="flex-between mb-12">
              <div className="card-title" style={{ marginBottom: 0 }}>
                🔎 Findings
              </div>
              {findings.length > 0 && (
                <span className="badge badge-high">{findings.length} found</span>
              )}
            </div>

            {/* Severity summary */}
            {findings.length > 0 && (
              <div className="summary-grid" style={{ marginBottom: 16 }}>
                {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                  const cnt = findings.filter(f => {
                    const s = (f.severity || 'info').toLowerCase();
                    return (s === sev) || (sev === 'info' && !['critical','high','medium','low'].includes(s));
                  }).length;
                  if (cnt === 0) return null;
                  return (
                    <div key={sev} className={`summary-card ${sev}`}>
                      <div className="count">{cnt}</div>
                      <div className="label">{sev}</div>
                    </div>
                  );
                })}
              </div>
            )}

            {findings.length === 0 ? (
              <div className="empty-state">
                <div className="icon">🔍</div>
                <p>No findings yet.</p>
                <p style={{ fontSize: '0.8rem', marginTop: 4 }}>
                  Start a scan to detect exposed secrets or vulnerabilities.
                </p>
              </div>
            ) : (
              <div className="vuln-list">
                {findings.map((f, i) => <FindingCard key={i} finding={f} />)}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
