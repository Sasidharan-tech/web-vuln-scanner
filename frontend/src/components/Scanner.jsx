/**
 * Scanner.jsx
 * The main web vulnerability scanner UI.
 *
 * Features:
 *  - URL input + module checkboxes + depth/max_urls options
 *  - Start scan via SSE (EventSource) for real-time log output
 *  - Stop scan button
 *  - Real-time progress bar
 *  - Severity summary dashboard
 *  - Vulnerability cards with type, severity, url, parameter, description, recommendation
 */
import { useState, useRef, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// All available scan modules
const ALL_MODULES = ['sql', 'xss', 'cmd', 'lfi', 'redirect', 'headers', 'cookies', 'csrf'];

/** Returns the CSS class matching a severity string */
function severityClass(sev = '') {
  const s = sev.toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high')     return 'high';
  if (s === 'medium')   return 'medium';
  if (s === 'low')      return 'low';
  return 'info';
}

/** Small severity badge component */
function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severityClass(severity)}`}>{severity || 'Info'}</span>;
}

/** Summary bar showing vulnerability counts by severity */
function SummaryDashboard({ vulns }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  vulns.forEach(v => {
    const k = severityClass(v.severity);
    counts[k] = (counts[k] || 0) + 1;
  });

  return (
    <div className="summary-grid">
      <div className="summary-card total">
        <div className="count">{vulns.length}</div>
        <div className="label">Total</div>
      </div>
      {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
        <div key={sev} className={`summary-card ${sev}`}>
          <div className="count">{counts[sev]}</div>
          <div className="label">{sev}</div>
        </div>
      ))}
    </div>
  );
}

/** A single vulnerability card */
function VulnCard({ vuln }) {
  const [expanded, setExpanded] = useState(false);
  const cls = severityClass(vuln.severity);

  return (
    <div className={`vuln-card ${cls}`} onClick={() => setExpanded(x => !x)} style={{ cursor: 'pointer' }}>
      <div className="vuln-card-header">
        <span className="vuln-type">{vuln.type || vuln.vulnerability_type || 'Unknown'}</span>
        <SeverityBadge severity={vuln.severity} />
      </div>

      <div className="vuln-meta">
        {vuln.url && (
          <div className="vuln-meta-item">
            🔗 URL: <span>{vuln.url}</span>
          </div>
        )}
        {vuln.parameter && (
          <div className="vuln-meta-item">
            📌 Param: <span>{vuln.parameter}</span>
          </div>
        )}
        {vuln.payload && (
          <div className="vuln-meta-item">
            💉 Payload: <span>{vuln.payload}</span>
          </div>
        )}
      </div>

      {/* Expandable description + recommendation */}
      {expanded && (
        <>
          {vuln.description && (
            <div className="vuln-description">📄 {vuln.description}</div>
          )}
          {vuln.recommendation && (
            <div className="vuln-recommendation">💡 {vuln.recommendation}</div>
          )}
        </>
      )}
      {!expanded && (vuln.description || vuln.recommendation) && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
          Click to {expanded ? 'collapse' : 'expand'} details
        </div>
      )}
    </div>
  );
}

export default function Scanner() {
  // Scan configuration state
  const [url, setUrl]             = useState('');
  const [modules, setModules]     = useState(['sql', 'xss', 'headers']);
  const [depth, setDepth]         = useState(2);
  const [maxUrls, setMaxUrls]     = useState(50);
  const [timeout, setTimeout_]    = useState(10);
  const [delay, setDelay]         = useState(0);

  // Runtime state
  const [scanning, setScanning]   = useState(false);
  const [logs, setLogs]           = useState([]);
  const [vulns, setVulns]         = useState([]);
  const [progress, setProgress]   = useState(0);
  const [statusMsg, setStatusMsg] = useState('');
  const [error, setError]         = useState('');

  // Ref to the EventSource so we can close it on Stop
  const esRef    = useRef(null);
  // Ref to the log box so we can auto-scroll
  const logBoxRef = useRef(null);

  // Auto-scroll log box whenever new lines arrive
  useEffect(() => {
    if (logBoxRef.current) {
      logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight;
    }
  }, [logs]);

  /** Toggle a module checkbox */
  function toggleModule(mod) {
    setModules(prev =>
      prev.includes(mod) ? prev.filter(m => m !== mod) : [...prev, mod]
    );
  }

  /** Start the scan – open an SSE stream */
  function startScan() {
    if (!url.trim()) {
      setError('Please enter a target URL.');
      return;
    }
    setError('');
    setLogs([]);
    setVulns([]);
    setProgress(0);
    setStatusMsg('Connecting…');
    setScanning(true);

    // Build query string for the SSE endpoint
    const params = new URLSearchParams({
      url:      url.trim(),
      modules:  modules.join(','),
      depth:    depth,
      max_urls: maxUrls,
      timeout:  timeout,
      delay:    delay,
    });

    const es = new EventSource(`${API}/api/scan?${params}`);
    esRef.current = es;

    // Generic message handler — the server sends JSON blobs
    es.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleSseMessage(msg);
      } catch {
        // Plain text log line
        appendLog(event.data, 'info');
      }
    };

    // Named event handlers (server may emit typed events)
    es.addEventListener('log',   e => handleSseMessage(tryParse(e.data)));
    es.addEventListener('vuln',  e => {
      const v = tryParse(e.data);
      if (v) setVulns(prev => [...prev, v]);
    });
    es.addEventListener('done',  e => {
      const d = tryParse(e.data);
      appendLog(d?.message || 'Scan complete.', 'info');
      setProgress(100);
      setStatusMsg('Scan complete');
      setScanning(false);
      es.close();
    });
    es.addEventListener('error_event', e => {
      const d = tryParse(e.data);
      appendLog(d?.message || 'An error occurred.', 'error');
      setScanning(false);
      es.close();
    });

    es.onerror = () => {
      // SSE connection closed or errored
      if (scanning) {
        setStatusMsg('Connection closed');
      }
      setScanning(false);
      es.close();
    };
  }

  /** Stop a running scan */
  async function stopScan() {
    if (esRef.current) {
      esRef.current.close();
      esRef.current = null;
    }
    try {
      await fetch(`${API}/api/scan/stop`, { method: 'POST' });
    } catch { /* ignore */ }
    setScanning(false);
    setStatusMsg('Scan stopped');
    appendLog('Scan stopped by user.', 'warn');
  }

  /** Handle a parsed SSE message object */
  function handleSseMessage(msg) {
    if (!msg) return;

    // Progress update
    if (typeof msg.progress === 'number') setProgress(msg.progress);

    // Status text
    if (msg.status) setStatusMsg(msg.status);

    // Log line
    if (msg.message) {
      const cls = msg.type === 'vuln' ? 'found'
                : msg.level === 'error' ? 'error'
                : msg.level === 'warn'  ? 'warn'
                : 'info';
      appendLog(msg.message, cls);
    }

    // Vulnerability finding
    if (msg.type === 'vuln' || msg.vulnerability_type) {
      setVulns(prev => [...prev, msg]);
    }

    // Scan completion
    if (msg.type === 'done' || msg.status === 'complete') {
      setProgress(100);
      setScanning(false);
      if (esRef.current) { esRef.current.close(); esRef.current = null; }
    }

    // URLs crawled — rough progress estimate
    if (msg.urls_crawled && msg.max_urls) {
      setProgress(Math.min(95, Math.round((msg.urls_crawled / msg.max_urls) * 100)));
    }
  }

  function appendLog(text, cls = 'info') {
    setLogs(prev => [...prev, { text, cls, id: Date.now() + Math.random() }]);
  }

  function tryParse(str) {
    try { return JSON.parse(str); } catch { return null; }
  }

  return (
    <div>
      <div className="section-header">
        <h2>🔍 Web Vulnerability Scanner</h2>
        <p>Scan websites for common security vulnerabilities in real-time</p>
      </div>

      <div className="scanner-layout">
        {/* ── LEFT: Configuration panel ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card">
            <div className="card-title">⚙️ Scan Configuration</div>

            {error && <div className="alert alert-error">⚠ {error}</div>}

            {/* Target URL */}
            <div className="form-group">
              <label className="form-label">Target URL *</label>
              <input
                className="form-control"
                type="url"
                placeholder="https://example.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                disabled={scanning}
              />
            </div>

            {/* Module checkboxes */}
            <div className="form-group">
              <label className="form-label">Scan Modules</label>
              <div className="checkbox-group">
                {ALL_MODULES.map(mod => (
                  <label
                    key={mod}
                    className={`checkbox-label ${modules.includes(mod) ? 'checked' : ''}`}
                  >
                    <input
                      type="checkbox"
                      checked={modules.includes(mod)}
                      onChange={() => toggleModule(mod)}
                      disabled={scanning}
                    />
                    {mod.toUpperCase()}
                  </label>
                ))}
              </div>
            </div>

            {/* Depth + Max URLs */}
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Crawl Depth</label>
                <input
                  className="form-control"
                  type="number"
                  min={1} max={10}
                  value={depth}
                  onChange={e => setDepth(Number(e.target.value))}
                  disabled={scanning}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Max URLs</label>
                <input
                  className="form-control"
                  type="number"
                  min={1} max={500}
                  value={maxUrls}
                  onChange={e => setMaxUrls(Number(e.target.value))}
                  disabled={scanning}
                />
              </div>
            </div>

            {/* Timeout + Delay */}
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Timeout (s)</label>
                <input
                  className="form-control"
                  type="number"
                  min={1} max={60}
                  value={timeout}
                  onChange={e => setTimeout_(Number(e.target.value))}
                  disabled={scanning}
                />
              </div>
              <div className="form-group">
                <label className="form-label">Delay (s)</label>
                <input
                  className="form-control"
                  type="number"
                  min={0} max={10} step={0.5}
                  value={delay}
                  onChange={e => setDelay(Number(e.target.value))}
                  disabled={scanning}
                />
              </div>
            </div>

            {/* Start / Stop */}
            <div className="flex-row mt-8">
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

          {/* Progress + status */}
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
        </div>

        {/* ── RIGHT: Logs + Findings ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Live log output */}
          <div className="card">
            <div className="flex-between mb-8">
              <div className="card-title" style={{ marginBottom: 0 }}>📟 Live Output</div>
              {logs.length > 0 && (
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => setLogs([])}
                >
                  Clear
                </button>
              )}
            </div>
            <div className="log-box" ref={logBoxRef}>
              {logs.length === 0 ? (
                <span style={{ color: 'var(--text-muted)' }}>
                  Scan logs will appear here…
                </span>
              ) : (
                logs.map(l => (
                  <div key={l.id} className={`log-line ${l.cls}`}>
                    {l.text}
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Vulnerability findings */}
          <div className="card">
            <div className="flex-between mb-8">
              <div className="card-title" style={{ marginBottom: 0 }}>
                🚨 Vulnerabilities Found
              </div>
              {vulns.length > 0 && (
                <span className="badge badge-critical">{vulns.length} found</span>
              )}
            </div>

            {vulns.length > 0 && <SummaryDashboard vulns={vulns} />}

            {vulns.length === 0 ? (
              <div className="empty-state">
                <div className="icon">🛡️</div>
                <p>No vulnerabilities found yet.</p>
                <p style={{ marginTop: 4, fontSize: '0.8rem' }}>
                  Start a scan to detect security issues.
                </p>
              </div>
            ) : (
              <div className="vuln-list">
                {vulns.map((v, i) => <VulnCard key={i} vuln={v} />)}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
