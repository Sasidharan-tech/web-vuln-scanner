/**
 * ProxyInterceptor.jsx
 * HTTP Proxy management UI.
 *
 * Features:
 *  - Start / stop the mitmproxy-based proxy
 *  - View proxy status and download CA certificate
 *  - Browse captured HTTP request history with filtering
 *  - Inspect request detail (headers + body)
 *  - Replay requests
 *  - Forward captured requests to the scanner
 *  - Clear history
 */
import { useState, useEffect, useCallback } from 'react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/** Show a coloured badge for HTTP methods */
function MethodBadge({ method = 'GET' }) {
  const cls = `method-badge method-${method.toLowerCase()}`;
  return <span className={cls}>{method}</span>;
}

/** Show a coloured HTTP status code */
function StatusCode({ code }) {
  if (!code) return <span className="text-muted">—</span>;
  const cls = code >= 500 ? 'status-5xx'
            : code >= 400 ? 'status-4xx'
            : code >= 300 ? 'status-3xx'
            : 'status-2xx';
  return <span className={`status-badge ${cls}`}>{code}</span>;
}

/** Format a headers object (or dict string) for display */
function formatHeaders(headers) {
  if (!headers) return '(none)';
  if (typeof headers === 'string') return headers;
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');
}

export default function ProxyInterceptor() {
  // Proxy status
  const [proxyStatus, setProxyStatus] = useState(null); // {running, port}
  const [proxyLoading, setProxyLoading] = useState(false);
  const [proxyPort, setProxyPort]       = useState(8080);

  // Request history
  const [requests, setRequests]           = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [hostFilter, setHostFilter]       = useState('');
  const [selectedReq, setSelectedReq]     = useState(null); // full detail object

  // Replay form
  const [replayResult, setReplayResult] = useState(null);
  const [replayLoading, setReplayLoading] = useState(false);

  // Scan-from-proxy result
  const [scanMsg, setScanMsg] = useState('');

  const [error, setError] = useState('');

  // ── Fetch proxy status on mount and periodically ──────────────────────────
  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  async function fetchStatus() {
    try {
      const res = await fetch(`${API}/api/proxy/status`);
      if (res.ok) setProxyStatus(await res.json());
    } catch { /* server might be offline */ }
  }

  // ── Fetch history whenever host filter changes ─────────────────────────────
  useEffect(() => {
    fetchHistory();
  }, [hostFilter]);

  const fetchHistory = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const params = new URLSearchParams({ limit: 200 });
      if (hostFilter.trim()) params.set('host', hostFilter.trim());
      const res = await fetch(`${API}/api/proxy/history?${params}`);
      if (res.ok) {
        const data = await res.json();
        setRequests(Array.isArray(data) ? data : data.requests || []);
      }
    } catch { /* ignore */ } finally {
      setHistoryLoading(false);
    }
  }, [hostFilter]);

  // ── Proxy control ──────────────────────────────────────────────────────────
  async function startProxy() {
    setProxyLoading(true);
    setError('');
    try {
      const res = await fetch(`${API}/api/proxy/start?port=${proxyPort}`, { method: 'POST' });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to start proxy');
      await fetchStatus();
    } catch (err) {
      setError(err.message);
    } finally {
      setProxyLoading(false);
    }
  }

  async function stopProxy() {
    setProxyLoading(true);
    try {
      await fetch(`${API}/api/proxy/stop`, { method: 'POST' });
      await fetchStatus();
    } catch { /* ignore */ } finally {
      setProxyLoading(false);
    }
  }

  // ── Request detail ─────────────────────────────────────────────────────────
  async function loadDetail(req) {
    setSelectedReq(null);
    setReplayResult(null);
    setScanMsg('');
    try {
      const res = await fetch(`${API}/api/proxy/request/${req.id}`);
      if (res.ok) setSelectedReq(await res.json());
      else setSelectedReq(req); // fall back to summary data
    } catch {
      setSelectedReq(req);
    }
  }

  // ── Replay ────────────────────────────────────────────────────────────────
  async function replayRequest() {
    if (!selectedReq) return;
    setReplayLoading(true);
    setReplayResult(null);
    try {
      const res = await fetch(`${API}/api/proxy/replay`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          method:  selectedReq.method,
          url:     selectedReq.url || `${selectedReq.scheme || 'http'}://${selectedReq.host}${selectedReq.path}`,
          headers: selectedReq.request_headers || selectedReq.headers || {},
          body:    selectedReq.request_body || selectedReq.body || '',
        }),
      });
      setReplayResult(await res.json());
    } catch (err) {
      setReplayResult({ error: err.message });
    } finally {
      setReplayLoading(false);
    }
  }

  // ── Scan captured request ─────────────────────────────────────────────────
  async function scanRequest() {
    if (!selectedReq) return;
    setScanMsg('');
    try {
      const res = await fetch(`${API}/api/proxy/scan/${selectedReq.id}`, { method: 'POST' });
      const data = await res.json();
      setScanMsg(data.message || 'Scan initiated!');
    } catch (err) {
      setScanMsg(`Error: ${err.message}`);
    }
  }

  // ── Clear history ─────────────────────────────────────────────────────────
  async function clearHistory() {
    if (!window.confirm('Clear all proxy history?')) return;
    await fetch(`${API}/api/proxy/history`, { method: 'DELETE' });
    setRequests([]);
    setSelectedReq(null);
  }

  const isRunning = proxyStatus?.running;

  return (
    <div>
      <div className="section-header">
        <h2>🕵️ Proxy Interceptor</h2>
        <p>Capture, inspect, replay, and scan HTTP traffic through a local proxy</p>
      </div>

      {error && <div className="alert alert-error mb-12">⚠ {error}</div>}

      {/* ── Proxy control bar ── */}
      <div className="card mb-16">
        <div className="flex-between">
          <div className="flex-row">
            {/* Status indicator */}
            <span className={`status-dot ${isRunning ? 'online' : 'offline'}`} />
            <span style={{ fontWeight: 600 }}>
              {isRunning ? `Proxy running on port ${proxyStatus?.port || proxyPort}` : 'Proxy stopped'}
            </span>
          </div>

          <div className="flex-row">
            {/* Port input */}
            {!isRunning && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <label className="form-label" style={{ marginBottom: 0, whiteSpace: 'nowrap' }}>
                  Port:
                </label>
                <input
                  className="form-control"
                  type="number"
                  min={1024} max={65535}
                  value={proxyPort}
                  onChange={e => setProxyPort(Number(e.target.value))}
                  style={{ width: 90 }}
                />
              </div>
            )}

            {!isRunning ? (
              <button className="btn btn-success" onClick={startProxy} disabled={proxyLoading}>
                {proxyLoading ? <span className="spinner" /> : '▶'} Start Proxy
              </button>
            ) : (
              <button className="btn btn-danger" onClick={stopProxy} disabled={proxyLoading}>
                {proxyLoading ? <span className="spinner" /> : '⏹'} Stop Proxy
              </button>
            )}

            {/* Download CA cert */}
            <a
              className="btn btn-outline"
              href={`${API}/api/proxy/cert`}
              download="mitmproxy-ca-cert.pem"
              title="Download mitmproxy CA certificate to intercept HTTPS"
            >
              🔒 Download CA Cert
            </a>
          </div>
        </div>

        {isRunning && (
          <div className="alert alert-info mt-12" style={{ marginBottom: 0 }}>
            Configure your browser to use <strong>HTTP proxy 127.0.0.1:{proxyStatus?.port || proxyPort}</strong>.
            Install the CA certificate to intercept HTTPS traffic.
          </div>
        )}
      </div>

      <div className="proxy-layout">
        {/* ── LEFT: Request history table ── */}
        <div>
          <div className="card" style={{ padding: 0 }}>
            {/* History toolbar */}
            <div className="flex-between" style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <span className="card-title" style={{ marginBottom: 0 }}>📋 Request History</span>
              <div className="flex-row gap-8">
                <input
                  className="form-control"
                  type="text"
                  placeholder="Filter by host…"
                  value={hostFilter}
                  onChange={e => setHostFilter(e.target.value)}
                  style={{ width: 160 }}
                />
                <button className="btn btn-outline btn-sm" onClick={fetchHistory}>
                  🔄 Refresh
                </button>
                <button className="btn btn-danger btn-sm" onClick={clearHistory}>
                  🗑 Clear
                </button>
              </div>
            </div>

            {historyLoading ? (
              <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)' }}>
                <span className="spinner" /> Loading…
              </div>
            ) : requests.length === 0 ? (
              <div className="empty-state">
                <div className="icon">📭</div>
                <p>No requests captured yet.</p>
                <p style={{ fontSize: '0.8rem', marginTop: 4 }}>
                  Start the proxy and browse the web.
                </p>
              </div>
            ) : (
              <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Method</th>
                      <th>Host</th>
                      <th>Path</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {requests.map(req => (
                      <tr
                        key={req.id}
                        onClick={() => loadDetail(req)}
                        className={selectedReq?.id === req.id ? 'selected' : ''}
                      >
                        <td className="td-mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          {req.id}
                        </td>
                        <td><MethodBadge method={req.method} /></td>
                        <td className="td-mono" style={{ maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {req.host}
                        </td>
                        <td className="td-mono" style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)' }}>
                          {req.path}
                        </td>
                        <td><StatusCode code={req.status_code} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* ── RIGHT: Request detail panel ── */}
        <div>
          {!selectedReq ? (
            <div className="card">
              <div className="empty-state">
                <div className="icon">👈</div>
                <p>Select a request to inspect it.</p>
              </div>
            </div>
          ) : (
            <div className="card">
              {/* Header row with method + URL */}
              <div className="flex-between mb-12">
                <div className="flex-row gap-8" style={{ flexWrap: 'nowrap', overflow: 'hidden' }}>
                  <MethodBadge method={selectedReq.method} />
                  <span
                    className="td-mono"
                    style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 300 }}
                    title={selectedReq.url || `${selectedReq.host}${selectedReq.path}`}
                  >
                    {selectedReq.url || `${selectedReq.host}${selectedReq.path}`}
                  </span>
                  <StatusCode code={selectedReq.status_code} />
                </div>

                {/* Action buttons */}
                <div className="flex-row gap-8">
                  <button className="btn btn-outline btn-sm" onClick={replayRequest} disabled={replayLoading}>
                    {replayLoading ? <span className="spinner" /> : '🔁'} Replay
                  </button>
                  <button className="btn btn-warning btn-sm" onClick={scanRequest}>
                    🔍 Scan
                  </button>
                </div>
              </div>

              {scanMsg && (
                <div className="alert alert-info mb-12" style={{ marginBottom: 8 }}>
                  {scanMsg}
                </div>
              )}

              {/* Request headers */}
              <div className="detail-panel">
                <h4>Request Headers</h4>
                <div className="headers-block">
                  {formatHeaders(selectedReq.request_headers || selectedReq.headers)}
                </div>

                {(selectedReq.request_body || selectedReq.body) && (
                  <>
                    <h4>Request Body</h4>
                    <div className="body-block">
                      {selectedReq.request_body || selectedReq.body}
                    </div>
                  </>
                )}

                {selectedReq.response_headers && (
                  <>
                    <h4>Response Headers</h4>
                    <div className="headers-block">
                      {formatHeaders(selectedReq.response_headers)}
                    </div>
                  </>
                )}

                {selectedReq.response_body && (
                  <>
                    <h4>Response Body</h4>
                    <div className="body-block">
                      {selectedReq.response_body}
                    </div>
                  </>
                )}
              </div>

              {/* Replay result */}
              {replayResult && (
                <div style={{ marginTop: 12 }}>
                  <div className="card-title" style={{ fontSize: '0.85rem' }}>🔁 Replay Response</div>
                  <div className="detail-panel">
                    <h4>Status: {replayResult.status_code || replayResult.error || 'Unknown'}</h4>
                    {replayResult.headers && (
                      <>
                        <h4>Headers</h4>
                        <div className="headers-block">{formatHeaders(replayResult.headers)}</div>
                      </>
                    )}
                    {replayResult.body && (
                      <>
                        <h4>Body</h4>
                        <div className="body-block">{replayResult.body}</div>
                      </>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
