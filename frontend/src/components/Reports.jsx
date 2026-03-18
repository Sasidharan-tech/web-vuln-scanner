/**
 * Reports.jsx
 * Scan history and PDF report management.
 *
 * Requires the user to be logged in (Bearer token in localStorage).
 * Features:
 *  - List past scans with target URL, date, vuln counts
 *  - Click a scan to view detailed findings
 *  - Download PDF report
 *  - Delete a scan record
 */
import { useState, useEffect } from 'react';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

/** Returns the CSS class matching a severity string */
function severityClass(sev = '') {
  const s = sev.toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high')     return 'high';
  if (s === 'medium')   return 'medium';
  if (s === 'low')      return 'low';
  return 'info';
}

/** Severity badge */
function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severityClass(severity)}`}>{severity || 'Info'}</span>;
}

/** Format an ISO timestamp to a readable local string */
function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

/** Get auth header object for fetch calls */
function authHeaders() {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export default function Reports({ isLoggedIn }) {
  // History list
  const [history, setHistory]       = useState([]);
  const [loading, setLoading]       = useState(false);
  const [page, setPage]             = useState(1);
  const [hasMore, setHasMore]       = useState(false);

  // Selected scan detail
  const [detail, setDetail]         = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // PDF generation
  const [pdfLoading, setPdfLoading] = useState(null); // scan_id being generated

  const [error, setError] = useState('');

  // Load history when logged in or page changes
  useEffect(() => {
    if (isLoggedIn) fetchHistory(page);
  }, [isLoggedIn, page]);

  async function fetchHistory(p = 1) {
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${API}/api/history?page=${p}&per_page=20`, {
        headers: authHeaders(),
      });
      if (res.status === 401) throw new Error('Please log in to view scan history.');
      if (!res.ok) throw new Error('Failed to load history');
      const data = await res.json();
      const items = Array.isArray(data) ? data : data.items || data.results || [];
      setHistory(items);
      // Detect if there are more pages by checking if we got a full page
      setHasMore(items.length === 20);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadDetail(scanId) {
    setDetail(null);
    setDetailLoading(true);
    try {
      const res = await fetch(`${API}/api/history/${scanId}`, {
        headers: authHeaders(),
      });
      if (res.ok) setDetail(await res.json());
    } catch { /* ignore */ } finally {
      setDetailLoading(false);
    }
  }

  async function deleteScan(scanId) {
    if (!window.confirm('Delete this scan record?')) return;
    try {
      await fetch(`${API}/api/history/${scanId}`, {
        method: 'DELETE',
        headers: authHeaders(),
      });
      setHistory(prev => prev.filter(h => h.id !== scanId));
      if (detail?.id === scanId) setDetail(null);
    } catch (err) {
      setError(err.message);
    }
  }

  async function downloadPdf(scanId) {
    setPdfLoading(scanId);
    try {
      const res = await fetch(`${API}/api/report/pdf?scan_id=${scanId}`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error('PDF generation failed');
      // Download the file
      const blob = await res.blob();
      const url  = window.URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `scan-report-${scanId}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.message);
    } finally {
      setPdfLoading(null);
    }
  }

  // ── Not logged in ─────────────────────────────────────────────────────────
  if (!isLoggedIn) {
    return (
      <div>
        <div className="section-header">
          <h2>📊 Reports & History</h2>
        </div>
        <div className="card">
          <div className="empty-state">
            <div className="icon">🔒</div>
            <p>Please <strong>log in</strong> to view your scan history and download reports.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="section-header">
        <h2>📊 Reports & History</h2>
        <p>View past scans, inspect findings, and download PDF reports</p>
      </div>

      {error && <div className="alert alert-error mb-16">⚠ {error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20 }}>
        {/* ── LEFT: History list ── */}
        <div className="card" style={{ padding: 0 }}>
          <div
            className="flex-between"
            style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)' }}
          >
            <span className="card-title" style={{ marginBottom: 0 }}>🗂 Scan History</span>
            <button
              className="btn btn-outline btn-sm"
              onClick={() => fetchHistory(page)}
              disabled={loading}
            >
              🔄 Refresh
            </button>
          </div>

          {loading ? (
            <div style={{ padding: 24, textAlign: 'center' }}>
              <span className="spinner" /> Loading…
            </div>
          ) : history.length === 0 ? (
            <div className="empty-state">
              <div className="icon">📭</div>
              <p>No scans recorded yet.</p>
              <p style={{ fontSize: '0.8rem', marginTop: 4 }}>
                Run a scan on the Scanner tab to see results here.
              </p>
            </div>
          ) : (
            <>
              <div className="table-wrapper" style={{ border: 'none', borderRadius: 0 }}>
                <table>
                  <thead>
                    <tr>
                      <th>Target URL</th>
                      <th>Date</th>
                      <th>Vulns</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map(h => (
                      <tr
                        key={h.id}
                        onClick={() => loadDetail(h.id)}
                        className={detail?.id === h.id ? 'selected' : ''}
                      >
                        <td
                          className="td-mono"
                          style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                          title={h.target_url}
                        >
                          {h.target_url}
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                          {formatDate(h.created_at || h.date || h.timestamp)}
                        </td>
                        <td>
                          {h.vulnerability_count !== undefined
                            ? <span className={`badge badge-${h.vulnerability_count > 0 ? 'high' : 'info'}`}>
                                {h.vulnerability_count}
                              </span>
                            : '—'}
                        </td>
                        <td onClick={e => e.stopPropagation()}>
                          <div className="flex-row gap-8">
                            <button
                              className="btn btn-outline btn-sm"
                              onClick={() => downloadPdf(h.id)}
                              disabled={pdfLoading === h.id}
                              title="Download PDF Report"
                            >
                              {pdfLoading === h.id ? <span className="spinner" /> : '📄'}
                            </button>
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => deleteScan(h.id)}
                              title="Delete"
                            >
                              🗑
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              <div className="flex-between" style={{ padding: '10px 16px', borderTop: '1px solid var(--border)' }}>
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                >
                  ← Prev
                </button>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>Page {page}</span>
                <button
                  className="btn btn-outline btn-sm"
                  onClick={() => setPage(p => p + 1)}
                  disabled={!hasMore}
                >
                  Next →
                </button>
              </div>
            </>
          )}
        </div>

        {/* ── RIGHT: Scan detail ── */}
        <div className="card">
          {detailLoading ? (
            <div style={{ padding: 24, textAlign: 'center' }}>
              <span className="spinner" /> Loading detail…
            </div>
          ) : !detail ? (
            <div className="empty-state">
              <div className="icon">👈</div>
              <p>Select a scan from the list to view details.</p>
            </div>
          ) : (
            <>
              <div className="flex-between mb-16">
                <div className="card-title" style={{ marginBottom: 0 }}>
                  🔍 Scan Detail
                </div>
                <button
                  className="btn btn-primary btn-sm"
                  onClick={() => downloadPdf(detail.id)}
                  disabled={pdfLoading === detail.id}
                >
                  {pdfLoading === detail.id
                    ? <><span className="spinner" /> Generating…</>
                    : '📄 Download PDF'}
                </button>
              </div>

              {/* Metadata */}
              <div style={{ marginBottom: 16 }}>
                <div className="vuln-meta" style={{ gridTemplateColumns: '1fr 1fr' }}>
                  <div className="vuln-meta-item">🔗 Target: <span>{detail.target_url}</span></div>
                  <div className="vuln-meta-item">📅 Date: <span>{formatDate(detail.created_at || detail.date)}</span></div>
                  <div className="vuln-meta-item">⏱ Duration: <span>{detail.scan_duration ? `${detail.scan_duration}s` : '—'}</span></div>
                  <div className="vuln-meta-item">🔗 URLs crawled: <span>{detail.urls_crawled ?? '—'}</span></div>
                  <div className="vuln-meta-item">📋 Forms: <span>{detail.forms_found ?? '—'}</span></div>
                  <div className="vuln-meta-item">🧩 Modules: <span>{Array.isArray(detail.modules_used) ? detail.modules_used.join(', ') : (detail.modules_used || '—')}</span></div>
                </div>
              </div>

              <hr className="divider" />

              {/* Vulnerability summary */}
              {detail.vulnerabilities && detail.vulnerabilities.length > 0 ? (
                <>
                  <div className="card-title" style={{ fontSize: '0.9rem' }}>
                    🚨 Vulnerabilities ({detail.vulnerabilities.length})
                  </div>
                  {/* Severity mini-summary */}
                  <div className="summary-grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', marginBottom: 12 }}>
                    {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
                      const cnt = detail.vulnerabilities.filter(
                        v => severityClass(v.severity) === sev
                      ).length;
                      if (cnt === 0) return null;
                      return (
                        <div key={sev} className={`summary-card ${sev}`} style={{ padding: '10px 8px' }}>
                          <div className="count" style={{ fontSize: '1.4rem' }}>{cnt}</div>
                          <div className="label">{sev}</div>
                        </div>
                      );
                    })}
                  </div>

                  {/* Individual vuln entries */}
                  <div className="vuln-list" style={{ maxHeight: 380, overflowY: 'auto' }}>
                    {detail.vulnerabilities.map((v, i) => (
                      <div key={i} className={`vuln-card ${severityClass(v.severity)}`}>
                        <div className="vuln-card-header">
                          <span className="vuln-type">{v.type || v.vulnerability_type || 'Unknown'}</span>
                          <SeverityBadge severity={v.severity} />
                        </div>
                        <div className="vuln-meta">
                          {v.url       && <div className="vuln-meta-item">🔗 <span>{v.url}</span></div>}
                          {v.parameter && <div className="vuln-meta-item">📌 Param: <span>{v.parameter}</span></div>}
                        </div>
                        {v.description && (
                          <div className="vuln-description">{v.description}</div>
                        )}
                        {v.recommendation && (
                          <div className="vuln-recommendation">💡 {v.recommendation}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div className="empty-state" style={{ padding: 24 }}>
                  <div className="icon">✅</div>
                  <p>No vulnerabilities recorded for this scan.</p>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
