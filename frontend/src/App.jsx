/**
 * App.jsx
 * Root application component.
 *
 * Provides:
 *  - Top navigation bar with tab switching
 *  - Auth state management (login / logout)
 *  - Auth modal trigger
 *  - Routes to Scanner, ProxyInterceptor, Reports, GitHubScanner tabs
 */
import { useState, useEffect } from 'react';
import './App.css';

import Scanner          from './components/Scanner';
import ProxyInterceptor from './components/ProxyInterceptor';
import Reports          from './components/Reports';
import GitHubScanner    from './components/GitHubScanner';
import AuthModal        from './components/AuthModal';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Tab definitions — label shown in nav + icon emoji
const TABS = [
  { id: 'scanner',  label: 'Scanner',       icon: '🔍' },
  { id: 'proxy',    label: 'Proxy',          icon: '🕵️' },
  { id: 'reports',  label: 'Reports',        icon: '📊' },
  { id: 'github',   label: 'GitHub Scanner', icon: '🐙' },
];

export default function App() {
  // Active tab key
  const [activeTab, setActiveTab] = useState('scanner');

  // Auth state — read initial values from localStorage
  const [username, setUsername]           = useState(() => localStorage.getItem('username') || '');
  const [showAuthModal, setShowAuthModal] = useState(false);

  // Backend health indicator
  const [backendOk, setBackendOk] = useState(null); // null=unknown, true/false

  // Check backend health on mount
  useEffect(() => {
    fetch(`${API}/api/health`)
      .then(r => setBackendOk(r.ok))
      .catch(() => setBackendOk(false));
  }, []);

  /** Called by AuthModal after a successful login */
  function handleLogin(user) {
    setUsername(user);
  }

  /** Log out: clear storage and optionally call the backend */
  function handleLogout() {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setUsername('');
    fetch(`${API}/auth/logout`, { method: 'POST' }).catch(() => {});
  }

  const isLoggedIn = Boolean(username);

  return (
    <div className="app">
      {/* ── Top navigation bar ── */}
      <nav className="navbar">
        {/* Brand / logo */}
        <div className="navbar-brand">
          <span className="shield-icon">🛡️</span>
          <span>WebVulnScanner</span>
          {/* Backend health status dot */}
          <span
            className={`status-dot ${backendOk === null ? '' : backendOk ? 'online' : 'offline'}`}
            title={
              backendOk === null ? 'Checking backend…'
              : backendOk ? 'Backend online'
              : 'Backend offline'
            }
            style={{ marginLeft: 4 }}
          />
        </div>

        {/* Tab buttons */}
        <div className="navbar-tabs">
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`nav-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Login / user badge */}
        <div className="navbar-auth">
          {isLoggedIn ? (
            <>
              <div className="user-badge">
                <span>👤</span>
                <span>{username}</span>
              </div>
              <button className="btn btn-outline btn-sm" onClick={handleLogout}>
                Logout
              </button>
            </>
          ) : (
            <button
              className="btn btn-primary btn-sm"
              onClick={() => setShowAuthModal(true)}
            >
              🔑 Login
            </button>
          )}
        </div>
      </nav>

      {/* ── Backend offline banner ── */}
      {backendOk === false && (
        <div
          style={{
            background: 'rgba(220,53,69,0.15)',
            borderBottom: '1px solid #dc3545',
            padding: '8px 24px',
            fontSize: '0.85rem',
            color: '#f87171',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          ⚠️ Cannot reach the backend at <strong>{API}</strong>.
          Make sure the FastAPI server is running.
        </div>
      )}

      {/* ── Main content area — renders the active tab ── */}
      <main className="main-content">
        {activeTab === 'scanner' && <Scanner />}
        {activeTab === 'proxy'   && <ProxyInterceptor />}
        {activeTab === 'reports' && <Reports isLoggedIn={isLoggedIn} />}
        {activeTab === 'github'  && <GitHubScanner />}
      </main>

      {/* ── Login / Register modal ── */}
      {showAuthModal && (
        <AuthModal
          onClose={() => setShowAuthModal(false)}
          onLogin={handleLogin}
        />
      )}

      {/* ── Footer ── */}
      <footer
        style={{
          borderTop: '1px solid var(--border)',
          padding: '12px 24px',
          textAlign: 'center',
          fontSize: '0.78rem',
          color: 'var(--text-muted)',
        }}
      >
        🛡️ Web Vulnerability Scanner — For authorized testing only. Use responsibly.
      </footer>
    </div>
  );
}
