import React from 'react';
import { ShieldAlert, RefreshCw, Server, Database } from 'lucide-react';

export default function Navbar({ health, loading, autoRefresh, setAutoRefresh, onRefresh }) {
  const getStatusClass = (status) => {
    if (status === 'connected') return 'online';
    if (status === 'unavailable') return 'offline';
    return 'degraded';
  };

  return (
    <header className="app-navbar">
      <div className="nav-brand">
        <div className="brand-icon">
          <ShieldAlert size={24} />
        </div>
        <div>
          <div className="brand-title">BankShield DDoS Defense</div>
          <div className="brand-subtitle">AI-Based Intelligent Network Monitoring System</div>
          <div className="brand-disclaimer">
            Academic prototype. Live monitoring is limited to traffic visible on the configured local network interface. Dataset-based tests are separate. Not deployed or validated on a production banking network.
          </div>
        </div>
      </div>

      <div className="nav-actions">
        {/* Backend Status Pill */}
        <div className="status-pill" title="Flask REST API Connection">
          <Server size={14} color="#94a3b8" />
          <span>Backend:</span>
          <div className={`status-dot ${health.backend === 'online' ? 'online' : 'offline'}`} />
          <span>{health.backend === 'online' ? 'Connected' : 'Disconnected'}</span>
        </div>

        {/* Database Status Pill */}
        <div className="status-pill" title="MySQL Relational Database Connection">
          <Database size={14} color="#94a3b8" />
          <span>DB:</span>
          <div className={`status-dot ${getStatusClass(health.database)}`} />
          <span style={{ textTransform: 'capitalize' }}>{health.database || 'Checking'}</span>
        </div>

        {/* Auto Refresh Toggle */}
        <label className="auto-refresh-toggle">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={(e) => setAutoRefresh(e.target.checked)}
          />
          <span>Auto-sync (10s)</span>
        </label>

        {/* Manual Refresh Button */}
        <button
          className="btn-action"
          onClick={onRefresh}
          disabled={loading}
          title="Sync Telemetry from Backend"
        >
          <RefreshCw size={15} className={loading ? 'spin' : ''} />
          <span>{loading ? 'Syncing...' : 'Refresh'}</span>
        </button>
      </div>
    </header>
  );
}
