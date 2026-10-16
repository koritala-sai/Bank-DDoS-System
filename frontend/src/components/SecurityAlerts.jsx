import React, { useState, useMemo } from 'react';
import { ShieldAlert, Bell, CheckCircle2, AlertOctagon, RefreshCw, Search, Filter } from 'lucide-react';

export default function SecurityAlerts({ alerts = [], loading, error, onUpdateStatus, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL'); // 'ALL' | 'NEW' | 'ACKNOWLEDGED' | 'RESOLVED'
  const [riskFilter, setRiskFilter] = useState('ALL'); // 'ALL' | 'HIGH' | 'LOW'

  // Filter alerts dynamically based on search term, status, and risk level
  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      const matchesSearch =
        !searchTerm ||
        a.id?.toString().includes(searchTerm) ||
        a.message?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        a.source_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        a.destination_ip?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesStatus =
        statusFilter === 'ALL' ||
        a.status?.toUpperCase() === statusFilter;

      const matchesRisk =
        riskFilter === 'ALL' ||
        a.risk_level?.toUpperCase() === riskFilter;

      return matchesSearch && matchesStatus && matchesRisk;
    });
  }, [alerts, searchTerm, statusFilter, riskFilter]);

  const formatDate = (isoString) => {
    if (!isoString) return '';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Header & Controls */}
      <div className="section-header" style={{ marginBottom: 0 }}>
        <div className="section-title">
          <ShieldAlert size={20} color="var(--accent-rose)" />
          Security Alerts Stream
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span className="section-badge" style={{ background: 'rgba(239, 68, 68, 0.15)', color: '#fca5a5' }}>
            {filteredAlerts.length} Active Stream
          </span>
          {onRefresh && (
            <button
              className="btn-xs"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh Security Alerts Stream"
              style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              <RefreshCw size={12} className={loading ? 'spin' : ''} />
              Sync
            </button>
          )}
        </div>
      </div>

      {/* Filter & Search Controls */}
      <div className="filter-bar">
        <div className="search-box">
          <Search size={15} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search alerts, IPs, message..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="search-input"
          />
        </div>

        <div className="filter-group">
          <Filter size={14} color="var(--text-muted)" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="filter-select"
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
            <option value="RESOLVED">RESOLVED</option>
          </select>
        </div>

        <div className="filter-group">
          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="filter-select"
          >
            <option value="ALL">All Severities</option>
            <option value="HIGH">HIGH Risk</option>
            <option value="LOW">LOW Risk</option>
          </select>
        </div>
      </div>

      {/* States: Loading, Error, Empty, List */}
      {loading && (
        <div className="state-container">
          <Bell size={32} className="spin" color="var(--accent-rose)" />
          <div className="state-title">Loading security alerts stream...</div>
        </div>
      )}

      {error && !loading && (
        <div className="error-banner">
          <AlertOctagon size={18} />
          <div>{error}</div>
        </div>
      )}

      {!loading && !error && filteredAlerts.length === 0 && (
        <div className="state-container">
          <CheckCircle2 size={36} color="var(--accent-emerald)" style={{ opacity: 0.8 }} />
          <div className="state-title">
            {alerts.length === 0 ? 'No Security Alerts' : 'No Matching Alerts'}
          </div>
          <div className="state-desc">
            {alerts.length === 0
              ? 'All system parameters are clear. No threats detected by the ML classifier.'
              : 'Try clearing your search term or adjusting status/risk filters.'}
          </div>
        </div>
      )}

      {!loading && !error && filteredAlerts.length > 0 && (
        <div className="alert-list">
          {filteredAlerts.map((a) => {
            const isHigh = a.risk_level?.toUpperCase() === 'HIGH';
            const statusClass = a.status === 'RESOLVED' ? 'badge-resolved' : a.status === 'ACKNOWLEDGED' ? 'badge-acknowledged' : 'badge-new';

            return (
              <div key={a.id} className={`alert-card ${isHigh ? 'high-risk' : ''}`}>
                <div className="alert-header">
                  <div className="alert-title">
                    <AlertOctagon size={16} color={isHigh ? '#ef4444' : '#f59e0b'} />
                    <span>Alert #{a.id}: {a.alert_type || 'DDoS Detection'}</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem' }}>
                    <span className={`badge ${isHigh ? 'badge-high' : 'badge-low'}`}>
                      {a.risk_level || 'HIGH'}
                    </span>
                    <span className={`badge ${statusClass}`}>
                      {a.status || 'NEW'}
                    </span>
                  </div>
                </div>

                <div className="alert-message">
                  {a.message || 'Security alert triggered by ML network classifier.'}
                </div>

                <div className="alert-footer">
                  <div className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    {a.source_ip || '127.0.0.1'} &rarr; {a.destination_ip || '10.0.0.1'}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span>{formatDate(a.timestamp)}</span>

                    {/* Alert Status Workflow Actions (Calls PATCH /api/alerts/:id) */}
                    {a.status === 'NEW' && onUpdateStatus && (
                      <button
                        className="btn-xs"
                        onClick={() => onUpdateStatus(a.id, 'ACKNOWLEDGED')}
                        title="Mark alert as Acknowledged"
                      >
                        Acknowledge
                      </button>
                    )}
                    {a.status !== 'RESOLVED' && onUpdateStatus && (
                      <button
                        className="btn-xs"
                        onClick={() => onUpdateStatus(a.id, 'RESOLVED')}
                        title="Mark alert as Resolved"
                        style={{ borderColor: 'rgba(16, 185, 129, 0.4)', color: '#6ee7b7' }}
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
