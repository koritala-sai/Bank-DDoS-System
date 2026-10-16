import React, { useState, useMemo } from 'react';
import { Activity, ShieldAlert, CheckCircle2, AlertTriangle, Layers, Clock, Search, RefreshCw, Filter, Wifi, FlaskConical } from 'lucide-react';

export default function TrafficHistoryTable({ records = [], loading, error, onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [predictionFilter, setPredictionFilter] = useState('ALL'); // 'ALL' | 'NORMAL' | 'DDOS'
  const [riskFilter, setRiskFilter] = useState('ALL'); // 'ALL' | 'HIGH' | 'LOW'
  const [sourceFilter, setSourceFilter] = useState('ALL'); // 'ALL' | 'LIVE' | 'SAMPLE' | 'UNLABELED'
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Helper to determine traffic source provenance from record fields/metadata without guessing
  const getTrafficSource = (record) => {
    const rawSource = record.source_type || record.traffic_source || record.origin || record.source_label;
    if (rawSource) {
      const s = String(rawSource).toLowerCase();
      if (s.includes('live') || s.includes('wifi') || s.includes('wi-fi')) {
        return {
          label: 'Live Wi-Fi Capture',
          type: 'live',
          className: 'badge-live',
          title: 'Captured live from local Wi-Fi interface'
        };
      }
      if (s.includes('sample') || s.includes('dataset') || s.includes('test') || s.includes('benchmark')) {
        return {
          label: 'Sample / Dataset Test',
          type: 'sample',
          className: 'badge-sample',
          title: 'Benchmark dataset or simulated test sample'
        };
      }
    }

    // Current backend limitation: legacy TrafficRecord schema does not include a source_type column
    return {
      label: 'Unlabeled (Legacy DB)',
      type: 'unlabeled',
      className: 'badge-unspecified',
      title: 'Source provenance not recorded in database schema'
    };
  };

  // Filter records dynamically based on search term, prediction, risk level, and source
  const filteredRecords = useMemo(() => {
    return records.filter((r) => {
      const matchesSearch =
        !searchTerm ||
        r.id?.toString().includes(searchTerm) ||
        r.source_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.destination_ip?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.protocol?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesPrediction =
        predictionFilter === 'ALL' ||
        r.prediction?.toUpperCase() === predictionFilter;

      const matchesRisk =
        riskFilter === 'ALL' ||
        r.risk_level?.toUpperCase() === riskFilter;

      const sourceInfo = getTrafficSource(r);
      const matchesSource =
        sourceFilter === 'ALL' ||
        (sourceFilter === 'LIVE' && sourceInfo.type === 'live') ||
        (sourceFilter === 'SAMPLE' && sourceInfo.type === 'sample') ||
        (sourceFilter === 'UNLABELED' && sourceInfo.type === 'unlabeled');

      return matchesSearch && matchesPrediction && matchesRisk && matchesSource;
    });
  }, [records, searchTerm, predictionFilter, riskFilter, sourceFilter]);

  // Calculate pagination bounds
  const totalPages = Math.ceil(filteredRecords.length / pageSize) || 1;
  const paginatedRecords = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredRecords.slice(start, start + pageSize);
  }, [filteredRecords, currentPage, pageSize]);

  const formatDate = (isoString) => {
    if (!isoString) return 'N/A';
    try {
      const date = new Date(isoString);
      return date.toLocaleString([], {
        year: 'numeric',
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Header & Controls */}
      <div className="section-header" style={{ marginBottom: 0 }}>
        <div className="section-title">
          <Activity size={20} color="var(--accent-cyan)" />
          Network Traffic Logs
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span className="section-badge">
            Showing {filteredRecords.length} of {records.length} Records
          </span>
          {onRefresh && (
            <button
              className="btn-xs"
              onClick={onRefresh}
              disabled={loading}
              title="Refresh Traffic History"
              style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}
            >
              <RefreshCw size={12} className={loading ? 'spin' : ''} />
              Sync
            </button>
          )}
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="filter-bar">
        {/* Search Input */}
        <div className="search-box">
          <Search size={15} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search by IP, ID, protocol..."
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="search-input"
          />
        </div>

        {/* Traffic Source Filter */}
        <div className="filter-group">
          <Filter size={14} color="var(--text-muted)" />
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="filter-select"
          >
            <option value="ALL">All Sources</option>
            <option value="LIVE">Live Wi-Fi Capture</option>
            <option value="SAMPLE">Sample / Dataset Test</option>
            <option value="UNLABELED">Unlabeled (Legacy DB)</option>
          </select>
        </div>

        {/* Prediction Filter */}
        <div className="filter-group">
          <select
            value={predictionFilter}
            onChange={(e) => {
              setPredictionFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="filter-select"
          >
            <option value="ALL">All Predictions</option>
            <option value="NORMAL">Normal Traffic</option>
            <option value="DDOS">DDoS Threat</option>
          </select>
        </div>

        {/* Risk Filter */}
        <div className="filter-group">
          <select
            value={riskFilter}
            onChange={(e) => {
              setRiskFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="filter-select"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="HIGH">HIGH Risk</option>
            <option value="LOW">LOW Risk</option>
          </select>
        </div>

        {/* Page Size */}
        <div className="filter-group">
          <select
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setCurrentPage(1);
            }}
            className="filter-select"
          >
            <option value={10}>10 / page</option>
            <option value={25}>25 / page</option>
            <option value={50}>50 / page</option>
          </select>
        </div>
      </div>

      {/* States: Loading, Error, Empty, Table */}
      {loading && (
        <div className="state-container">
          <Layers size={36} className="spin" color="var(--accent-cyan)" />
          <div className="state-title">Fetching network traffic history...</div>
        </div>
      )}

      {error && !loading && (
        <div className="error-banner">
          <AlertTriangle size={20} />
          <div>
            <strong>Failed to retrieve traffic history:</strong> {error}
          </div>
        </div>
      )}

      {!loading && !error && filteredRecords.length === 0 && (
        <div className="state-container">
          <Clock size={36} />
          <div className="state-title">
            {records.length === 0 ? 'No Traffic Records Found' : 'No Matching Records'}
          </div>
          <div className="state-desc">
            {records.length === 0
              ? 'No network traffic records found. Run a live capture session on your local network interface or evaluate sample flows in the Sample Flow ML Analyzer.'
              : 'Try clearing your search term or adjusting prediction, risk, or source filters.'}
          </div>
        </div>
      )}

      {!loading && !error && paginatedRecords.length > 0 && (
        <>
          <div className="table-container">
            <table className="custom-table">
              <thead>
                <tr>
                  <th>Record ID</th>
                  <th>Traffic Source</th>
                  <th>Timestamp</th>
                  <th>Source IP:Port</th>
                  <th>Destination IP:Port</th>
                  <th>Protocol</th>
                  <th>Packets</th>
                  <th>Duration (s)</th>
                  <th>ML Prediction</th>
                  <th>Risk Level</th>
                </tr>
              </thead>
              <tbody>
                {paginatedRecords.map((r) => {
                  const isDdos = r.prediction?.toLowerCase() === 'ddos';
                  const isHigh = r.risk_level?.toUpperCase() === 'HIGH';
                  const sourceInfo = getTrafficSource(r);

                  return (
                    <tr key={r.id}>
                      <td className="font-mono" style={{ color: 'var(--text-muted)' }}>#{r.id}</td>
                      <td>
                        <span className={`badge ${sourceInfo.className}`} title={sourceInfo.title}>
                          {sourceInfo.type === 'live' && <Wifi size={11} />}
                          {sourceInfo.type === 'sample' && <FlaskConical size={11} />}
                          {sourceInfo.type === 'unlabeled' && <Layers size={11} />}
                          {sourceInfo.label}
                        </span>
                      </td>
                      <td className="font-mono">{formatDate(r.timestamp)}</td>
                      <td className="font-mono">
                        {r.source_ip}{r.source_port ? `:${r.source_port}` : ''}
                      </td>
                      <td className="font-mono">
                        {r.destination_ip}{r.destination_port ? `:${r.destination_port}` : ''}
                      </td>
                      <td>
                        <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)' }}>
                          {r.protocol || 'TCP'}
                        </span>
                      </td>
                      <td className="font-mono">{r.packet_count ?? 'N/A'}</td>
                      <td className="font-mono">{r.flow_duration !== null && r.flow_duration !== undefined ? Number(r.flow_duration).toFixed(2) : 'N/A'}</td>
                      <td>
                        {/* Explicit ML Prediction Label (Distinguishes ML Inference from Confirmed Attack) */}
                        <span className={`badge ${isDdos ? 'badge-ddos' : 'badge-normal'}`} title="DecisionTree Model Output">
                          {isDdos ? <ShieldAlert size={12} /> : <CheckCircle2 size={12} />}
                          ML Pred: {r.prediction || 'Unknown'}
                        </span>
                      </td>
                      <td>
                        <span className={`badge ${isHigh ? 'badge-high' : 'badge-low'}`}>
                          {r.risk_level || 'LOW'}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination Navigation */}
          {totalPages > 1 && (
            <div className="pagination-bar">
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                Page {currentPage} of {totalPages}
              </span>
              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button
                  className="btn-xs"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </button>
                <button
                  className="btn-xs"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
