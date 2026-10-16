import React from 'react';
import { Activity, ShieldAlert, CheckCircle2, AlertTriangle, Bell, Database } from 'lucide-react';

export default function OverviewCards({ summary, health, loading }) {
  const total = summary?.total_traffic;
  const ddos = summary?.ddos_count;
  const normal = summary?.normal_count;
  const highRisk = summary?.high_risk_count;
  const activeAlerts = summary?.active_alerts;
  const dbState = health?.database || 'checking';

  const formatVal = (val) => {
    if (val === undefined || val === null) return loading ? '...' : 'N/A';
    return Number(val).toLocaleString();
  };

  return (
    <div className="overview-grid">
      {/* Card 1: Total Traffic */}
      <div className="glass-card metric-card">
        <div className="metric-icon-box cyan">
          <Activity size={24} />
        </div>
        <div className="metric-details">
          <span className="metric-title">Total Analyzed Traffic</span>
          <span className="metric-value">{formatVal(total)}</span>
          <span className="metric-subtext">Backend flow records count</span>
        </div>
      </div>

      {/* Card 2: DDoS Threats */}
      <div className="glass-card metric-card">
        <div className="metric-icon-box rose">
          <ShieldAlert size={24} />
        </div>
        <div className="metric-details">
          <span className="metric-title">DDoS Predictions</span>
          <span className="metric-value" style={{ color: ddos > 0 ? '#ef4444' : '#fff' }}>
            {formatVal(ddos)}
          </span>
          <span className="metric-subtext">DecisionTree ML detections</span>
        </div>
      </div>

      {/* Card 3: Normal Traffic */}
      <div className="glass-card metric-card">
        <div className="metric-icon-box emerald">
          <CheckCircle2 size={24} />
        </div>
        <div className="metric-details">
          <span className="metric-title">Normal Traffic</span>
          <span className="metric-value">{formatVal(normal)}</span>
          <span className="metric-subtext">Legitimate network flows</span>
        </div>
      </div>

      {/* Card 4: High-Risk Traffic */}
      <div className="glass-card metric-card">
        <div className="metric-icon-box amber">
          <AlertTriangle size={24} />
        </div>
        <div className="metric-details">
          <span className="metric-title">High-Risk Flows</span>
          <span className="metric-value" style={{ color: highRisk > 0 ? '#f59e0b' : '#fff' }}>
            {formatVal(highRisk)}
          </span>
          <span className="metric-subtext">HIGH severity classifications</span>
        </div>
      </div>

      {/* Card 5: Active Alerts */}
      <div className="glass-card metric-card">
        <div className="metric-icon-box purple">
          <Bell size={24} />
        </div>
        <div className="metric-details">
          <span className="metric-title">Active Alerts</span>
          <span className="metric-value" style={{ color: activeAlerts > 0 ? '#a78bfa' : '#fff' }}>
            {formatVal(activeAlerts)}
          </span>
          <span className="metric-subtext">NEW & ACKNOWLEDGED alerts</span>
        </div>
      </div>
    </div>
  );
}
