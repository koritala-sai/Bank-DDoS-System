import React from 'react';
import { LayoutDashboard, Activity, ShieldAlert, Terminal, Server, Database } from 'lucide-react';

export default function Sidebar({ activeTab, setActiveTab, health }) {
  const navItems = [
    { id: 'dashboard', label: 'Executive Overview', icon: LayoutDashboard },
    { id: 'traffic', label: 'Traffic History Log', icon: Activity },
    { id: 'alerts', label: 'Security Alerts Stream', icon: ShieldAlert },
    { id: 'analyzer', label: 'Sample Flow ML Analyzer', icon: Terminal }
  ];

  return (
    <aside className="app-sidebar">
      <div className="sidebar-section">
        <div className="sidebar-label">NAVIGATION</div>
        <nav className="sidebar-menu">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                className={`sidebar-item ${isActive ? 'active' : ''}`}
                onClick={() => setActiveTab(item.id)}
              >
                <Icon size={18} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      <div className="sidebar-section sidebar-footer">
        <div className="sidebar-label">SYSTEM HEALTH</div>
        <div className="sidebar-health-status">
          <div className="health-row">
            <Server size={14} color="#94a3b8" />
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>API Server:</span>
            <span className={`health-badge ${health.backend === 'online' ? 'online' : 'offline'}`}>
              {health.backend === 'online' ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <div className="health-row">
            <Database size={14} color="#94a3b8" />
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>MySQL DB:</span>
            <span className={`health-badge ${health.database === 'connected' ? 'online' : 'offline'}`}>
              {(health.database || 'UNKNOWN').toUpperCase()}
            </span>
          </div>
        </div>
      </div>
    </aside>
  );
}
