import React, { useState } from 'react';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import OverviewCards from './components/OverviewCards';
import TrafficHistoryTable from './components/TrafficHistoryTable';
import SecurityAlerts from './components/SecurityAlerts';
import AnalyticsCharts from './components/AnalyticsCharts';
import FlowAnalyzer from './components/FlowAnalyzer';
import { useDdosData } from './hooks/useDdosData';
import { AlertOctagon } from 'lucide-react';

export default function App() {
  const {
    health,
    summary,
    traffic,
    alerts,
    loading,
    error,
    autoRefresh,
    setAutoRefresh,
    refreshData,
    updateAlertStatus
  } = useDdosData();

  const [activeTab, setActiveTab] = useState('dashboard'); // 'dashboard' | 'traffic' | 'alerts' | 'analyzer'

  return (
    <div className="app-shell">
      {/* Top Header Navigation */}
      <Navbar
        health={health}
        loading={loading}
        autoRefresh={autoRefresh}
        setAutoRefresh={setAutoRefresh}
        onRefresh={refreshData}
      />

      {/* Sidebar + Main Content Layout */}
      <div className="app-layout">
        {/* Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          health={health}
        />

        {/* Main Content Area */}
        <main className="dashboard-content">
          {/* Backend Connection Error Banner */}
          {error && health.backend === 'offline' && (
            <div className="error-banner" style={{ background: 'rgba(239, 68, 68, 0.15)', borderColor: 'rgba(239, 68, 68, 0.4)', padding: '1rem 1.25rem' }}>
              <AlertOctagon size={24} color="#ef4444" />
              <div>
                <div style={{ fontWeight: 600, color: '#fff' }}>Flask Backend Offline</div>
                <div style={{ fontSize: '0.825rem', marginTop: '0.2rem' }}>
                  Cannot connect to Flask backend. Please ensure <code>python backend/app.py</code> is running.
                </div>
              </div>
            </div>
          )}

          {/* View 1: Executive Overview Dashboard */}
          {activeTab === 'dashboard' && (
            <div className="view-container">
              <OverviewCards summary={summary} health={health} loading={loading} />
              <AnalyticsCharts records={traffic} summary={summary} />
            </div>
          )}

          {/* View 2: Traffic History Monitoring Page */}
          {activeTab === 'traffic' && (
            <div className="view-container">
              <TrafficHistoryTable records={traffic} loading={loading} error={error} onRefresh={refreshData} />
            </div>
          )}

          {/* View 3: Security Alerts Stream Page */}
          {activeTab === 'alerts' && (
            <div className="view-container">
              <SecurityAlerts
                alerts={alerts}
                loading={loading}
                error={error}
                onUpdateStatus={updateAlertStatus}
                onRefresh={refreshData}
              />
            </div>
          )}

          {/* View 4: Interactive Sample Flow ML Analyzer Page */}
          {activeTab === 'analyzer' && (
            <div className="view-container">
              <div className="analyzer-container">
                <FlowAnalyzer onFlowAnalyzed={refreshData} />
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
