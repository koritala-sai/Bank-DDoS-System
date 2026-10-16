import { useState, useEffect, useCallback, useRef } from 'react';
import ddosApi from '../api/ddosApi';

export function useDdosData() {
  const [health, setHealth] = useState({ backend: 'checking', database: 'checking' });
  const [summary, setSummary] = useState(null);
  const [traffic, setTraffic] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const timerRef = useRef(null);

  const fetchAllData = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    setError(null);

    let backendAlive = false;
    let dbStatus = 'unavailable';

    // 1. Check Health
    try {
      const healthRes = await ddosApi.getHealth();
      backendAlive = healthRes.status === 'success';
      dbStatus = healthRes.database || 'connected';
      setHealth({ backend: backendAlive ? 'online' : 'offline', database: dbStatus });
    } catch (err) {
      setHealth({ backend: 'offline', database: 'unavailable' });
      setError('Backend server offline or unreachable at http://127.0.0.1:5000');
      setLoading(false);
      return;
    }

    // 2. Fetch Summary, Traffic, Alerts concurrently
    try {
      const [summaryRes, trafficRes, alertsRes] = await Promise.all([
        ddosApi.getDashboardSummary().catch(() => null),
        ddosApi.getTrafficHistory(50).catch(() => null),
        ddosApi.getAlerts(50).catch(() => null)
      ]);

      if (summaryRes && summaryRes.status === 'success') {
        setSummary({
          total_traffic: summaryRes.total_traffic,
          normal_count: summaryRes.normal_count,
          ddos_count: summaryRes.ddos_count,
          high_risk_count: summaryRes.high_risk_count,
          active_alerts: summaryRes.active_alerts
        });
      }

      if (trafficRes && trafficRes.status === 'success') {
        setTraffic(trafficRes.data || []);
      }

      if (alertsRes && alertsRes.status === 'success') {
        setAlerts(alertsRes.data || []);
      }
    } catch (err) {
      setError(`Failed to retrieve telemetry data: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  // Handler for updating alert status
  const updateAlertStatus = async (alertId, newStatus) => {
    try {
      await ddosApi.updateAlertStatus(alertId, newStatus);
      // Refresh alerts and summary silently
      fetchAllData(true);
    } catch (err) {
      alert(`Error updating alert status: ${err.message}`);
    }
  };

  // Initial load
  useEffect(() => {
    fetchAllData(false);
  }, [fetchAllData]);

  // Setup / teardown auto refresh timer cleanly
  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = setInterval(() => {
        fetchAllData(true);
      }, 10000); // 10s polling interval
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [autoRefresh, fetchAllData]);

  return {
    health,
    summary,
    traffic,
    alerts,
    loading,
    error,
    autoRefresh,
    setAutoRefresh,
    refreshData: () => fetchAllData(false),
    updateAlertStatus
  };
}
