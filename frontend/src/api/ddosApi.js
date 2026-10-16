import apiClient from './config';

export const ddosApi = {
  /**
   * Health Check: GET /api/health
   */
  getHealth: async () => {
    return await apiClient.get('/api/health');
  },

  /**
   * Fetch Traffic History: GET /api/traffic?limit=50
   */
  getTrafficHistory: async (limit = 50) => {
    return await apiClient.get(`/api/traffic?limit=${limit}`);
  },

  /**
   * Fetch Security Alerts: GET /api/alerts?limit=50
   */
  getAlerts: async (limit = 50) => {
    return await apiClient.get(`/api/alerts?limit=${limit}`);
  },

  /**
   * Fetch Dashboard Aggregated Telemetry: GET /api/dashboard/summary
   */
  getDashboardSummary: async () => {
    return await apiClient.get('/api/dashboard/summary');
  },

  /**
   * Analyze Flow using ML Classifier & Save Record: POST /api/analyze
   */
  analyzeFlow: async (flowPayload) => {
    return await apiClient.post('/api/analyze', flowPayload);
  },

  /**
   * Update Alert Status: PATCH /api/alerts/:id
   */
  updateAlertStatus: async (alertId, newStatus) => {
    return await apiClient.patch(`/api/alerts/${alertId}`, { status: newStatus });
  }
};

export default ddosApi;
