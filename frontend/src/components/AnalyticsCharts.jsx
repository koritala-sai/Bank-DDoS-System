import React from 'react';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';
import { PieChart as PieIcon, BarChart2 } from 'lucide-react';

export default function AnalyticsCharts({ records = [], summary }) {
  const ddosCount = summary?.ddos_count ?? records.filter(r => r.prediction?.toLowerCase() === 'ddos').length;
  const normalCount = summary?.normal_count ?? records.filter(r => r.prediction?.toLowerCase() === 'normal').length;

  const totalAnalyzed = (summary?.total_traffic ?? records.length) || 0;
  const hasData = totalAnalyzed > 0;

  const pieData = [
    { name: 'DDoS Threat', value: ddosCount, color: '#ef4444' },
    { name: 'Normal Traffic', value: normalCount, color: '#10b981' }
  ].filter(item => item.value > 0);

  // Compute risk level breakdown from fetched records
  const riskCounts = records.reduce((acc, r) => {
    const level = (r.risk_level || 'LOW').toUpperCase();
    acc[level] = (acc[level] || 0) + 1;
    return acc;
  }, { HIGH: 0, MEDIUM: 0, LOW: 0 });

  const barData = [
    { level: 'HIGH Risk', count: riskCounts.HIGH || summary?.high_risk_count || 0, fill: '#ef4444' },
    { level: 'MEDIUM Risk', count: riskCounts.MEDIUM || 0, fill: '#f59e0b' },
    { level: 'LOW Risk', count: riskCounts.LOW || 0, fill: '#10b981' }
  ];

  return (
    <div className="charts-grid">
      {/* Chart 1: Traffic Prediction Distribution */}
      <div className="glass-card" style={{ display: 'flex', flexDirection: 'column' }}>
        <div className="section-header">
          <div className="section-title">
            <PieIcon size={18} color="var(--accent-cyan)" />
            Classifier Prediction Breakdown
          </div>
        </div>

        {!hasData ? (
          <div className="state-container" style={{ height: '220px' }}>
            <PieIcon size={32} />
            <div className="state-title">No Telemetry Available</div>
            <div className="state-desc">Metrics will appear automatically once traffic flows are processed.</div>
          </div>
        ) : (
          <div className="chart-wrapper">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData.length > 0 ? pieData : [{ name: 'No Traffic', value: 1, color: '#334155' }]}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: '#121829', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }}
                  itemStyle={{ color: '#fff' }}
                />
                <Legend
                  verticalAlign="bottom"
                  height={36}
                  formatter={(value) => <span style={{ color: '#94a3b8', fontSize: '0.8rem' }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Chart 2: Alert Risk Distribution */}
      <div className="glass-card" style={{ display: 'flex', flexDirection: 'column' }}>
        <div className="section-header">
          <div className="section-title">
            <BarChart2 size={18} color="var(--accent-purple)" />
            Threat Severity Distribution
          </div>
        </div>

        {!hasData ? (
          <div className="state-container" style={{ height: '220px' }}>
            <BarChart2 size={32} />
            <div className="state-title">No Telemetry Available</div>
            <div className="state-desc">Risk classifications will be summarized here.</div>
          </div>
        ) : (
          <div className="chart-wrapper">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} margin={{ top: 15, right: 20, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="level" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <YAxis allowDecimals={false} stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                <Tooltip
                  contentStyle={{ background: '#121829', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px', color: '#fff' }}
                  cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {barData.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>
    </div>
  );
}
