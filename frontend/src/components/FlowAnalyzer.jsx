import React, { useState } from 'react';
import { Send, Cpu, CheckCircle2, ShieldAlert, AlertTriangle, ChevronDown, ChevronUp, Info } from 'lucide-react';
import ddosApi from '../api/ddosApi';

export default function FlowAnalyzer({ onFlowAnalyzed }) {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [showMlFeatures, setShowMlFeatures] = useState(false);

  // Flow metadata form state
  const [flowMeta, setFlowMeta] = useState({
    source_ip: '192.168.1.188',
    destination_ip: '10.0.0.1',
    source_port: 54321,
    destination_port: 443,
    protocol: 'TCP',
    packet_count: 500,
    flow_duration: 0.1,
    sample_type: 'ddos'
  });

  // Top 20 validated Decision Tree feature vectors
  const [mlFeatures, setMlFeatures] = useState({
    "Min Packet Length": 500,
    "Inbound": 1,
    "Fwd Packet Length Min": 500,
    "Fwd Packet Length Mean": 500,
    "Avg Fwd Segment Size": 500,
    "Average Packet Size": 500,
    "Bwd IAT Max": 0,
    "Bwd Packets/s": 0,
    "Packet Length Mean": 500,
    "Bwd Header Length": 0,
    "URG Flag Count": 0,
    "Total Backward Packets": 0,
    "Fwd IAT Std": 10,
    "Down/Up Ratio": 0,
    "Fwd IAT Mean": 100,
    "Flow IAT Mean": 100,
    "ACK Flag Count": 0,
    "Init_Win_bytes_forward": 512,
    "Bwd IAT Mean": 0,
    "Init_Win_bytes_backward": -1
  });

  const samplePresets = {
    ddos: {
      meta: {
        source_ip: '192.168.1.188',
        destination_ip: '10.0.0.1',
        source_port: 54321,
        destination_port: 443,
        protocol: 'TCP',
        packet_count: 500,
        flow_duration: 0.1,
        sample_type: 'ddos'
      },
      features: {
        "Min Packet Length": 500,
        "Inbound": 1,
        "Fwd Packet Length Min": 500,
        "Fwd Packet Length Mean": 500,
        "Avg Fwd Segment Size": 500,
        "Average Packet Size": 500,
        "Bwd IAT Max": 0,
        "Bwd Packets/s": 0,
        "Packet Length Mean": 500,
        "Bwd Header Length": 0,
        "URG Flag Count": 0,
        "Total Backward Packets": 0,
        "Fwd IAT Std": 10,
        "Down/Up Ratio": 0,
        "Fwd IAT Mean": 100,
        "Flow IAT Mean": 100,
        "ACK Flag Count": 0,
        "Init_Win_bytes_forward": 512,
        "Bwd IAT Mean": 0,
        "Init_Win_bytes_backward": -1
      }
    },
    normal: {
      meta: {
        source_ip: '10.0.1.45',
        destination_ip: '10.0.0.1',
        source_port: 49152,
        destination_port: 443,
        protocol: 'TCP',
        packet_count: 12,
        flow_duration: 2.5,
        sample_type: 'normal'
      },
      features: {
        "Min Packet Length": 0,
        "Inbound": 0,
        "Fwd Packet Length Min": 0,
        "Fwd Packet Length Mean": 64,
        "Avg Fwd Segment Size": 64,
        "Average Packet Size": 128,
        "Bwd IAT Max": 10000,
        "Bwd Packets/s": 10,
        "Packet Length Mean": 128,
        "Bwd Header Length": 40,
        "URG Flag Count": 0,
        "Total Backward Packets": 5,
        "Fwd IAT Std": 5000,
        "Down/Up Ratio": 1,
        "Fwd IAT Mean": 10000,
        "Flow IAT Mean": 8000,
        "ACK Flag Count": 1,
        "Init_Win_bytes_forward": 512,
        "Bwd IAT Mean": 2000,
        "Init_Win_bytes_backward": 512
      }
    }
  };

  const handlePresetSelect = (type) => {
    const preset = samplePresets[type];
    if (preset) {
      setFlowMeta(preset.meta);
      setMlFeatures(preset.features);
      setResult(null);
      setError(null);
    }
  };

  const handleFeatureChange = (featureName, value) => {
    setMlFeatures((prev) => ({
      ...prev,
      [featureName]: value === '' ? '' : Number(value)
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (loading) return; // Prevent duplicate submit

    setLoading(true);
    setError(null);
    setResult(null);

    // Validate feature completeness & numeric validity
    for (const [key, val] of Object.entries(mlFeatures)) {
      if (val === '' || val === null || isNaN(Number(val))) {
        setError(`Feature '${key}' must be a valid numeric value.`);
        setLoading(false);
        return;
      }
    }

    const payload = {
      source_ip: flowMeta.source_ip,
      destination_ip: flowMeta.destination_ip,
      source_port: parseInt(flowMeta.source_port, 10) || 0,
      destination_port: parseInt(flowMeta.destination_port, 10) || 0,
      protocol: flowMeta.protocol,
      packet_count: parseInt(flowMeta.packet_count, 10) || 0,
      flow_duration: parseFloat(flowMeta.flow_duration) || 0,
      ...mlFeatures
    };

    try {
      const res = await ddosApi.analyzeFlow(payload);
      setResult(res);
      // Trigger automatic dashboard refresh callback
      if (onFlowAnalyzed) {
        onFlowAnalyzed();
      }
    } catch (err) {
      setError(err.message || 'Failed to analyze flow sample.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-card" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Header */}
      <div className="section-header" style={{ marginBottom: 0 }}>
        <div className="section-title">
          <Cpu size={20} color="var(--accent-cyan)" />
          Sample Network Flow ML Analyzer
        </div>
        <span className="section-badge" style={{ background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-cyan)' }}>
          DecisionTree Model Evaluator
        </span>
      </div>

      {/* Safety Notice Banner */}
      <div className="info-banner">
        <Info size={16} />
        <span>
          <strong>Safe Simulation Mode:</strong> Submits structured sample flow feature vectors to <code>POST /api/analyze</code>. Does not run live packet capturing or generate actual network attack traffic.
        </span>
      </div>

      {/* Preset Selector Buttons */}
      <div style={{ display: 'flex', gap: '0.75rem' }}>
        <button
          type="button"
          className={`btn-action ${flowMeta.sample_type === 'ddos' ? 'btn-primary' : ''}`}
          onClick={() => handlePresetSelect('ddos')}
          style={{ fontSize: '0.8rem' }}
        >
          Load High-Rate DDoS Sample
        </button>
        <button
          type="button"
          className={`btn-action ${flowMeta.sample_type === 'normal' ? 'btn-primary' : ''}`}
          onClick={() => handlePresetSelect('normal')}
          style={{ fontSize: '0.8rem' }}
        >
          Load Normal Banking Sample
        </button>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {/* Flow Metadata Section */}
        <div className="form-row-3">
          <div className="form-group">
            <label className="form-label">Source IP Address</label>
            <input
              type="text"
              className="form-input"
              value={flowMeta.source_ip}
              onChange={(e) => setFlowMeta({ ...flowMeta, source_ip: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Destination IP Address</label>
            <input
              type="text"
              className="form-input"
              value={flowMeta.destination_ip}
              onChange={(e) => setFlowMeta({ ...flowMeta, destination_ip: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Protocol</label>
            <select
              className="form-input"
              value={flowMeta.protocol}
              onChange={(e) => setFlowMeta({ ...flowMeta, protocol: e.target.value })}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Source Port</label>
            <input
              type="number"
              className="form-input"
              value={flowMeta.source_port}
              onChange={(e) => setFlowMeta({ ...flowMeta, source_port: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Destination Port</label>
            <input
              type="number"
              className="form-input"
              value={flowMeta.destination_port}
              onChange={(e) => setFlowMeta({ ...flowMeta, destination_port: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Packet Count</label>
            <input
              type="number"
              className="form-input"
              value={flowMeta.packet_count}
              onChange={(e) => setFlowMeta({ ...flowMeta, packet_count: e.target.value })}
              required
            />
          </div>
          <div className="form-group">
            <label className="form-label">Flow Duration (sec)</label>
            <input
              type="number"
              step="0.001"
              className="form-input"
              value={flowMeta.flow_duration}
              onChange={(e) => setFlowMeta({ ...flowMeta, flow_duration: e.target.value })}
              required
            />
          </div>
        </div>

        {/* Collapsible ML Feature Inspector */}
        <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '0.75rem' }}>
          <button
            type="button"
            className="btn-action"
            onClick={() => setShowMlFeatures(!showMlFeatures)}
            style={{ width: '100%', justifyContent: 'space-between', fontSize: '0.8rem' }}
          >
            <span>Inspect & Edit 20 Validated DecisionTree Features ({Object.keys(mlFeatures).length} Parameters)</span>
            {showMlFeatures ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>

          {showMlFeatures && (
            <div className="features-grid" style={{ marginTop: '0.75rem' }}>
              {Object.keys(mlFeatures).map((key) => (
                <div className="form-group" key={key}>
                  <label className="form-label" style={{ fontSize: '0.7rem' }}>{key}</label>
                  <input
                    type="number"
                    step="any"
                    className="form-input"
                    value={mlFeatures[key]}
                    onChange={(e) => handleFeatureChange(key, e.target.value)}
                    style={{ fontSize: '0.75rem', padding: '0.35rem 0.5rem' }}
                  />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          className="btn-action btn-primary"
          disabled={loading}
          style={{ justifyContent: 'center', padding: '0.65rem', marginTop: '0.5rem' }}
        >
          {loading ? (
            <>
              <Cpu size={16} className="spin" />
              Running ML Inference & Database Save...
            </>
          ) : (
            <>
              <Send size={16} />
              Evaluate Flow with DecisionTree Model (POST /api/analyze)
            </>
          )}
        </button>
      </form>

      {/* Error Banner */}
      {error && (
        <div className="error-banner">
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Results Display */}
      {result && (
        <div
          className="glass-card"
          style={{
            background: result.prediction?.toLowerCase() === 'ddos' ? 'rgba(239, 68, 68, 0.1)' : 'rgba(16, 185, 129, 0.1)',
            borderColor: result.prediction?.toLowerCase() === 'ddos' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)',
            marginTop: '0.5rem'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 600 }}>
              {result.prediction?.toLowerCase() === 'ddos' ? (
                <ShieldAlert size={20} color="#ef4444" />
              ) : (
                <CheckCircle2 size={20} color="#10b981" />
              )}
              <span>DecisionTree Prediction: {result.prediction}</span>
            </div>
            <span className={`badge ${result.prediction?.toLowerCase() === 'ddos' ? 'badge-ddos' : 'badge-normal'}`}>
              Risk Level: {result.risk_level || 'LOW'}
            </span>
          </div>

          <div className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            Record ID: #{result.record_id} | Status: {result.message}
            {result.confidence !== null && result.confidence !== undefined && (
              <span> | Confidence: {(result.confidence * 100).toFixed(1)}%</span>
            )}
            {result.alert_created && (
              <div style={{ color: '#ef4444', marginTop: '0.3rem', fontWeight: 600 }}>
                High-Risk Threat Alert #{result.alert_id} auto-created in MySQL database!
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
