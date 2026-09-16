# Data Processing & Operational Workflow

This document outlines the step-by-step end-to-end data pipeline of the **AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks**.

---

## Complete End-to-End Data Pipeline

```
Network Traffic
     │
     ▼
Network Monitoring (Scapy Sniffing)
     │
     ▼
Traffic Analysis + Feature Extraction (PPS, BPS, Flag ratios, IP entropy)
     │
     ▼
ML-Based DDoS Detection (Pre-trained Random Forest / XGBoost Model)
     │
     ▼
Risk Assessment (Low / Medium / High / Critical)
     │
     ▼
Alert Generation + MySQL Database Persistence (traffic_logs & alerts)
     │
     ▼
React Monitoring Dashboard (Recharts Visualizations & Alert Feed)
```

---

## Detailed Step-by-Step Execution Flow

### Step 1: Network Traffic Generation / Ingress
- Network packets (TCP, UDP, ICMP, HTTP/S) arrive at the network interface of the target banking server or gateway.

### Step 2: Network Monitoring (`network_monitor/capture.py`)
- Scapy packet capturer listens in promiscuous mode on designated network interfaces.
- Filters out non-relevant control traffic and inspects packet headers (Ethernet, IP, TCP, UDP).

### Step 3: Feature Extraction (`network_monitor/traffic_analyzer.py`)
- Standardizes packet metadata into time-window statistics:
  - Total Packet Count & Packets Per Second (PPS)
  - Total Byte Count & Average Packet Size (Bytes)
  - Ratio of TCP SYN packets to ACK packets
  - Unique Source IP Entropy (detects distributed botnets vs single-source floods)

### Step 4: ML Prediction (`ml/src/predict.py`)
- Extracted feature vector is passed to the ML prediction interface.
- Applies feature scaling identical to training preprocessing (`data_preprocessing.py`).
- Pre-trained classifier evaluates feature vector:
  - **Output**: Multi-class label (`Benign / Normal`, `SYN Flood`, `UDP Flood`, `HTTP Flood`) + Prediction Probability.

### Step 5: Risk Assessment (`backend/utils/`)
- Evaluates classification label, prediction probability, and metric thresholds to compute a consolidated risk level:
  - **Low**: Normal baseline traffic.
  - **Medium**: Slight metric deviation; suspicious source IP pattern.
  - **High**: Confirmed attack pattern with moderate bandwidth consumption.
  - **Critical**: Massive volumetric flood threatening banking gateway availability.

### Step 6: Database Persistence & Alert Dispatch (`backend/services/`)
- Saves traffic parameters and ML prediction results into the `traffic_logs` table.
- If risk level is **High** or **Critical**, creates a new record in `alerts` table with timestamp, attack classification details, and recommended mitigation status (`Unresolved`).

### Step 7: React Dashboard Visualization (`frontend/`)
- React dashboard queries Flask REST endpoints `/api/traffic` and `/api/alerts`.
- Renders live bandwidth charts, packet rate graphs, risk level status indicators, and real-time security alert tables.
