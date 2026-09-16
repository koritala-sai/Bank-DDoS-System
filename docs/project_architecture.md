# Project Architecture & System Design

## Overview

The **AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks** is an end-to-end cybersecurity solution designed to protect financial network infrastructure from Distributed Denial of Service (DDoS) attacks. The system continuously captures live packet streams, extracts statistical flow features, classifies traffic using trained Machine Learning models, calculates threat risk levels, logs events to a persistent MySQL database, and visualizes security metrics on an interactive React dashboard.

---

## Architectural Diagram

```
+-----------------------------------------------------------------------------------+
|                                  NETWORK TRAFFIC                                  |
|                      (HTTP/S, TCP SYN, UDP, ICMP Ingress Packets)                 |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                        MODULE 2: NETWORK MONITORING (Scapy)                       |
|           - Promiscuous Sniffing / Packet Capture (`capture.py`)                  |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                     TRAFFIC ANALYSIS & FEATURE EXTRACTION                         |
|   - Compute Packets/sec, Byte rates, Flag Ratios, IP Entropy (`traffic_analyzer.py`)|
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         MODULE 1: ML-BASED DDOS DETECTION                         |
|   - Data Preprocessing & Feature Scaling (`data_preprocessing.py`)                |
|   - Real-time Model Inference (`predict.py`) -> Normal / SYN-Flood / UDP-Flood...|
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                            RISK ASSESSMENT ENGINE                                 |
|   - Evaluate anomaly threshold & confidence score -> (Low / Medium / High / Critical)|
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                       MODULE 3: FLASK BACKEND & MYSQL DATABASE                    |
|   - SQLAlchemy ORM Data Access (`traffic_logs` & `alerts` tables)                 |
|   - REST API Endpoints (`/api/traffic`, `/api/alerts`, `/api/health`)            |
+-----------------------------------------------------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                         MODULE 4: REACT FRONTEND DASHBOARD                        |
|   - Live Traffic Charts (Recharts), Threat Heatmaps, Alert Notifications          |
+-----------------------------------------------------------------------------------+
```

---

## Module Breakdown & Interconnections

### 1. Network Monitoring (`network_monitor/`)
- **Responsibility**: Captures raw ingress and egress network packets using Scapy.
- **Interconnection**: Feeds raw packet data structures into `traffic_analyzer.py` for aggregation.

### 2. Traffic Analysis & Feature Extraction (`network_monitor/traffic_analyzer.py`)
- **Responsibility**: Processes raw packet streams into aggregated sliding-window feature vectors (Packets Per Second, Bytes Per Second, TCP SYN/ACK ratios, Source IP entropy).
- **Interconnection**: Passes preprocessed numerical feature vectors to the ML Prediction engine.

### 3. ML-Based DDoS Detection (`ml/`)
- **Responsibility**: Preprocesses feature vectors and runs prediction inference using pre-trained machine learning classifiers (Random Forest / XGBoost). Assigns threat classification labels and probability scores.
- **Interconnection**: Sends classification results and feature metrics to the Risk Assessment module and Backend API.

### 4. Risk Assessment & Alerts (`backend/utils/` & `backend/services/`)
- **Responsibility**: Computes threat risk levels (`Low`, `Medium`, `High`, `Critical`) based on ML model confidence and anomaly thresholds. Triggers security alerts when risk levels exceed acceptable thresholds.
- **Interconnection**: Writes logs to `traffic_logs` and raises entries in `alerts`.

### 5. Flask Backend & MySQL Database (`backend/` & `database/`)
- **Responsibility**: Exposes RESTful JSON endpoints for frontend queries, manages database persistence using MySQL and SQLAlchemy.
- **Interconnection**: Serves historical traffic data, real-time alerts, and system health status to the React Dashboard.

### 6. React Dashboard (`frontend/`)
- **Responsibility**: Provides security analysts with real-time visual monitoring, metric charts, alert management interfaces, and risk level indicators.
- **Interconnection**: Queries Flask API via Axios over HTTP/REST.

---

## Security & Resilience Considerations

1. **Environment Variables**: Sensitive database credentials and secret keys are managed securely using `.env` configurations.
2. **Modular Decoupling**: Packet monitoring operates asynchronously from database logging and frontend API response loops to prevent packet loss under high load.
3. **Fail-Safe Defaults**: If ML inference fails, fallback rule-based threshold filters evaluate network traffic.
