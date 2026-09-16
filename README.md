# AI-Based DDoS Detection and Intelligent Network Monitoring System for Banking Networks

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%20%7C%20React-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-MIT-orange.svg)](LICENSE)

An intelligent, real-time network monitoring and cybersecurity platform designed to protect banking network infrastructure from Distributed Denial of Service (DDoS) attacks using Machine Learning, packet stream analysis, and multi-tier risk assessment.

---

## 1. Problem Statement

Modern banking and online financial services require uninterrupted network availability and low latency. Distributed Denial of Service (DDoS) attacks pose a critical threat by flooding banking servers with massive traffic volumes (SYN Floods, UDP Floods, HTTP Floods), causing service outages, transaction failures, and severe financial and reputational damage. Traditional signature-based firewalls often fail against dynamic zero-day attacks, while crude threshold-based filters frequently cause false positives during legitimate traffic surges.

---

## 2. Project Objective

The objective of this capstone project is to develop an automated, end-to-end network monitoring and DDoS detection system tailored for banking environments. The system captures live network traffic, extracts statistical flow features, classifies traffic using supervised Machine Learning algorithms, assigns threat risk levels, logs incidents into a MySQL database, and alerts security administrators via a React-based interactive monitoring dashboard.

---

## 3. Main Features

- **Live Packet Capture**: Captures IP, TCP, and UDP packet streams using Scapy.
- **Statistical Feature Extraction**: Calculates sliding-window metrics including Packets Per Second (PPS), Bytes Per Second (BPS), TCP SYN/ACK ratios, and IP entropy.
- **ML DDoS Classification**: Classifies traffic into Benign or attack types (SYN Flood, UDP Flood, HTTP Flood) using pre-trained ML models (Random Forest / XGBoost).
- **Multi-Tier Risk Assessment**: Dynamically assigns risk levels (`Low`, `Medium`, `High`, `Critical`) based on prediction confidence and traffic thresholds.
- **Automated Alerts & Logging**: Stores detailed incident records in MySQL database and generates real-time security alerts.
- **Interactive Monitoring Dashboard**: Displays live traffic bandwidth charts, threat heatmaps, and unresolved alert logs.

---

## 4. Technology Stack

- **Frontend**: React, Vite, Custom CSS, Axios, Recharts
- **Backend**: Python 3, Flask, Flask-CORS, SQLAlchemy, PyMySQL, python-dotenv
- **Machine Learning**: Pandas, NumPy, Scikit-Learn, Joblib
- **Network Monitoring**: Scapy
- **Database**: MySQL 8.0+
- **Version Control**: Git & GitHub

---

## 5. Project Architecture

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
ML-Based DDoS Detection (Pre-trained ML Model)
     │
     ▼
Risk Assessment Engine (Low / Medium / High / Critical)
     │
     ▼
Flask Backend & MySQL Database (traffic_logs & alerts)
     │
     ▼
React Monitoring Dashboard
```

---

## 6. Folder Structure

```
Bank-DDoS-System/
│
├── frontend/                     # React + Vite Dashboard Application
│   └── README.md
│
├── backend/                      # Flask REST API & Business Logic
│   ├── app.py                    # Application entry point & health check endpoint
│   ├── config.py                 # Environment configuration loader
│   ├── requirements.txt          # Backend dependencies
│   ├── routes/                   # API Blueprint routes placeholder
│   ├── services/                 # Business logic & DB services placeholder
│   └── utils/                    # Utility & risk calculation helper functions
│
├── ml/                           # Machine Learning Module
│   ├── notebooks/                # Jupyter Notebooks for EDA & prototyping
│   ├── src/                      # ML pipeline scripts
│   │   ├── data_preprocessing.py # Cleaning, normalization & encoding
│   │   ├── feature_selection.py  # Feature engineering & selection
│   │   ├── train_model.py        # Model training script
│   │   ├── evaluate_model.py     # Evaluation & metrics generation
│   │   └── predict.py            # Model inference interface
│   ├── models/                   # Serialized model artifacts (.joblib)
│   └── README.md
│
├── network_monitor/              # Scapy Packet Sniffing & Traffic Metrics
│   ├── capture.py                # Packet capturer implementation
│   ├── traffic_analyzer.py       # Feature aggregation engine
│   └── README.md
│
├── database/                     # MySQL Database Setup
│   ├── schema.sql                # SQL schema (traffic_logs & alerts tables)
│   └── README.md
│
├── dataset/                      # Network Datasets
│   ├── raw/                      # Raw dataset storage (CICDDoS2019)
│   ├── processed/                # Preprocessed dataset storage
│   └── README.md
│
├── docs/                         # Project Documentation
│   ├── project_architecture.md   # Architectural design details
│   ├── workflow.md               # End-to-end data pipeline flow
│   └── literature_review.md      # Research literature review
│
├── tests/                        # Test Suite
│   ├── __init__.py
│   └── README.md
│
├── .env.example                  # Sample environment variables
├── .gitignore                    # Git ignore file
├── README.md                     # Main repository README
└── requirements.txt              # Root Python dependencies
```

---

## 7. Week 1 Progress

In Week 1, the project foundation and clean modular directory structure were successfully established:

- [x] Complete modular folder structure created across all team modules.
- [x] Configured `.gitignore` to protect environment secrets (`.env`), Python caches, datasets, and model artifacts.
- [x] Created root `requirements.txt` and `backend/requirements.txt` with all dependencies (Flask, Scapy, Scikit-learn, SQLAlchemy, etc.).
- [x] Implemented environment configuration management in `backend/config.py` and `.env.example`.
- [x] Developed basic Flask backend application (`backend/app.py`) with `GET /api/health` health check endpoint and error handling.
- [x] Registered Scapy dependency and created placeholder structure in `network_monitor/capture.py`.
- [x] Designed initial MySQL database schema (`database/schema.sql`) defining `traffic_logs` and `alerts` tables.
- [x] Created modular Python placeholder scripts (`ml/src/`, `network_monitor/`) with docstrings and clean function signatures.
- [x] Wrote core project documentation: `project_architecture.md`, `workflow.md`, and `literature_review.md`.

---

## 8. Future Development Plan

- **Week 2**: Dataset acquisition (CICDDoS2019/CICIDS2017), preprocessing, exploratory data analysis, and feature selection implementation.
- **Week 3**: Machine learning model training (Random Forest, Decision Trees, XGBoost), hyperparameter tuning, and model evaluation.
- **Week 4**: Advanced Scapy packet sniffing, real-time metric extraction, and flow aggregation engine completion.
- **Week 5**: Integration of ML prediction interface with live traffic feature extractor and risk level computation.
- **Week 6**: Database persistence layer (SQLAlchemy ORM models) and API routes implementation in Flask.
- **Week 7**: React frontend dashboard development (Recharts visualization components, alert tables, live metrics).
- **Week 8**: System integration testing, end-to-end validation, performance optimization, and final deployment documentation.

---

## 9. How to Run the Basic Flask Backend

### Prerequisites
- Python 3.9 or higher installed
- Virtual environment (recommended)

### Step 1: Clone the Repository & Navigate to Workspace
```bash
git clone <repository-url>
cd Bank-DDoS-System
```

### Step 2: Create & Activate Virtual Environment
```bash
# On Windows
python -m venv venv
venv\Scripts\activate

# On Linux/macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables (Optional)
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### Step 5: Run the Flask Server
```bash
# Run using Python directly from the root directory
python backend/app.py
```

### Step 6: Test the Health Check Endpoint
Open your browser or run curl:
```bash
curl http://127.0.0.1:5000/api/health
```

**Expected JSON Response**:
```json
{
  "status": "success",
  "message": "Bank DDoS Detection System backend is running"
}
```
