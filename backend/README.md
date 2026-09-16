# Bank DDoS Detection System — Backend

## Purpose

This is the Flask REST API backend for the AI-Based DDoS Detection and Intelligent Network Monitoring System.  
It bridges the existing Network Monitoring + ML prediction pipeline with a MySQL database and REST APIs consumed by the future React dashboard.

**Architecture:**
```
Real Network Traffic
       ↓
Network Monitor (Passive Capture)
       ↓
Feature Extraction (Top 20 validated features)
       ↓
Decision Tree ML Model (best_validation_model.pkl)
       ↓
Flask Backend (REST APIs)
       ↓
MySQL Database (bank_ddos)
       ↓
REST APIs → Future React Dashboard
```

---

## Prerequisites

- Python 3.10+
- MySQL 8.0+ running locally

---

## 1. MySQL Setup

Install MySQL 8.0 from https://dev.mysql.com/downloads/ and ensure the service is running.

**Create the database** (one-time setup):
```sql
CREATE DATABASE IF NOT EXISTS bank_ddos
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

Or use the provided helper:
```bash
cd c:/Users/korit/pro/capstone
python -c "
import pymysql, os
from dotenv import load_dotenv
load_dotenv('backend/.env')
conn = pymysql.connect(host='localhost', port=3306,
       user=os.getenv('DB_USER'), password=os.getenv('DB_PASSWORD'))
conn.cursor().execute('CREATE DATABASE IF NOT EXISTS bank_ddos;')
conn.commit(); conn.close(); print('Done')
"
```

---

## 2. Environment Configuration (.env)

Create `backend/.env` (do NOT commit to Git):

```env
FLASK_APP=backend/app.py
FLASK_ENV=development
FLASK_DEBUG=1
PORT=5000
SECRET_KEY=change-this-in-production

DB_HOST=localhost
DB_PORT=3306
DB_NAME=bank_ddos
DB_USER=root
DB_PASSWORD=your_password_here
```

> **Important:** If your password contains special characters like `@`, `#`, `:`, `/`, do NOT modify it.
> The backend automatically URL-encodes credentials using `urllib.parse.quote_plus` before building the MySQL connection URI.
> Do NOT manually add a `DATABASE_URL` override unless you URL-encode it yourself.

---

## 3. Install Dependencies

```bash
cd c:/Users/korit/pro/capstone
.venv\Scripts\pip install -r backend/requirements.txt
```

---

## 4. Start the Flask Backend

```bash
cd c:/Users/korit/pro/capstone
$env:PYTHONPATH="."
.venv\Scripts\python backend/app.py
```

Server starts at: **http://localhost:5000**

On startup Flask will:
1. Load environment variables from `backend/.env`
2. Connect to MySQL using URL-safe credentials
3. Create tables `traffic_records` and `alerts` if they don't exist (safe, non-destructive)

---

## 5. API Endpoints

### Health Check
```
GET /api/health
```
**Response:**
```json
{
  "status": "success",
  "message": "Bank DDoS Detection System backend is running",
  "database": "connected"
}
```

---

### ML Prediction
```
POST /api/predict
Content-Type: application/json
```
**Request body:** All 20 validated feature names with numeric values.

**Response (Normal):**
```json
{
  "status": "success",
  "prediction": "Normal",
  "risk_level": "LOW",
  "confidence": 0.98
}
```

**Response (DDoS):**
```json
{
  "status": "success",
  "prediction": "DDoS",
  "risk_level": "HIGH",
  "confidence": 0.99
}
```

**Validation errors (400):**  
- Missing features  
- NaN or Infinity values  
- Non-JSON body

---

### Store Traffic Record
```
POST /api/traffic
Content-Type: application/json
```
**Required fields:** `source_ip`, `destination_ip`, `prediction`, `risk_level`  
**Optional:** `source_port`, `destination_port`, `protocol`, `flow_duration`, `packet_count`, `confidence`

**Response:**
```json
{
  "status": "success",
  "message": "Traffic record stored",
  "record_id": 42,
  "alert_created": true,
  "alert_id": 7
}
```
> DDoS flows automatically trigger a security alert with status `NEW`.

---

### Get Traffic History
```
GET /api/traffic?limit=50
```
**Response:**
```json
{
  "status": "success",
  "count": 50,
  "limit": 50,
  "data": [{ "id": 1, "timestamp": "...", "prediction": "Normal", ... }]
}
```

---

### Dashboard Summary
```
GET /api/dashboard/summary
```
**Response:**
```json
{
  "status": "success",
  "total_traffic": 100,
  "normal_count": 90,
  "ddos_count": 10,
  "high_risk_count": 10,
  "active_alerts": 5
}
```

---

### Get Alerts
```
GET /api/alerts?limit=50
```
**Response:**
```json
{
  "status": "success",
  "count": 2,
  "limit": 50,
  "data": [{ "id": 1, "alert_type": "DDoS", "risk_level": "HIGH", "status": "NEW", ... }]
}
```

---

### Update Alert Status
```
PATCH /api/alerts/<id>
Content-Type: application/json
```
**Body:**
```json
{ "status": "ACKNOWLEDGED" }
```
**Valid statuses:** `NEW` → `ACKNOWLEDGED` → `RESOLVED`

**Response:**
```json
{
  "status": "success",
  "message": "Alert 1 status updated to ACKNOWLEDGED",
  "data": { "id": 1, "status": "ACKNOWLEDGED", ... }
}
```

---

## 6. Testing

### Run backend tests (uses in-memory SQLite, no real DB required):
```bash
$env:PYTHONPATH="."
.venv\Scripts\python -m pytest backend/tests -v
```

### Run network monitor tests:
```bash
$env:PYTHONPATH="."
.venv\Scripts\python -m pytest network_monitor/tests -v
```

### Run all tests:
```bash
$env:PYTHONPATH="."
.venv\Scripts\python -m pytest backend/tests network_monitor/tests -v
```

---

## 7. Common MySQL Connection Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `Access denied for user 'root'@'localhost'` | Wrong password in `.env` | Update `DB_PASSWORD` in `backend/.env` |
| `Can't connect to MySQL server on 'xxx@localhost'` | Special char in password not encoded | Fixed in `config.py` using `quote_plus` — no action needed |
| `Unknown database 'bank_ddos'` | Database not created | Run the DB creation step above |
| `Can't connect to MySQL server on 'localhost'` | MySQL service not running | Start MySQL: `net start MySQL80` |
| `ModuleNotFoundError: No module named 'pymysql'` | Missing dependency | Run `pip install -r backend/requirements.txt` |

---

## 8. Database Tables

| Table | Purpose |
|-------|---------|
| `traffic_records` | Stores analyzed network flows and ML predictions |
| `alerts` | Stores DDoS security alerts generated by the ML classifier |

> **Note:** The backend describes alerts as ML classification results, not as absolute proof of an attack.  
> Raw packet payloads are **never** stored.
