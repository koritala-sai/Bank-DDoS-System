# Module 3: Database Initialization & Schema

This directory contains the initial MySQL database schema definition for the Bank DDoS Detection System.

## Tables Defined

1. `traffic_logs`: Logs network traffic metrics, protocol data, ML prediction outcomes (e.g. Normal, SYN Flood, HTTP Flood), and assigned risk levels.
2. `alerts`: Stores security alert notifications generated for high/critical risk events.

## How to Initialize Database

Using MySQL CLI:
```bash
mysql -u root -p < database/schema.sql
```

Using Workbench or DBeaver:
Open `database/schema.sql` and execute the SQL script.
