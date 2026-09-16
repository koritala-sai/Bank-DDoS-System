# Backend Services Module

Business logic services:
- `database_service.py`: SQLAlchemy database CRUD operations for `traffic_logs` and `alerts`.
- `prediction_service.py`: Interface to invoke the ML model pipeline for live traffic features.
- `alert_service.py`: Business logic for threshold-based and ML-triggered alert generation.
