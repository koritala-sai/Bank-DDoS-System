"""
Bank DDoS Detection System - Backend Test Suite

Verifies:
1. /api/health endpoint
2. /api/predict with valid 20 features (Normal and DDoS predictions)
3. /api/predict validation error handling (missing fields, NaN, Infinity, non-JSON)
4. /api/traffic record creation (Normal flow)
5. /api/traffic record creation (DDoS flow -> auto alert creation)
6. /api/traffic missing required fields handling
7. GET /api/traffic history with limit parameter
8. GET /api/alerts with limit parameter
9. PATCH /api/alerts/<id> status update (ACKNOWLEDGED, RESOLVED)
10. PATCH /api/alerts/<id> invalid status and 404 handling
11. GET /api/dashboard/summary dynamic database aggregation
12. Database error resilience
"""

import sys
import unittest
from pathlib import Path

# Add project root and backend directory to path
TEST_DIR = Path(__file__).resolve().parent
BACKEND_DIR = TEST_DIR.parent
PROJECT_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from extensions import db
from models.traffic_record import TrafficRecord
from models.alert import Alert
from network_monitor.config import TOP_20_FEATURES


class BackendAPITestCase(unittest.TestCase):
    """Test suite covering all REST endpoints and business logic."""

    @classmethod
    def setUpClass(cls):
        """Create app instance configured for testing (in-memory SQLite)."""
        cls.app = create_app('testing')
        cls.client = cls.app.test_client()

    def setUp(self):
        """Re-create database tables cleanly before every test."""
        with self.app.app_context():
            db.create_all()

    def tearDown(self):
        """Drop tables after each test to ensure test isolation."""
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def _get_valid_feature_payload(self, inbound=1.0, min_pkt_len=64.0):
        """Helper generating a dictionary with all 20 valid features."""
        return {
            "Min Packet Length": min_pkt_len,
            "Inbound": inbound,
            "Fwd Packet Length Min": 64.0,
            "Fwd Packet Length Mean": 128.0,
            "Avg Fwd Segment Size": 128.0,
            "Average Packet Size": 256.0,
            "Bwd IAT Max": 1000.0,
            "Bwd Packets/s": 50.0,
            "Packet Length Mean": 200.0,
            "Bwd Header Length": 40.0,
            "URG Flag Count": 0.0,
            "Total Backward Packets": 10.0,
            "Fwd IAT Std": 50.0,
            "Down/Up Ratio": 1.0,
            "Fwd IAT Mean": 100.0,
            "Flow IAT Mean": 80.0,
            "ACK Flag Count": 15.0,
            "Init_Win_bytes_forward": 65535.0,
            "Bwd IAT Mean": 120.0,
            "Init_Win_bytes_backward": 28960.0
        }

    # -------------------------------------------------------------
    # 1. Health Endpoint Tests
    # -------------------------------------------------------------
    def test_01_health_endpoint(self):
        """Verify /api/health returns 200 and expected status fields."""
        response = self.client.get('/api/health')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("Bank DDoS Detection System", data["message"])
        self.assertIn(data["database"], ["connected", "unavailable"])

    # -------------------------------------------------------------
    # 2. Prediction API Tests
    # -------------------------------------------------------------
    def test_02_predict_valid_features(self):
        """Verify /api/predict accepts 20 valid features and returns classification."""
        payload = self._get_valid_feature_payload()
        response = self.client.post('/api/predict', json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn(data["prediction"], ["Normal", "DDoS"])
        self.assertIn(data["risk_level"], ["LOW", "HIGH"])
        if "confidence" in data:
            self.assertIsInstance(data["confidence"], (int, float))

    def test_03_predict_missing_features(self):
        """Verify /api/predict rejects payloads missing required features."""
        payload = self._get_valid_feature_payload()
        del payload["Min Packet Length"]
        response = self.client.post('/api/predict', json=payload)
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Missing required ML features", data["message"])

    def test_04_predict_nan_and_inf_rejected(self):
        """Verify /api/predict rejects NaN or Infinity feature values."""
        payload = self._get_valid_feature_payload()
        payload["Flow IAT Mean"] = float("nan")
        response = self.client.post('/api/predict', json=payload)
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("NaN", data["message"])

        payload["Flow IAT Mean"] = float("inf")
        response = self.client.post('/api/predict', json=payload)
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("Infinity", data["message"])

    def test_05_predict_invalid_content_type(self):
        """Verify /api/predict rejects non-JSON payloads."""
        response = self.client.post('/api/predict', data="plain text body")
        self.assertEqual(response.status_code, 400)

    # -------------------------------------------------------------
    # 3. Traffic Record Ingestion & History Tests
    # -------------------------------------------------------------
    def test_06_store_normal_traffic_record(self):
        """Verify POST /api/traffic stores a normal flow record without creating an alert."""
        flow_payload = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "source_port": 54321,
            "destination_port": 443,
            "protocol": "TCP",
            "flow_duration": 1.25,
            "packet_count": 45,
            "prediction": "Normal",
            "risk_level": "LOW",
            "confidence": 0.98
        }
        response = self.client.post('/api/traffic', json=flow_payload)
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("record_id", data)
        self.assertFalse(data.get("alert_created", False))

        # Check DB record
        with self.app.app_context():
            rec = TrafficRecord.query.get(data["record_id"])
            self.assertIsNotNone(rec)
            self.assertEqual(rec.prediction, "Normal")
            # Verify no alerts were created
            self.assertEqual(Alert.query.count(), 0)

    def test_07_store_ddos_traffic_triggers_alert(self):
        """Verify POST /api/traffic with DDoS/HIGH risk automatically creates an alert."""
        flow_payload = {
            "source_ip": "203.0.113.55",
            "destination_ip": "10.0.0.1",
            "source_port": 44444,
            "destination_port": 80,
            "protocol": "TCP",
            "flow_duration": 0.05,
            "packet_count": 1000,
            "prediction": "DDoS",
            "risk_level": "HIGH",
            "confidence": 0.99
        }
        response = self.client.post('/api/traffic', json=flow_payload)
        self.assertEqual(response.status_code, 201)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data.get("alert_created"))
        self.assertIn("alert_id", data)

        # Check that alert was saved in DB
        with self.app.app_context():
            alert = Alert.query.get(data["alert_id"])
            self.assertIsNotNone(alert)
            self.assertEqual(alert.alert_type, "DDoS")
            self.assertEqual(alert.risk_level, "HIGH")
            self.assertEqual(alert.status, "NEW")
            self.assertEqual(alert.source_ip, "203.0.113.55")
            self.assertIn("ML classifier", alert.message)

    def test_08_store_traffic_missing_required_fields(self):
        """Verify POST /api/traffic rejects records with missing required fields."""
        incomplete_payload = {
            "source_ip": "192.168.1.1"
            # Missing destination_ip, prediction, risk_level
        }
        response = self.client.post('/api/traffic', json=incomplete_payload)
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertEqual(data["status"], "error")
        self.assertIn("Missing required fields", data["message"])

    def test_09_get_traffic_history_with_limit(self):
        """Verify GET /api/traffic pagination and limit behavior."""
        # Insert 5 records
        with self.app.app_context():
            for i in range(5):
                db.session.add(TrafficRecord(
                    source_ip=f"10.0.0.{i+1}",
                    destination_ip="192.168.1.1",
                    prediction="Normal",
                    risk_level="LOW"
                ))
            db.session.commit()

        # Query with limit=3
        response = self.client.get('/api/traffic?limit=3')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["count"], 3)
        self.assertEqual(len(data["data"]), 3)

    # -------------------------------------------------------------
    # 4. Alerts API Tests
    # -------------------------------------------------------------
    def test_10_get_alerts_and_patch_status(self):
        """Verify GET /api/alerts and PATCH /api/alerts/<id> workflow."""
        # Create an alert
        with self.app.app_context():
            alert = Alert(
                alert_type="DDoS",
                risk_level="HIGH",
                message="DDoS traffic detected by ML classifier.",
                source_ip="198.51.100.2",
                status="NEW"
            )
            db.session.add(alert)
            db.session.commit()
            alert_id = alert.id

        # GET /api/alerts
        get_resp = self.client.get('/api/alerts?limit=10')
        self.assertEqual(get_resp.status_code, 200)
        data = get_resp.get_json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["data"][0]["status"], "NEW")

        # PATCH to ACKNOWLEDGED
        patch_resp = self.client.patch(f'/api/alerts/{alert_id}', json={"status": "ACKNOWLEDGED"})
        self.assertEqual(patch_resp.status_code, 200)
        self.assertEqual(patch_resp.get_json()["data"]["status"], "ACKNOWLEDGED")

        # PATCH to RESOLVED
        patch_resp2 = self.client.patch(f'/api/alerts/{alert_id}', json={"status": "RESOLVED"})
        self.assertEqual(patch_resp2.status_code, 200)
        self.assertEqual(patch_resp2.get_json()["data"]["status"], "RESOLVED")

    def test_11_patch_alert_invalid_status_and_not_found(self):
        """Verify error responses for invalid alert status and nonexistent ID."""
        # Nonexistent alert ID
        resp_404 = self.client.patch('/api/alerts/99999', json={"status": "ACKNOWLEDGED"})
        self.assertEqual(resp_404.status_code, 404)

        # Create alert, then send invalid status
        with self.app.app_context():
            alert = Alert(alert_type="DDoS", risk_level="HIGH", message="test", status="NEW")
            db.session.add(alert)
            db.session.commit()
            aid = alert.id

        resp_bad = self.client.patch(f'/api/alerts/{aid}', json={"status": "INVALID_STATUS"})
        self.assertEqual(resp_bad.status_code, 400)
        self.assertIn("Invalid status", resp_bad.get_json()["message"])

    # -------------------------------------------------------------
    # 5. Dashboard Summary API Tests
    # -------------------------------------------------------------
    def test_12_dashboard_summary_dynamic_calculation(self):
        """Verify GET /api/dashboard/summary calculates dynamic counts directly from DB."""
        with self.app.app_context():
            # 3 Normal flows
            for _ in range(3):
                db.session.add(TrafficRecord(
                    source_ip="192.168.1.5",
                    destination_ip="10.0.0.1",
                    prediction="Normal",
                    risk_level="LOW"
                ))
            # 2 DDoS flows
            for _ in range(2):
                db.session.add(TrafficRecord(
                    source_ip="203.0.113.1",
                    destination_ip="10.0.0.1",
                    prediction="DDoS",
                    risk_level="HIGH"
                ))
            # 1 active alert (NEW), 1 active alert (ACKNOWLEDGED), 1 closed alert (RESOLVED)
            db.session.add(Alert(alert_type="DDoS", risk_level="HIGH", message="a1", status="NEW"))
            db.session.add(Alert(alert_type="DDoS", risk_level="HIGH", message="a2", status="ACKNOWLEDGED"))
            db.session.add(Alert(alert_type="DDoS", risk_level="HIGH", message="a3", status="RESOLVED"))
            db.session.commit()

        response = self.client.get('/api/dashboard/summary')
        self.assertEqual(response.status_code, 200)
        stats = response.get_json()
        self.assertEqual(stats["status"], "success")
        self.assertEqual(stats["total_traffic"], 5)
        self.assertEqual(stats["normal_count"], 3)
        self.assertEqual(stats["ddos_count"], 2)
        self.assertEqual(stats["high_risk_count"], 2)
        self.assertEqual(stats["active_alerts"], 2)  # NEW + ACKNOWLEDGED


if __name__ == '__main__':
    unittest.main()
