"""
Bank DDoS Detection System - Network Monitor Integration Service

Provides a clean interface connecting the Network Monitoring module
(feature extraction + ML inference) with the Flask backend and MySQL database.

Pipeline:
NetworkFlow -> extract_features() -> predict_flow() -> Flask /api/traffic -> MySQL
"""

import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from extensions import db
from models.traffic_record import TrafficRecord
from services.alert_service import AlertService

logger = logging.getLogger("backend.network_integration_service")


class NetworkIntegrationService:
    """
    Bridge connecting network flow analysis to backend database ingestion
    and remote API synchronization.
    """

    @staticmethod
    def store_analyzed_flow(record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Stores an analyzed flow record directly into the database.
        Automatically triggers a security alert if the flow is classified as DDoS.

        Args:
            record (dict): Analyzed flow record containing:
                - source_ip, destination_ip, source_port, destination_port
                - protocol, flow_duration, packet_count
                - prediction ("Normal" | "DDoS")
                - risk_level ("LOW" | "HIGH")
                - confidence (float | None)

        Returns:
            dict: Ingestion summary with record_id and alert details if created.
        """
        traffic_record = TrafficRecord(
            source_ip=str(record.get("source_ip", "0.0.0.0")),
            destination_ip=str(record.get("destination_ip", "0.0.0.0")),
            source_port=int(record["source_port"]) if record.get("source_port") is not None else None,
            destination_port=int(record["destination_port"]) if record.get("destination_port") is not None else None,
            protocol=str(record.get("protocol", "TCP")),
            flow_duration=float(record["flow_duration"]) if record.get("flow_duration") is not None else None,
            packet_count=int(record["packet_count"]) if record.get("packet_count") is not None else None,
            prediction=str(record.get("prediction", "Normal")),
            risk_level=str(record.get("risk_level", "LOW")),
            confidence=float(record["confidence"]) if record.get("confidence") is not None else None
        )

        db.session.add(traffic_record)
        db.session.commit()

        alert_created = False
        alert_id = None
        # Auto-create DDoS alert if classified as DDoS / HIGH risk
        if traffic_record.prediction.upper() == "DDOS" or traffic_record.risk_level.upper() == "HIGH":
            alert = AlertService.create_ddos_alert(
                source_ip=traffic_record.source_ip,
                destination_ip=traffic_record.destination_ip
            )
            alert_created = True
            alert_id = alert.id

        return {
            "record_id": traffic_record.id,
            "prediction": traffic_record.prediction,
            "risk_level": traffic_record.risk_level,
            "alert_created": alert_created,
            "alert_id": alert_id
        }

    @staticmethod
    def send_to_remote_backend(
        record: Dict[str, Any],
        backend_url: str = "http://localhost:5000",
        timeout: int = 5
    ) -> Dict[str, Any]:
        """
        Sends an analyzed flow record to the running Flask backend API via HTTP POST.

        Args:
            record: Flow record dictionary.
            backend_url: Base URL of Flask server.
            timeout: HTTP request timeout in seconds.

        Returns:
            dict: Server response JSON.
        """
        endpoint = f"{backend_url.rstrip('/')}/api/traffic"
        payload = {
            "source_ip": record.get("source_ip"),
            "destination_ip": record.get("destination_ip"),
            "source_port": record.get("source_port"),
            "destination_port": record.get("destination_port"),
            "protocol": record.get("protocol"),
            "flow_duration": record.get("flow_duration"),
            "packet_count": record.get("packet_count"),
            "prediction": record.get("prediction"),
            "risk_level": record.get("risk_level"),
            "confidence": record.get("confidence")
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=data_bytes,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
