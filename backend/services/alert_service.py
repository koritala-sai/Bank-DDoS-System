"""
Bank DDoS Detection System - Alert Service

Manages security alert creation, querying, and lifecycle status updates.
DDoS alerts are generated exclusively when traffic is classified as DDoS (risk_level = HIGH).
All alert messages strictly indicate ML classification results rather than definitive proof of attack.
"""

import logging
from typing import List, Optional, Tuple, Dict, Any
from extensions import db
from models.alert import Alert

logger = logging.getLogger("backend.alert_service")

ALERT_MESSAGE_DDoS = "DDoS traffic detected by ML classifier."


class AlertService:
    """Service providing alert creation and lifecycle operations."""

    @staticmethod
    def create_ddos_alert(
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        custom_message: Optional[str] = None
    ) -> Alert:
        """
        Creates a new DDoS alert in the database with status 'NEW'.

        Args:
            source_ip (str, optional): Source IP address of suspicious flow.
            destination_ip (str, optional): Target IP address.
            custom_message (str, optional): Custom description if any.

        Returns:
            Alert: Newly created and committed Alert instance.
        """
        msg = custom_message or ALERT_MESSAGE_DDoS
        alert = Alert(
            alert_type="DDoS",
            risk_level="HIGH",
            message=msg,
            source_ip=source_ip,
            destination_ip=destination_ip,
            status="NEW"
        )
        db.session.add(alert)
        db.session.commit()
        logger.info(f"Created DDoS Alert [ID: {alert.id}] for {source_ip} -> {destination_ip}")
        return alert

    @staticmethod
    def get_recent_alerts(limit: int = 50) -> List[Alert]:
        """
        Fetches the most recent alerts ordered by timestamp descending.

        Args:
            limit (int): Maximum records to retrieve (1 to 500).

        Returns:
            List[Alert]: Query result list.
        """
        clamped_limit = max(1, min(int(limit), 500))
        return Alert.query.order_by(Alert.timestamp.desc()).limit(clamped_limit).all()

    @staticmethod
    def update_alert_status(alert_id: int, new_status: str) -> Tuple[bool, Optional[Alert], Optional[str]]:
        """
        Updates the status of an existing alert.

        Args:
            alert_id (int): Database ID of alert.
            new_status (str): One of NEW, ACKNOWLEDGED, RESOLVED.

        Returns:
            Tuple[is_success, alert_instance, error_message]
        """
        status_clean = str(new_status).strip().upper()
        if status_clean not in Alert.VALID_STATUSES:
            return False, None, f"Invalid status '{new_status}'. Allowed values: {list(Alert.VALID_STATUSES)}"

        alert = Alert.query.get(alert_id)
        if not alert:
            return False, None, f"Alert with ID {alert_id} not found."

        alert.status = status_clean
        db.session.commit()
        logger.info(f"Updated Alert [ID: {alert_id}] status to {status_clean}")
        return True, alert, None
