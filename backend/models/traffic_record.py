"""
Bank DDoS Detection System - TrafficRecord Model

Stores analyzed network flow information and ML prediction outcomes.
Does NOT store raw packet payloads or sensitive banking payload data.
"""

from datetime import datetime, timezone
from extensions import db


class TrafficRecord(db.Model):
    """
    SQLAlchemy Model for the 'traffic_records' table.
    Records processed network flows, flow-level telemetry, and ML classifier results.
    """
    __tablename__ = 'traffic_records'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True)
    protocol = db.Column(db.String(20), nullable=True)
    flow_duration = db.Column(db.Float, nullable=True)
    packet_count = db.Column(db.Integer, nullable=True)
    prediction = db.Column(db.String(50), nullable=False, default="Normal")  # "Normal" | "DDoS"
    risk_level = db.Column(db.String(20), nullable=False, default="LOW", index=True)  # "LOW" | "HIGH"
    confidence = db.Column(db.Float, nullable=True)

    def to_dict(self):
        """Serializes the TrafficRecord model instance into a dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "flow_duration": self.flow_duration,
            "packet_count": self.packet_count,
            "prediction": self.prediction,
            "risk_level": self.risk_level,
            "confidence": self.confidence
        }

    def __repr__(self):
        return (
            f"<TrafficRecord id={self.id} {self.source_ip}->{self.destination_ip} "
            f"pred={self.prediction} risk={self.risk_level}>"
        )
