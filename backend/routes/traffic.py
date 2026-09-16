"""
Bank DDoS Detection System - Traffic & Dashboard Routes

Handles network traffic record ingestion, history querying,
and aggregated metrics calculation for future React dashboard consumption.
"""

from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from models.traffic_record import TrafficRecord
from models.alert import Alert
from services.network_integration_service import NetworkIntegrationService

traffic_bp = Blueprint('traffic', __name__)


@traffic_bp.route('/api/traffic', methods=['POST'])
def store_traffic_record():
    """
    POST /api/traffic
    Ingests analyzed flow information and stores it in the database.
    If the record is classified as DDoS / HIGH risk, creates an alert automatically.

    Expected JSON body:
        source_ip (required)
        destination_ip (required)
        source_port (optional)
        destination_port (optional)
        protocol (optional)
        flow_duration (optional)
        packet_count (optional)
        prediction (required, e.g. "Normal", "DDoS")
        risk_level (required, e.g. "LOW", "HIGH")
        confidence (optional)

    Returns:
        JSON with created record_id.
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Malformed JSON in request body."
        }), 400

    # Validate required fields
    required_fields = ["source_ip", "destination_ip", "prediction", "risk_level"]
    missing_fields = [f for f in required_fields if f not in payload or payload[f] is None]
    if missing_fields:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": f"Missing required fields: {missing_fields}"
        }), 400

    try:
        result = NetworkIntegrationService.store_analyzed_flow(payload)
        response_data = {
            "status": "success",
            "message": "Traffic record stored",
            "record_id": result["record_id"]
        }
        if result.get("alert_created"):
            response_data["alert_created"] = True
            response_data["alert_id"] = result["alert_id"]

        return jsonify(response_data), 201

    except SQLAlchemyError as db_err:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "error_code": 503,
            "message": f"Database operation failed: {str(db_err)}"
        }), 503
    except Exception as e:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "error_code": 500,
            "message": f"Failed to store traffic record: {str(e)}"
        }), 500


@traffic_bp.route('/api/traffic', methods=['GET'])
def get_traffic_history():
    """
    GET /api/traffic?limit=50
    Retrieves recent network traffic records with bounded pagination.

    Query parameters:
        limit (int, default=50, max=500)

    Returns:
        JSON list of traffic records.
    """
    limit_param = request.args.get('limit', 50)
    try:
        limit = max(1, min(int(limit_param), 500))
    except (ValueError, TypeError):
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Invalid 'limit' parameter. Must be an integer between 1 and 500."
        }), 400

    try:
        records = (
            TrafficRecord.query
            .order_by(TrafficRecord.timestamp.desc())
            .limit(limit)
            .all()
        )
        return jsonify({
            "status": "success",
            "count": len(records),
            "limit": limit,
            "data": [r.to_dict() for r in records]
        }), 200

    except SQLAlchemyError as db_err:
        return jsonify({
            "status": "error",
            "error_code": 503,
            "message": f"Database unavailable: {str(db_err)}"
        }), 503


@traffic_bp.route('/api/dashboard/summary', methods=['GET'])
def get_dashboard_summary():
    """
    GET /api/dashboard/summary
    Aggregates real-time operational statistics for the dashboard:
        - total_traffic
        - normal_count
        - ddos_count
        - high_risk_count
        - active_alerts

    Calculated dynamically from database tables.

    Returns:
        JSON statistics summary.
    """
    try:
        total_traffic = db.session.query(TrafficRecord).count()
        normal_count = db.session.query(TrafficRecord).filter(TrafficRecord.prediction == "Normal").count()
        ddos_count = db.session.query(TrafficRecord).filter(TrafficRecord.prediction == "DDoS").count()
        high_risk_count = db.session.query(TrafficRecord).filter(TrafficRecord.risk_level == "HIGH").count()
        active_alerts = db.session.query(Alert).filter(Alert.status.in_(["NEW", "ACKNOWLEDGED"])).count()

        return jsonify({
            "status": "success",
            "total_traffic": total_traffic,
            "normal_count": normal_count,
            "ddos_count": ddos_count,
            "high_risk_count": high_risk_count,
            "active_alerts": active_alerts
        }), 200

    except SQLAlchemyError as db_err:
        return jsonify({
            "status": "error",
            "error_code": 503,
            "message": f"Database unavailable: {str(db_err)}"
        }), 503
