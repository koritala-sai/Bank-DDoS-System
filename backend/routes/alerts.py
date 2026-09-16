"""
Bank DDoS Detection System - Alerts Route

Provides REST API endpoints for monitoring security alerts
and managing alert status workflow (NEW -> ACKNOWLEDGED -> RESOLVED).
"""

from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from services.alert_service import AlertService

alerts_bp = Blueprint('alerts', __name__)


@alerts_bp.route('/api/alerts', methods=['GET'])
def get_alerts():
    """
    GET /api/alerts?limit=50
    Retrieves recent security alerts with pagination.

    Query parameters:
        limit (int, default=50, max=500)

    Returns:
        JSON list of alerts.
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
        alerts = AlertService.get_recent_alerts(limit=limit)
        return jsonify({
            "status": "success",
            "count": len(alerts),
            "limit": limit,
            "data": [a.to_dict() for a in alerts]
        }), 200

    except SQLAlchemyError as db_err:
        return jsonify({
            "status": "error",
            "error_code": 503,
            "message": f"Database unavailable: {str(db_err)}"
        }), 503


@alerts_bp.route('/api/alerts/<int:alert_id>', methods=['PATCH'])
def update_alert(alert_id: int):
    """
    PATCH /api/alerts/<id>
    Updates the lifecycle status of a specific security alert.

    Expected JSON body:
        status (string, required): One of NEW, ACKNOWLEDGED, RESOLVED

    Returns:
        JSON with updated alert details.
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True)
    if not payload or "status" not in payload:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Missing required 'status' field in request body."
        }), 400

    new_status = payload["status"]

    try:
        success, alert, err_msg = AlertService.update_alert_status(alert_id, new_status)
        if not success:
            code = 404 if "not found" in (err_msg or "").lower() else 400
            return jsonify({
                "status": "error",
                "error_code": code,
                "message": err_msg
            }), code

        return jsonify({
            "status": "success",
            "message": f"Alert {alert_id} status updated to {alert.status}",
            "data": alert.to_dict()
        }), 200

    except SQLAlchemyError as db_err:
        db.session.rollback()
        return jsonify({
            "status": "error",
            "error_code": 503,
            "message": f"Database update failed: {str(db_err)}"
        }), 503
