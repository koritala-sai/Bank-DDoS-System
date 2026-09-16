"""
Bank DDoS Detection System - Health Check Route

Provides system health status and database connectivity inspection.
Preserves existing health check response schema for backward compatibility.
"""

from flask import Blueprint, jsonify
from sqlalchemy import text
from extensions import db

health_bp = Blueprint('health', __name__)


@health_bp.route('/api/health', methods=['GET'])
def health_check():
    """
    Health Check Endpoint.
    Verifies that the backend API is operational and checks database connectivity.

    Returns:
        JSON response with service status and database state.
    """
    db_status = "connected"
    try:
        # Fast query to verify database connectivity
        db.session.execute(text("SELECT 1"))
    except Exception:
        db_status = "unavailable"

    response = {
        "status": "success",
        "message": "Bank DDoS Detection System backend is running",
        "database": db_status
    }
    return jsonify(response), 200
