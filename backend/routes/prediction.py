"""
Bank DDoS Detection System - Prediction & Analysis Routes

Exposes:
- POST /api/predict for evaluating real-time network flow feature vectors against the validated Decision Tree classifier.
- POST /api/analyze for accepting a sample flow, evaluating it with the prediction pipeline, and persisting results to database.
"""

from flask import Blueprint, request, jsonify
from sqlalchemy.exc import SQLAlchemyError
from extensions import db
from services.prediction_service import get_prediction_service
from services.network_integration_service import NetworkIntegrationService

prediction_bp = Blueprint('prediction', __name__)


@prediction_bp.route('/api/predict', methods=['POST'])
def predict_endpoint():
    """
    POST /api/predict
    Evaluates extracted 20-feature vectors using the validated ML model.

    Expected JSON body:
        Dictionary with all 20 feature keys and numeric values.

    Returns:
        JSON response with prediction ("Normal" | "DDoS"), risk_level, confidence.
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Invalid Content-Type. Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Malformed JSON in request body."
        }), 400

    service = get_prediction_service()
    is_valid, sanitized_features, err_msg = service.validate_features(payload)

    if not is_valid:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": err_msg
        }), 400

    try:
        inference = service.predict(sanitized_features)
        response_data = {
            "status": "success",
            "prediction": inference["prediction"],
            "risk_level": inference["risk_level"]
        }
        if inference.get("confidence") is not None:
            response_data["confidence"] = inference["confidence"]

        return jsonify(response_data), 200

    except Exception as e:
        return jsonify({
            "status": "error",
            "error_code": 500,
            "message": f"Inference execution failed: {str(e)}"
        }), 500


@prediction_bp.route('/api/analyze', methods=['POST'])
def analyze_endpoint():
    """
    POST /api/analyze
    Accepts a safe sample flow payload, runs it through the ML prediction pipeline,
    and persists the record (and optional alert if DDoS/HIGH risk) to the database.

    Expected JSON body:
        Flow metadata (source_ip, destination_ip, source_port, destination_port, protocol, packet_count, flow_duration)
        along with the 20 ML feature values (either top-level or under "features" key).

    Returns:
        JSON response with stored record_id, prediction, risk_level, confidence, and alert details.
    """
    if not request.is_json:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Invalid Content-Type. Request body must be valid application/json."
        }), 400

    payload = request.get_json(silent=True)
    if payload is None:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": "Malformed JSON in request body."
        }), 400

    service = get_prediction_service()
    is_valid, sanitized_features, err_msg = service.validate_features(payload)

    if not is_valid:
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": err_msg
        }), 400

    try:
        # Run model inference using validated ML model
        inference = service.predict(sanitized_features)

        # Construct full flow record dictionary
        record_data = {
            "source_ip": payload.get("source_ip", "127.0.0.1"),
            "destination_ip": payload.get("destination_ip", "10.0.0.1"),
            "source_port": payload.get("source_port"),
            "destination_port": payload.get("destination_port"),
            "protocol": payload.get("protocol", "TCP"),
            "flow_duration": payload.get("flow_duration"),
            "packet_count": payload.get("packet_count"),
            "prediction": inference["prediction"],
            "risk_level": inference["risk_level"],
            "confidence": inference.get("confidence"),
            "source_type": "sample"
        }

        # Store flow record and create auto-alert if DDoS / HIGH risk
        result = NetworkIntegrationService.store_analyzed_flow(record_data)

        response_data = {
            "status": "success",
            "message": "Flow analyzed and saved successfully",
            "record_id": result["record_id"],
            "prediction": inference["prediction"],
            "risk_level": inference["risk_level"]
        }
        if inference.get("confidence") is not None:
            response_data["confidence"] = inference["confidence"]

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
            "message": f"Analysis execution failed: {str(e)}"
        }), 500

