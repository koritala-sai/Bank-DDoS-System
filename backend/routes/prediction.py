"""
Bank DDoS Detection System - Prediction Route

Exposes POST /api/predict for evaluating real-time network flow feature vectors
against the validated Decision Tree classifier.
"""

from flask import Blueprint, request, jsonify
from services.prediction_service import get_prediction_service

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
