"""
Bank DDoS Detection System - Prediction Service

Integrates with the validated ML model (ml/validation/results/best_validation_model.pkl)
using the exact Top 20 validated feature set. Performs rigorous input validation,
verifies against NaN/Infinity, and returns structured prediction results.
"""

import math
import logging
import sys
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

# Add project root to path if needed for network_monitor imports
BACKEND_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = BACKEND_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from network_monitor.config import TOP_20_FEATURES, MODEL_PATH
from network_monitor.ml_predictor import MLPredictor, get_predictor

logger = logging.getLogger("backend.prediction_service")


class PredictionService:
    """
    Service wrapper around MLPredictor providing API-level validation,
    sanitization, and error handling.
    """

    def __init__(self, model_path: Optional[Path] = None):
        """Initializes the ML predictor using the validated model artifact."""
        target_path = model_path or MODEL_PATH
        self.predictor = MLPredictor(model_path=target_path)

    def validate_features(self, payload: Any) -> Tuple[bool, Optional[Dict[str, float]], Optional[str]]:
        """
        Validates that the input payload contains exactly all 20 required features
        with valid numeric values, and contains no NaN, null, or infinite values.

        Args:
            payload: Parsed JSON data (expected dict or dict with "features" key)

        Returns:
            Tuple of (is_valid, sanitized_features_dict, error_message)
        """
        if not isinstance(payload, dict):
            return False, None, "Payload must be a valid JSON object."

        # Support both direct feature dict {"Min Packet Length": ...} and nested {"features": {...}}
        features_dict = payload.get("features", payload) if "features" in payload and isinstance(payload.get("features"), dict) else payload

        # Check for missing features
        missing = [f for f in TOP_20_FEATURES if f not in features_dict]
        if missing:
            return False, None, f"Missing required ML features: {missing}"

        # Validate numeric type and check for NaN / Inf
        sanitized = {}
        for feature_name in TOP_20_FEATURES:
            val = features_dict.get(feature_name)
            if val is None:
                return False, None, f"Feature '{feature_name}' cannot be null."

            try:
                numeric_val = float(val)
            except (ValueError, TypeError):
                return False, None, f"Feature '{feature_name}' must be a numeric value, got: {type(val).__name__}."

            if math.isnan(numeric_val):
                return False, None, f"Feature '{feature_name}' contains NaN, which is rejected for security and model safety."
            if math.isinf(numeric_val):
                return False, None, f"Feature '{feature_name}' contains Infinity, which is rejected."

            sanitized[feature_name] = numeric_val

        return True, sanitized, None

    def predict(self, feature_data: Dict[str, float]) -> Dict[str, Any]:
        """
        Executes model inference on validated feature dictionary.

        Args:
            feature_data: Validated dictionary containing exactly TOP_20_FEATURES.

        Returns:
            dict: {
                "prediction": "Normal" | "DDoS",
                "risk_level": "LOW" | "HIGH",
                "confidence": float | None,
                "label": int
            }
        """
        result = self.predictor.predict_flow(feature_data)
        return {
            "prediction": result["prediction"],
            "risk_level": result["risk_level"],
            "confidence": round(result["confidence"], 4) if result["confidence"] is not None else None,
            "label": result["label"]
        }


# Singleton service instance
_prediction_service_instance: Optional[PredictionService] = None


def get_prediction_service() -> PredictionService:
    """Returns or lazily creates the singleton PredictionService."""
    global _prediction_service_instance
    if _prediction_service_instance is None:
        _prediction_service_instance = PredictionService()
    return _prediction_service_instance
