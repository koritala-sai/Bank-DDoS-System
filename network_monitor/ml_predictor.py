"""
Module 2: Network Monitoring and Traffic Analysis - ML Predictor
Loads the validated Decision Tree model and performs live/offline inference
on extracted Top 20 feature vectors.
"""

import os
import sys
import types
import logging
from pathlib import Path
from typing import Dict, Union, Any, Optional

# Windows Application Control / Smart App Control compatibility fix for scipy.spatial
if "scipy.spatial._ckdtree" not in sys.modules:
    try:
        import scipy.spatial._ckdtree  # noqa: F401
    except ImportError:
        dummy_ckdtree = types.ModuleType("scipy.spatial._ckdtree")
        dummy_ckdtree.cKDTree = object
        dummy_ckdtree.cKDTreeNode = object
        sys.modules["scipy.spatial._ckdtree"] = dummy_ckdtree

import joblib
import numpy as np
import pandas as pd

from .config import MODEL_PATH, TOP_20_FEATURES, LABEL_MAP, RISK_LEVEL_MAP

logger = logging.getLogger("network_monitor.ml_predictor")


class MLPredictor:
    """
    Inference engine for DDoS detection using the validated Decision Tree model.
    """

    def __init__(self, model_path: Optional[Union[str, Path]] = None):
        """
        Initializes the predictor and loads the trained model.

        Args:
            model_path (str | Path, optional): Custom path to model PKL file.
        """
        self.model_path = Path(model_path) if model_path else MODEL_PATH
        self.model = None
        self._load_model()

    def _load_model(self):
        """Loads the serialized model PKL from disk."""
        if not self.model_path.exists():
            err_msg = (
                f"Model file not found at '{self.model_path}'. "
                "Ensure 'ml/validation/results/best_validation_model.pkl' exists."
            )
            logger.error(err_msg)
            raise FileNotFoundError(err_msg)

        try:
            self.model = joblib.load(self.model_path)
            logger.info(f"Successfully loaded validation model from '{self.model_path}'.")
        except Exception as e:
            err_msg = f"Failed to load model from '{self.model_path}': {e}"
            logger.error(err_msg)
            raise RuntimeError(err_msg) from e

    def prepare_feature_vector(self, features: Union[Dict[str, float], pd.DataFrame]) -> pd.DataFrame:
        """
        Ensures the input feature vector matches the exact 20 feature names and order.

        Args:
            features: Dictionary of feature names -> values, or pandas DataFrame.

        Returns:
            pd.DataFrame with 1 row and exactly TOP_20_FEATURES columns in strict order.
        """
        if isinstance(features, dict):
            # Check for missing features
            missing = [f for f in TOP_20_FEATURES if f not in features]
            if missing:
                raise ValueError(f"Missing required features: {missing}")

            ordered_data = {f: [float(features[f])] for f in TOP_20_FEATURES}
            df = pd.DataFrame(ordered_data, columns=TOP_20_FEATURES)
        elif isinstance(features, pd.DataFrame):
            missing = [f for f in TOP_20_FEATURES if f not in features.columns]
            if missing:
                raise ValueError(f"Missing required features in DataFrame: {missing}")

            df = features[TOP_20_FEATURES].copy()
        else:
            raise TypeError(f"Expected dict or pd.DataFrame, got {type(features)}")

        # Handle any possible NaN or Inf values
        df = df.fillna(0.0).replace([np.inf, -np.inf], 0.0)
        return df

    def predict_flow(self, features: Union[Dict[str, float], pd.DataFrame]) -> Dict[str, Any]:
        """
        Runs model inference on the provided feature vector.

        Args:
            features: Top 20 feature dictionary or DataFrame.

        Returns:
            dict containing:
                - prediction: "Normal" | "DDoS"
                - label: 0 | 1
                - confidence: float | None
                - risk_level: "LOW" | "HIGH"
        """
        if self.model is None:
            self._load_model()

        X = self.prepare_feature_vector(features)

        # Binary label prediction (0 = Normal, 1 = DDoS)
        label_pred = int(self.model.predict(X)[0])
        prediction_str = LABEL_MAP.get(label_pred, "Unknown")
        risk_level_str = RISK_LEVEL_MAP.get(label_pred, "UNKNOWN")

        # Confidence calculation via predict_proba if supported
        confidence = None
        if hasattr(self.model, "predict_proba"):
            try:
                probabilities = self.model.predict_proba(X)[0]
                # Probability corresponding to the predicted class
                class_idx = list(self.model.classes_).index(label_pred) if hasattr(self.model, "classes_") else label_pred
                confidence = float(probabilities[class_idx])
            except Exception as pe:
                logger.warning(f"Could not compute prediction probability: {pe}")
                confidence = None

        return {
            "prediction": prediction_str,
            "label": label_pred,
            "confidence": confidence,
            "risk_level": risk_level_str
        }


# Module singleton instance
_DEFAULT_PREDICTOR: Optional[MLPredictor] = None


def get_predictor() -> MLPredictor:
    """Returns or creates the default singleton MLPredictor."""
    global _DEFAULT_PREDICTOR
    if _DEFAULT_PREDICTOR is None:
        _DEFAULT_PREDICTOR = MLPredictor()
    return _DEFAULT_PREDICTOR


def predict_flow(features: Union[Dict[str, float], pd.DataFrame]) -> Dict[str, Any]:
    """
    Convenience function to predict on a feature dictionary or DataFrame.
    """
    predictor = get_predictor()
    return predictor.predict_flow(features)
