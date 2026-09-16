"""
Bank DDoS Detection System - Routes Package

Registers all modular API blueprints.
"""

from flask import Flask
from .health import health_bp
from .prediction import prediction_bp
from .traffic import traffic_bp
from .alerts import alerts_bp


def register_routes(app: Flask):
    """Registers blueprints with the Flask application instance."""
    app.register_blueprint(health_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(traffic_bp)
    app.register_blueprint(alerts_bp)


__all__ = ["register_routes", "health_bp", "prediction_bp", "traffic_bp", "alerts_bp"]
