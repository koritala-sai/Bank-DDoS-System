"""
Bank DDoS Detection System - Flask Application Entry Point

Module 3: Flask Backend, MySQL Database & REST APIs
Provides REST API endpoints for:
- System health and database connectivity (/api/health)
- Real-time ML inference with validated 20 features (/api/predict)
- Network flow ingestion and historical queries (/api/traffic)
- Security alerts management (/api/alerts)
- Real-time dashboard aggregated telemetry (/api/dashboard/summary)
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, jsonify

# Add backend and project root directories to Python module search path
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import config_by_name
from extensions import db, cors
from routes import register_routes
# Import models to ensure they are registered with SQLAlchemy metadata
import models  # noqa: F401

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("backend.app")


def create_app(config_name=None):
    """
    Application Factory Pattern for creating Flask app instances.

    Args:
        config_name (str, optional): Environment name ('development', 'testing', 'production').

    Returns:
        Flask: Initialized Flask application.
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    config_class = config_by_name.get(config_name, config_by_name['default'])
    app.config.from_object(config_class)

    # Initialize CORS
    cors.init_app(app, resources={r"/api/*": {"origins": "*"}})

    # Initialize Database
    db.init_app(app)

    # Register Blueprints
    register_routes(app)

    # Safe database table initialization (does not drop existing data)
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database schema verified and tables initialized.")
        except Exception as db_err:
            logger.warning(
                f"Database initialization deferred (MySQL may be offline or credentials unconfigured): {db_err}. "
                "Backend started in degraded mode; /api/health and /api/predict remain functional."
            )

    # Global Error Handlers
    @app.errorhandler(400)
    def handle_bad_request(error):
        return jsonify({
            "status": "error",
            "error_code": 400,
            "message": getattr(error, 'description', "Bad request syntax or parameter.")
        }), 400

    @app.errorhandler(404)
    def handle_not_found(error):
        return jsonify({
            "status": "error",
            "error_code": 404,
            "message": "Requested endpoint or resource was not found."
        }), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return jsonify({
            "status": "error",
            "error_code": 405,
            "message": "HTTP method not allowed for this endpoint."
        }), 405

    @app.errorhandler(500)
    def handle_internal_server_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({
            "status": "error",
            "error_code": 500,
            "message": "An internal server error occurred."
        }), 500

    return app


# Default application instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = app.config.get('DEBUG', False)
    logger.info(f"Starting Bank DDoS Detection System backend on port {port}...")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
