"""
Bank DDoS Detection System - Backend Configuration

Loads configuration settings from environment variables with safe defaults.
Supports development, testing, and production environments.
"""

import os
from pathlib import Path
from urllib.parse import quote_plus
from dotenv import load_dotenv

# Base directory for resolving paths
BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent

# Load environment variables from .env in backend/ or project root
load_dotenv(BACKEND_DIR / ".env")
load_dotenv(PROJECT_ROOT / ".env")


def _build_mysql_uri(user: str, password: str, host: str, port: str, db: str) -> str:
    """
    Safely builds a MySQL SQLAlchemy URI by URL-encoding the username and password.
    This ensures special characters such as '@', ':', '/', '?' in credentials
    are correctly percent-encoded and do not break URI parsing.
    """
    encoded_user = quote_plus(user)
    encoded_password = quote_plus(password)
    return f"mysql+pymysql://{encoded_user}:{encoded_password}@{host}:{port}/{db}"


class Config:
    """Base Configuration Class."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'bank-ddos-default-dev-secret-key-change-in-prod')
    FLASK_ENV = os.environ.get('FLASK_ENV', 'development')
    DEBUG = os.environ.get('FLASK_DEBUG', '1') == '1'
    PORT = int(os.environ.get('PORT', 5000))

    # Database Configuration from Environment Variables
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '3306')
    DB_NAME = os.environ.get('DB_NAME', 'bank_ddos')
    DB_USER = os.environ.get('DB_USER', 'root')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', '')

    # Connection URI — use DATABASE_URL if explicitly provided, otherwise build it
    # safely with URL-encoded credentials to handle special characters (e.g. '@' in password).
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or _build_mysql_uri(
        user=os.environ.get('DB_USER', 'root'),
        password=os.environ.get('DB_PASSWORD', ''),
        host=os.environ.get('DB_HOST', 'localhost'),
        port=os.environ.get('DB_PORT', '3306'),
        db=os.environ.get('DB_NAME', 'bank_ddos'),
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_recycle': 280,
        'pool_timeout': 5,
        'connect_args': {'connect_timeout': 3}
    }


class DevelopmentConfig(Config):
    """Development Environment Specific Configuration."""
    DEBUG = True


class ProductionConfig(Config):
    """Production Environment Specific Configuration."""
    DEBUG = False


class TestingConfig(Config):
    """Testing Environment Specific Configuration using safe in-memory SQLite."""
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL', 'sqlite:///:memory:')
    SQLALCHEMY_ENGINE_OPTIONS = {}


# Environment Mapping
config_by_name = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
