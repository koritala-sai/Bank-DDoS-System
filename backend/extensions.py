"""
Bank DDoS Detection System - Extensions

Initializes shared Flask extensions to avoid circular import issues.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS

db = SQLAlchemy()
cors = CORS()
