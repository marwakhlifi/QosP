from flask import Blueprint
from .. import socketio  # Import global socketio

sniffing_bp = Blueprint('sniffing', __name__, template_folder='../../templates')

def init_app(app):
    """Initialize sniffing module (import routes)"""
    # Import routes after app initialization to avoid circular imports
    from . import routes    