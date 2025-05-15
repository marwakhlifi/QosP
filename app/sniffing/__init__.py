from flask import Blueprint
from flask_socketio import SocketIO

sniffing_bp = Blueprint('sniffing', __name__, template_folder='../../templates')
socketio = SocketIO()

def init_app(app):
    """Initialize SocketIO with the Flask app"""
    socketio.init_app(app)

from . import routes