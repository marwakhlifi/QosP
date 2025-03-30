from flask import Blueprint

bp = Blueprint('auth', __name__)

# Import routes at the END to avoid circular import
import app.auth.routes
