from flask import Blueprint

bp = Blueprint('auth', __name__, template_folder='../../templates')

# Import routes at the END to avoid circular import
import app.auth.routes
