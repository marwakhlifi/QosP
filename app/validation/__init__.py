from flask import Blueprint

validation_bp = Blueprint('validation', __name__, template_folder='../../templates')

from . import routes
