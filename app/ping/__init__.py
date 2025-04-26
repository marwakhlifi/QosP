from flask import Blueprint

ping_bp = Blueprint('ping', __name__, template_folder='../../templates')

from . import routes