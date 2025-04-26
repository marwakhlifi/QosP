from flask import Blueprint

traceroute_bp = Blueprint('traceroute', __name__, template_folder='../../templates')

from . import routes
