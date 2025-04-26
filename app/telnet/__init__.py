from flask import Blueprint

telnet_bp = Blueprint('telnet', __name__, template_folder='../../templates')

from . import routes
