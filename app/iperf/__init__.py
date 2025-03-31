from flask import Blueprint

iperf_bp = Blueprint('iperf', __name__, template_folder='../../templates')

from . import routes
