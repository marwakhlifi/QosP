from flask import Blueprint

iperf_bp = Blueprint('iperf', __name__)

from . import routes
