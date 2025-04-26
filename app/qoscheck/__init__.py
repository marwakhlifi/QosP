from flask import Blueprint

qos_bp = Blueprint('qos', __name__, template_folder='templates')

from . import routes

