from flask import Blueprint

nslookup_bp = Blueprint('nslookup', __name__, template_folder='../../templates')

from . import routes