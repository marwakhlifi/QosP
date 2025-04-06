from flask import Blueprint

bp = Blueprint('auto', __name__, template_folder='../../templates')

from . import routes
