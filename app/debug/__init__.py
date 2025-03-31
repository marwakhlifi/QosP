from flask import Blueprint

bp = Blueprint('debug', __name__, template_folder='../../templates')

from app.debug import routes