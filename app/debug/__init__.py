from flask import Blueprint

bp = Blueprint('debug', __name__)

from app.debug import routes