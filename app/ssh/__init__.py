from flask import Blueprint

ssh_bp = Blueprint('ssh', __name__)

from . import routes
