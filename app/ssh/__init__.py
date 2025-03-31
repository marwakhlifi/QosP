from flask import Blueprint

ssh_bp = Blueprint('ssh', __name__, template_folder='../../templates')

from . import routes
