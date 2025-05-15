from flask import Blueprint

wmm_bp = Blueprint('vmm', __name__, template_folder='../../templates')

from . import routes
