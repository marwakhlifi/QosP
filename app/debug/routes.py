from . import bp  

from flask import jsonify, request
import subprocess
from ..utils.decorators import login_required, admin_required

@bp.route('/info', methods=['POST'])
@admin_required
def get_debug_info():
    hgw_ip = "192.168.1.1"
    command = f"ssh admin@{hgw_ip} getDebugInformation -A"
    try:
        result = subprocess.check_output(command, shell=True)
        return f"<pre>{result.decode()}</pre>"
    except subprocess.CalledProcessError as e:
        return f"Error executing command: {e}"