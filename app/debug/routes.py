from . import bp
from flask import jsonify, request
from ..validation.routes import simple_telnet

from . import debug_bp

@debug_bp.route('/get_debug_info', methods=['POST'])
def get_debug_info():
    hgw_ip = "192.168.1.1"
    command = "getDebugInformation -A"
    try:
        # Use Telnet to execute the command
        output = simple_telnet(
            host=hgw_ip,
            port=23,
            username="root",
            password="sah",
            command=command
        )
        # Join output lines and wrap in <pre> tags
        result = "\n".join(output)
        return f"<pre>{result}</pre>"
    except Exception as e:
        return f"Error executing Telnet command: {str(e)}"
    