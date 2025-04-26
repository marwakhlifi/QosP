from flask import render_template, request, jsonify
import subprocess
import platform
from . import ping_bp

@ping_bp.route('/ping')
def ping_page():
    return render_template('ping.html')

@ping_bp.route('/network')
def network_page():
    return render_template('network.html')

@ping_bp.route('/api/ping', methods=['POST'])
def ping_host():
    data = request.get_json()
    host = data.get('host')
    count = data.get('count', 4)
    
    if not host:
        return jsonify({'error': 'Host is required'}), 400
    
    try:
        count = int(count)
    except ValueError:
        return jsonify({'error': 'Count must be a number'}), 400
    
    if platform.system().lower() == "windows":
        command = ['ping', '-n', str(count), host]
    else:
        command = ['ping', '-c', str(count), host]
    
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return jsonify({'result': result.stdout})
        else:
            return jsonify({'error': result.stderr or "Ping failed"}), 400
            
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Ping request timed out'}), 408
    except Exception as e:
        return jsonify({'error': str(e)}), 500