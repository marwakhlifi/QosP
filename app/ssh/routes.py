from flask import request, jsonify
from . import ssh_bp
import paramiko
import subprocess
import os
import json

# Chemin du fichier JSON pour stocker l'historique
HISTORY_FILE = 'ssh_history.json'

def load_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    return []

def test_ssh_connectivity(ip, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password, timeout=10)
        ssh.close()
        return True
    except Exception as e:
        print(f"SSH Connection Failed: {e}")
        return False

@ssh_bp.route('/test_ssh', methods=['POST'])
def test_ssh():
    data = request.get_json()
    server_ip = data.get('server_ip')
    server_username = data.get('server_username')
    server_password = data.get('server_password')
    clients = data.get('clients', [])

    if not all([server_ip, server_username, server_password]) or not clients:
        return jsonify({"status": "error", "message": "Missing credentials"}), 400

    server_test = test_ssh_connectivity(server_ip, server_username, server_password)
    client_tests = [test_ssh_connectivity(client['client_ip'], client['username'], client['password']) for client in clients]

    if server_test and all(client_tests):
        return jsonify({"status": "success", "message": "✅ SSH Connections Successful!"})
    else:
        failed_tests = []
        if not server_test:
            failed_tests.append("QoS Server")
        for i, client_test in enumerate(client_tests):
            if not client_test:
                failed_tests.append(f"Client {i + 1}")
        return jsonify({"status": "error", "message": f"❌ SSH Connection Failed for: {', '.join(failed_tests)}!"})

