from flask import request, jsonify
from . import ssh_bp
import paramiko
import subprocess
import os
import json
from flask import session, jsonify
import logging





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





# Configure logging (ensure this is in your file or app setup)
logging.basicConfig(
    filename='flask.log',
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s: %(message)s'
)


@ssh_bp.route('/close_ssh_session', methods=['POST'])
def close_ssh_session():
    logging.info("Received request to close SSH session")
    
    # Get SSH session from Flask session
    ssh_session = session.get('ssh_session', None)

    # If no session or not active, return success
    if not ssh_session or not ssh_session.get('ssh_client_active', False):
        logging.info("No active SSH session to close")
        session.pop('ssh_session', None)
        return jsonify({"status": "success", "message": "SSH session closed successfully"}), 200

    try:
        # Get server process list from session
        server_process_list = ssh_session.get('server_process_list', [])
        if not server_process_list:
            logging.info("No server processes to terminate")
            session.pop('ssh_session', None)
            return jsonify({"status": "success", "message": "SSH session closed successfully"}), 200

        # Attempt to terminate each process
        for ssh_client, pid in server_process_list:
            try:
                # Check if SSH client is still active
                if ssh_client and ssh_client.get_transport() and ssh_client.get_transport().is_active():
                    cmd = f"kill -9 {pid}"
                    logging.info(f"Terminating iPerf server process {pid}")
                    stdin, stdout, stderr = ssh_client.exec_command(cmd)
                    stdout.read()  # Wait for command to complete
                    stderr_output = stderr.read().decode()
                    if stderr_output:
                        logging.warning(f"Error during termination of PID {pid}: {stderr_output}")
                    ssh_client.close()
                    logging.info(f"Closed SSH connection for PID {pid}")
                else:
                    logging.info(f"SSH connection for PID {pid} is already closed or invalid")
            except Exception as e:
                logging.error(f"Error terminating PID {pid}: {e}")
                # Continue to next PID to ensure all are attempted

        # Clear session data
        session.pop('ssh_session', None)
        logging.info("SSH session closed successfully")
        return jsonify({"status": "success", "message": "SSH session closed successfully"}), 200

    except Exception as e:
        logging.error(f"Unexpected error closing SSH session: {e}")
        # Clear session to prevent stuck state
        session.pop('ssh_session', None)
        return jsonify({"status": "success", "message": "SSH session closed successfully"}), 200
    