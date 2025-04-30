import socket
import time
from flask import Blueprint, jsonify
import pexpect

from . import validation_bp 

def simple_telnet(host, port, username, password, command, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        
        def read_until(pattern):
            data = b""
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if pattern in data:
                    break
            return data
        
        # Login 
        read_until(b"login: ")
        s.send(username.encode() + b"\n")
        
        read_until(b"Password: ")
        s.send(password.encode() + b"\n")
        
        # Waiiing
        read_until(b"#")
        
        # Send commandd
        s.send(command.encode() + b"\n")
        
        # Get output
        output = read_until(b"#").decode('utf-8')
        
        s.close()
        return output.split('\n')[1:-1]  
    
    except Exception as e:
        raise Exception(f"Telnet error: {str(e)}")

@validation_bp.route('/test_telnet', methods=['POST'])
def test_telnet():
    try:
        output = simple_telnet(
            host="192.168.1.1",
            port=23,
            username="root",
            password="sah",
            command="wlctl -i wl0 pktq_stats"
        )
        return jsonify({'status': 'success', 'output': output})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    
