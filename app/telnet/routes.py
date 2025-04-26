from flask import Blueprint, jsonify, request,render_template
import socket
import time

from . import telnet_bp 

def simple_telnet(host, port, username, password, command, timeout=5):
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        
        # Helper function to read until pattern
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
        
        read_until(b"login: ")
        s.send(username.encode() + b"\n")
        
        read_until(b"Password: ")
        s.send(password.encode() + b"\n")
        
        read_until(b"#")
        
        
        
    
    except socket.timeout:
        raise Exception("Connection timed out")
    except ConnectionRefusedError:
        raise Exception("Connection refused - check if Telnet is enabled on the target")
    except Exception as e:
        raise Exception(f"Telnet error: {str(e)}")

@telnet_bp.route('/test_telnet', methods=['POST'])
def test_telnet():
    data = request.get_json()
    try:
        output = simple_telnet(
            host=data.get('host'),
            port=data.get('port', 23),
            username=data.get('username'),
            password=data.get('password'),
        )
        return jsonify({
            'status': 'success',
            'output': output,
            'message': 'Telnet connection successful'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@telnet_bp.route('/telnet_test_page')
def telnet_test_page():
    return render_template('telnet.html')


