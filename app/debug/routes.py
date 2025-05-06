from flask import render_template, jsonify, request
from . import debug_bp
import socket
import time
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def simple_telnet(host, port, username, password, command, timeout=15):
    try:
        logger.debug(f"Connecting to {host}:{port}")
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        
        # Helper function to read until pattern or no more data
        def read_until(pattern, max_timeout=timeout):
            data = b""
            start_time = time.time()
            while time.time() - start_time < max_timeout:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        logger.debug("No more data received, connection closed")
                        break
                    data += chunk
                    logger.debug(f"Received (raw): {data}")
                    logger.debug(f"Received (decoded): {data.decode('ascii', errors='ignore')}")
                    if pattern in data:
                        logger.debug(f"Found pattern {pattern.decode('ascii', errors='ignore')}")
                        return data
                except socket.timeout:
                    logger.debug("Socket timeout, checking for accumulated data")
                    if data:
                        logger.debug(f"Returning accumulated data: {data.decode('ascii', errors='ignore')}")
                        return data
                    continue
            logger.debug(f"No pattern {pattern.decode('ascii', errors='ignore')} found, returning data: {data.decode('ascii', errors='ignore')}")
            return data

        # Handle login
        logger.debug("Waiting for login prompt")
        read_until(b"login: ")
        logger.debug("Sending username")
        s.send(username.encode('ascii') + b"\n")
        
        # Handle password
        logger.debug("Waiting for password prompt")
        read_until(b"Password: ")
        logger.debug("Sending password")
        s.send(password.encode('ascii') + b"\n")
        
        # Wait for command prompt
        logger.debug("Waiting for command prompt")
        read_until(b"# ")
        
        # Send the command
        logger.debug(f"Sending command: {command}")
        s.send(command.encode('ascii') + b"\n")
        
        # Wait for command execution
        logger.debug("Waiting for command to execute")
        time.sleep(2)
        
        # Read all output until no more data
        logger.debug("Reading command output")
        output = read_until(b"# ", max_timeout=timeout).decode('ascii', errors='ignore')
        
        # Close the socket
        s.close()
        
        # Clean the output (remove echoed command and prompt)
        output_lines = output.split('\n')
        cleaned_output = '\n'.join(line for line in output_lines 
                                if not line.strip().startswith(command.strip()) 
                                and not line.strip().endswith('#'))
        
        logger.debug(f"Cleaned output: {cleaned_output}")
        return cleaned_output.strip()
    
    except socket.timeout as e:
        logger.error(f"Socket timeout: {str(e)}")
        raise Exception(f"Connection timed out: {str(e)}")
    except ConnectionRefusedError as e:
        logger.error(f"Connection refused: {str(e)}")
        raise Exception("Connection refused - check if Telnet is enabled on the target")
    except Exception as e:
        logger.error(f"Telnet error: {str(e)}", exc_info=True)
        raise Exception(f"Telnet error: {str(e)}")

@debug_bp.route('/get_debug_info', methods=['POST'])
def get_debug_info():
    try:
        logger.debug("Received request for /get_debug_info")
        # Execute telnet command
        output = simple_telnet(
            host='192.168.1.1',
            port=23,
            username='root',
            password='sah',
            command='getDebugInformation -A'
        )
        logger.debug("Telnet command executed successfully")
        return jsonify({
            'status': 'success',
            'debug_output': output
        })
    
    except Exception as e:
        logger.error(f"Error in get_debug_info: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'debug_output': f"Error retrieving debug info: {str(e)}"
        }), 500