from flask import Response, render_template, request, jsonify, stream_with_context
import subprocess
import platform
from . import traceroute_bp

@traceroute_bp.route('/traceroute')
def traceroute_page():
    return render_template('traceroute.html')

@traceroute_bp.route('/api/traceroute', methods=['POST'])
def run_traceroute():
    data = request.get_json()
    target = data.get('target')
    
    if not target:
        return jsonify({'error': 'Target host is required'}), 400
    
    if platform.system().lower() == "windows":
        command = ['tracert', target]
    else:
        command = ['traceroute', target]
    
    def generate():
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            for line in iter(process.stdout.readline, ''):
                yield f"data: {line}\n\n"
                
            process.stdout.close()
            return_code = process.wait()
            
            if return_code != 0:
                error_msg = process.stderr.read()
                yield f"data: ERROR: {error_msg}\n\n"
                
        except Exception as e:
            yield f"data: ERROR: {str(e)}\n\n"
        finally:
            yield "data: END_OF_STREAM\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')
