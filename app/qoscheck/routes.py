from flask import Blueprint, request, jsonify, session, render_template, url_for
import threading
import queue
import subprocess
import os
import ipaddress
import re
import time
import psutil
import paramiko

from . import qos_bp

def parse_iperf_output(output):
    """Parse iperf output to extract metrics"""
    metrics = {
        'throughput': 0,
        'jitter': 0,
        'packet_loss': 0,
        'raw_output': output
    }
    
    # Throughput (Mbps)
    throughput_match = re.search(r'(\d+\.\d+)\s+Mbits/sec', output, re.MULTILINE)
    if throughput_match:
        metrics['throughput'] = float(throughput_match.group(1))
    
    # Jitter (ms) - only for UDP
    jitter_match = re.search(r'(\d+\.\d+)\s+ms', output, re.MULTILINE)
    if jitter_match:
        metrics['jitter'] = float(jitter_match.group(1))
    
    # Packet Loss (%) - improved for UDP
    loss_match = re.search(r'(\d+\.\d+)%', output, re.MULTILINE)
    if not loss_match:
        loss_match = re.search(r'(\d+)/\d+\s+\((\d+\.\d+)%\)', output, re.MULTILINE)
        if loss_match:
            metrics['packet_loss'] = float(loss_match.group(2))
    elif loss_match:
        metrics['packet_loss'] = float(loss_match.group(1))
    
    return metrics

def run_iperf_command(cmd, result_queue):
    try:
        print(f"Executing iPerf command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=60  # Timeout after 60 seconds
        )
        parsed = parse_iperf_output(result.stdout)
        print(f"iPerf command succeeded: Throughput={parsed['throughput']} Mbps, Jitter={parsed['jitter']} ms, Packet Loss={parsed['packet_loss']}%")
        result_queue.put(parsed)
    except subprocess.CalledProcessError as e:
        print(f"iPerf command failed: {e.stderr}")
        parsed = parse_iperf_output(e.stderr)
        parsed['error'] = True
        result_queue.put(parsed)
    except subprocess.TimeoutExpired as e:
        print(f"iPerf command timed out: {e.stderr}")
        parsed = {'throughput': 0, 'jitter': 0, 'packet_loss': 0, 'raw_output': str(e.stderr), 'error': True}
        result_queue.put(parsed)
    except Exception as e:
        print(f"Unexpected error in iPerf command: {e}")
        parsed = {'throughput': 0, 'jitter': 0, 'packet_loss': 0, 'raw_output': str(e), 'error': True}
        result_queue.put(parsed)

def run_iperf_server(port, server_process_list):
    try:
        iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
        if not os.path.exists(iperf_path):
            print(f"iperf3 executable not found at {iperf_path}")
            return None

        cmd = [iperf_path, "-s", "-p", str(port)]
        print(f"Starting iPerf server: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        server_process_list.append(process)
        time.sleep(1)
        if process.poll() is not None:
            print(f"Server failed to start: {process.stderr.read()}")
            return None
        return process
    except Exception as e:
        print(f"Error starting iPerf server: {e}")
        return None

def terminate_server_processes(server_process_list):
    for process in server_process_list:
        try:
            parent = psutil.Process(process.pid)
            for child in parent.children(recursive=True):
                child.terminate()
            parent.terminate()
            process.terminate()
            process.wait(timeout=5)
            print(f"Terminated server process {process.pid}")
        except Exception as e:
            print(f"Error terminating server process {process.pid}: {e}")
    server_process_list.clear()

@qos_bp.route('/queuing')
def queuing():
    return render_template('queuing.html')

@qos_bp.route('/qostype')
def qostype():
    return render_template('qostype.html')

@qos_bp.route('/queuingresult')
def queuingresult():
    results = session.get('iperf_results', [])
    
    chart_data = {
        'types': [],
        'throughputs': [],
        'jitters': [],
        'packet_losses': [],
        'colors': {
            'VO': '#3b82f6',
            'VI': '#8b5cf6',
            'BK': '#64748b',
            'BE': '#94a3b8'
        }
    }
    
    for result in results:
        chart_data['types'].append(result['type'])
        chart_data['throughputs'].append(result['metrics']['throughput'])
        chart_data['jitters'].append(result['metrics']['jitter'])
        chart_data['packet_losses'].append(result['metrics']['packet_loss'])
    
    return render_template('queuingresult.html', 
                         results=results, 
                         chart_data=chart_data)

@qos_bp.route('/run_queuing_test', methods=['POST'])
def run_queuing_test():
    data = request.get_json()
    print(f"Received data: {data}")

    # Extract input data
    server_ip = data.get('serverIp')
    client_ip = data.get('clientIp')
    duration = data.get('duration')
    server_control = data.get('serverControl', 'manual')
    remote_server_ip = data.get('remoteServerIp')
    ssh_username = data.get('sshUsername')
    ssh_password = data.get('sshPassword')

    # Validate basic inputs
    if not server_ip or not client_ip or not duration:
        return jsonify({"status": "error", "message": "Server IP, Client IP, and duration are required"}), 400

    try:
        duration = int(duration)
        if duration < 2 or duration > 3000:
            return jsonify({"status": "error", "message": "Duration must be between 2 and 3000 seconds"}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid duration format"}), 400

    # Get flow configurations
    flows = []
    for flow_type in ['VO', 'VI', 'BK', 'BE']:
        flow_data = data.get(flow_type, {})
        if flow_data:
            flows.append({
                'type': flow_type,
                'port': flow_data.get('port'),
                'dscp': flow_data.get('dscp', '0'),
                'protocol': flow_data.get('protocol', 'tcp').lower()
            })

    if len(flows) != 4:
        return jsonify({"status": "error", "message": "Configuration for all 4 flows (VO, VI, BK, BE) is required"}), 400

    # Validate ports
    for flow in flows:
        port = flow['port']
        if not port or not str(port).isdigit() or int(port) < 1 or int(port) > 65535:
            return jsonify({"status": "error", "message": f"Invalid port for {flow['type']} flow: must be a number between 1 and 65535"}), 400

    # Ensure all ports are different
    ports = [flow['port'] for flow in flows]
    if len(set(ports)) != 4:
        return jsonify({"status": "error", "message": "All flow ports must be different"}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

    # Check iperf3 executable permissions
    if not os.access(iperf_path, os.X_OK):
        print(f"iPerf3 executable at {iperf_path} is not executable")
        return jsonify({"status": "error", "message": f"iPerf3 executable at {iperf_path} is not executable"}), 500

    # Check if IP is IPv6
    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def build_iperf_command(flow):
        cmd = [iperf_path]
        if is_ipv6(server_ip) or is_ipv6(client_ip):
            cmd.append("-6")
        cmd.extend(["-c", server_ip, "-p", str(flow['port']), "-S", str(flow['dscp'])])
        if flow['protocol'] == "udp":
            cmd.append("-u")
            cmd.extend(["-b", "10M"])
        cmd.extend(["-t", str(duration), "-i", "1"])
        return cmd

    server_process_list = []
    ssh_client = None
    if server_control == 'ssh':
        # Validate SSH inputs
        if not remote_server_ip or not ssh_username or not ssh_password:
            return jsonify({"status": "error", "message": "Remote Server IP, SSH Username, and SSH Password are required for SSH control"}), 400

        # Verify SSH connectivity
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"Verifying SSH connectivity to {remote_server_ip}")
            ssh_client.connect(
                hostname=remote_server_ip,
                username=ssh_username,
                password=ssh_password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            print(f"SSH connectivity verified to {remote_server_ip}")
        except Exception as e:
            print(f"SSH connection failed: {e}")
            if ssh_client:
                ssh_client.close()
            return jsonify({"status": "error", "message": f"Failed to verify SSH connectivity: {str(e)}"}), 500

        # Threaded server startup via SSH
        REMOTE_IPERF_PATH = "/usr/bin/iperf3"  # Adjust if needed
        def start_ssh_server_thread(port, flow_type, server_process_list, ssh_client):
            try:
                # Check if port is free
                check_cmd = f"ss -tuln | grep :{port} || echo 'Port free'"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                check_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode()
                if 'Port free' not in check_output:
                    print(f"Port {port} is already in use on {remote_server_ip} for {flow_type}: {check_output}")
                    return None

                # Start iPerf3 server
                cmd = f"{REMOTE_IPERF_PATH} -s -p {port} --daemon"
                print(f"Starting iPerf server on remote host {remote_server_ip} for {flow_type} on port {port}: {cmd}")
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                stderr_output = stderr.read().decode().strip()
                time.sleep(3)  # Increased to ensure server starts
                if stderr_output:
                    print(f"Error starting iPerf server on port {port} for {flow_type}: {stderr_output}")
                    return None
                # Get PID
                pid_cmd = f"pgrep -f 'iperf3.*-p {port}'"
                stdin, stdout, stderr = ssh_client.exec_command(pid_cmd)
                pid = stdout.read().decode().strip()
                if not pid.isdigit():
                    print(f"Failed to get PID for iPerf server on port {port} for {flow_type}: {stderr.read().decode()}")
                    return None
                print(f"iPerf server started with PID {pid} on port {port} for {flow_type}")
                server_process_list.append((ssh_client, pid))
                return pid
            except Exception as e:
                print(f"Error starting iPerf server on port {port} for {flow_type}: {e}")
                return None

        # Start servers in parallel
        server_threads = []
        for flow in flows:
            thread = threading.Thread(
                target=start_ssh_server_thread,
                args=(flow['port'], flow['type'], server_process_list, ssh_client)
            )
            server_threads.append(thread)
            thread.start()

        # Wait for all server threads to complete
        for thread in server_threads:
            thread.join()

        # Check if all servers started
        if len(server_process_list) != 4:
            print(f"Failed to start all iPerf servers: only {len(server_process_list)} started")
            if ssh_client:
                for _, pid in server_process_list:
                    try:
                        ssh_client.exec_command(f"kill -9 {pid}")
                        print(f"Terminated iPerf server with PID {pid}")
                    except Exception as e:
                        print(f"Error killing PID {pid}: {e}")
                ssh_client.close()
            return jsonify({"status": "error", "message": f"Failed to start all iPerf servers: only {len(server_process_list)} of 4 started"}), 500

    else:
        # Manual mode
        print(f"Manual server control: assuming iPerf3 servers are running on {server_ip} at ports {', '.join(str(flow['port']) for flow in flows)}")

    # Launch clients in parallel
    result_queues = [queue.Queue() for _ in range(4)]
    client_threads = []

    for i, flow in enumerate(flows):
        cmd = build_iperf_command(flow)
        print(f"Preparing client command for {flow['type']} flow: {' '.join(cmd)}")
        thread = threading.Thread(
            target=run_iperf_command,
            args=(cmd, result_queues[i])
        )
        client_threads.append(thread)
        thread.start()

    # Wait for all client threads to complete with timeout
    timeout = duration + 10  # Allow extra time
    start_time = time.time()
    for thread in client_threads:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            break
        thread.join(remaining)

    # Check if all clients returned results
    results = []
    for i, flow in enumerate(flows):
        try:
            if not result_queues[i].empty():
                metrics = result_queues[i].get_nowait()
                print(f"Collected results for {flow['type']}: Throughput={metrics['throughput']} Mbps, Jitter={metrics['jitter']} ms, Packet Loss={metrics['packet_loss']}%")
                results.append({
                    "type": flow['type'],
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "port": flow['port'],
                    "dscp": flow['dscp'],
                    "protocol": flow['protocol'],
                    "metrics": metrics
                })
            else:
                print(f"No results for {flow['type']} flow: client may have failed or timed out")
                results.append({
                    "type": flow['type'],
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "port": flow['port'],
                    "dscp": flow['dscp'],
                    "protocol": flow['protocol'],
                    "metrics": {
                        "throughput": 0,
                        "jitter": 0,
                        "packet_loss": 0,
                        "raw_output": "Client failed to return results",
                        "error": True
                    }
                })
        except Exception as e:
            print(f"Error retrieving results for {flow['type']}: {e}")
            results.append({
                "type": flow['type'],
                "client_ip": client_ip,
                "server_ip": server_ip,
                "port": flow['port'],
                "dscp": flow['dscp'],
                "protocol": flow['protocol'],
                "metrics": {
                    "throughput": 0,
                    "jitter": 0,
                    "packet_loss": 0,
                    "raw_output": f"Error retrieving results: {str(e)}",
                    "error": True
                }
            })

    # Cleanup SSH servers
    if server_control == 'ssh' and ssh_client:
        for _, pid in server_process_list:
            try:
                ssh_client.exec_command(f"kill -9 {pid}")
                print(f"Terminated iPerf server with PID {pid}")
            except Exception as e:
                print(f"Error killing PID {pid}: {e}")
        ssh_client.close()

    # Store results and redirect
    session["iperf_results"] = results
    print("Stored results in session, redirecting to queuingresult")
    return jsonify({
        "status": "success",
        "redirect_url": url_for('qos.queuingresult')
    })
