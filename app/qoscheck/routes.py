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
    """Parse iPerf output to extract metrics, per-second data, and summary."""
    metrics = {
        'throughput': 0,
        'jitter': 0,
        'packet_loss': 0,
        'raw_output': output
    }
    per_second = []
    summary = {}

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

    # Per-second data (e.g., [  4]   0.00-1.00   sec  1.25 MBytes  10.5 Mbits/sec)
    per_second_matches = re.findall(
        r'\[\s*\d+\]\s+(\d+\.\d+)-(\d+\.\d+)\s+sec\s+([\d\.]+\s+\w+)\s+(\d+\.\d+)\s+Mbits/sec',
        output, re.MULTILINE
    )
    for match in per_second_matches:
        per_second.append({
            'start': float(match[0]),
            'end': float(match[1]),
            'transfer': match[2],
            'bandwidth': float(match[3])
        })

    # Summary (e.g., [  4]   0.00-10.00  sec  12.5 MBytes  10.5 Mbits/sec)
    summary_match = re.search(
        r'\[\s*\d+\]\s+(\d+\.\d+)-(\d+\.\d+)\s+sec\s+([\d\.]+\s+\w+)\s+(\d+\.\d+)\s+Mbits/sec\s*(?:sender|receiver)?$',
        output, re.MULTILINE
    )
    if summary_match:
        summary = {
            'duration': float(summary_match.group(2)) - float(summary_match.group(1)),
            'transfer': summary_match.group(3),
            'bandwidth': float(summary_match.group(4))
        }

    return metrics, per_second, summary

def run_iperf_command(cmd, result_queue, delay=0):
    """Run iPerf command after specified delay."""
    try:
        if delay > 0:
            print(f"Delaying iPerf command by {delay} seconds: {' '.join(cmd)}")
            time.sleep(delay)
        print(f"Executing iPerf command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )
        metrics, per_second, summary = parse_iperf_output(result.stdout)
        print(f"iPerf command succeeded: Throughput={metrics['throughput']} Mbps, Jitter={metrics['jitter']} ms, Packet Loss={metrics['packet_loss']}%")
        result_queue.put((metrics, per_second, summary))
    except subprocess.CalledProcessError as e:
        print(f"iPerf command failed: {e.stderr}")
        metrics, per_second, summary = parse_iperf_output(e.stderr)
        metrics['error'] = True
        result_queue.put((metrics, per_second, summary))
    except subprocess.TimeoutExpired as e:
        print(f"iPerf command timed out: {e.stderr}")
        metrics = {'throughput': 0, 'jitter': 0, 'packet_loss': 0, 'raw_output': str(e.stderr), 'error': True}
        result_queue.put((metrics, [], None))
    except Exception as e:
        print(f"Unexpected error in iPerf command: {e}")
        metrics = {'throughput': 0, 'jitter': 0, 'packet_loss': 0, 'raw_output': str(e), 'error': True}
        result_queue.put((metrics, [], None))

def run_iperf_server(port, server_process_list):
    """Start iPerf server on specified port."""
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
    """Terminate all iPerf server processes."""
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

def analyze_prioritization(test_config, iperf_results):
    """Analyze iPerf results to verify traffic prioritization based on DSCP values."""
    prioritization_results = []
    traffic_classes = [cls for cls in ['VO', 'VI', 'BK', 'BE'] if cls in test_config]
    
    # Sort traffic classes by DSCP value (descending) to determine priority order
    traffic_priority = sorted(
        [(cls, int(test_config[cls]['dscp'])) for cls in traffic_classes],
        key=lambda x: x[1],
        reverse=True
    )
    
    # Parse iPerf results for each traffic class
    parsed_results = {}
    for cls in traffic_classes:
        metrics, per_second, summary = parse_iperf_output(iperf_results.get(cls, ""))
        parsed_results[cls] = {
            "per_second": per_second,
            "summary": summary,
            "delay": float(test_config[cls].get('delay', 0)),
            "duration": float(test_config['duration']),
            "data_size": float(test_config[cls].get('dataSize', 0))
        }
    
    # Analyze prioritization for each lower-priority traffic
    for i in range(1, len(traffic_priority)):
        lower_cls, lower_dscp = traffic_priority[i]
        lower_data = parsed_results.get(lower_cls)
        if not lower_data:
            continue
        
        # Get baseline bandwidth (average of first few seconds before any higher-priority traffic)
        baseline_seconds = min(5, len(lower_data['per_second']))  # Use first 5 seconds or less
        baseline_bandwidth = sum(
            entry['bandwidth'] for entry in lower_data['per_second'][:baseline_seconds]
        ) / baseline_seconds if baseline_seconds > 0 else lower_data['summary'].get('bandwidth', 0)
        
        for j in range(i):
            higher_cls, higher_dscp = traffic_priority[j]
            higher_data = parsed_results.get(higher_cls)
            if not higher_data:
                continue
            
            # Determine overlap period
            higher_start = higher_data['delay']
            higher_end = higher_start + higher_data['duration']
            lower_start = lower_data['delay']
            lower_end = lower_start + lower_data['duration']
            
            overlap_start = max(lower_start, higher_start)
            overlap_end = min(lower_end, higher_end)
            
            if overlap_start >= overlap_end:
                continue  # No overlap
            
            # Convert to iPerf line indices (1-second intervals)
            overlap_start_idx = int(overlap_start - lower_start)
            overlap_end_idx = int(overlap_end - lower_start)
            
            # Calculate average bandwidth during overlap
            overlap_bandwidth = 0
            overlap_count = 0
            for entry in lower_data['per_second']:
                if overlap_start_idx <= entry['start'] < overlap_end_idx:
                    overlap_bandwidth += entry['bandwidth']
                    overlap_count += 1
            
            avg_overlap_bandwidth = overlap_bandwidth / overlap_count if overlap_count > 0 else baseline_bandwidth
            
            # Expected reduction (approximate bandwidth of higher-priority traffic)
            higher_bandwidth = higher_data['data_size'] if higher_data['data_size'] > 0 else higher_data['summary'].get('bandwidth', 0)
            reduction = baseline_bandwidth - avg_overlap_bandwidth
            
            # Threshold: Reduction should be at least 10% of baseline or close to higher traffic's bandwidth
            min_reduction = max(0.1 * baseline_bandwidth, higher_bandwidth * 0.5)
            
            if reduction >= min_reduction:
                status = "success"
                message = f"{higher_cls} traffic (DSCP {higher_dscp}) is prioritized over {lower_cls} traffic (DSCP {lower_dscp})"
            else:
                status = "danger"
                message = f"{higher_cls} traffic (DSCP {higher_dscp}) is not prioritized over {lower_cls} traffic (DSCP {lower_dscp})"
            
            prioritization_results.append({
                "higher": higher_cls,
                "lower": lower_cls,
                "status": status,
                "message": message
            })
    
    return prioritization_results

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
    
    iperf_details = []
    for result in results:
        metrics, per_second, summary = parse_iperf_output(result['metrics'].get('raw_output', ''))
        chart_data['types'].append(result['type'])
        chart_data['throughputs'].append(metrics['throughput'])
        chart_data['jitters'].append(metrics['jitter'])
        chart_data['packet_losses'].append(metrics['packet_loss'])
        iperf_details.append({
            'type': result['type'],
            'port': result['port'],
            'dscp': result['dscp'],
            'per_second': per_second,
            'summary': summary
        })
    
    test_config = session.get('test_config', {})
    iperf_results = {result['type']: result['metrics']['raw_output'] for result in results}
    prioritization_results = analyze_prioritization(test_config, iperf_results)
    
    return render_template('queuingresult.html', 
                         results=results, 
                         chart_data=chart_data,
                         prioritization_results=prioritization_results,
                         iperf_details=iperf_details)

@qos_bp.route('/run_queuing_test', methods=['POST'])
def run_queuing_test():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip = data.get('clientIp')
    duration = data.get('duration')
    direction = data.get('direction', 'uplink')
    server_control = data.get('serverControl', 'manual')
    remote_server_ip = data.get('remoteServerIp')
    ssh_username = data.get('sshUsername')
    ssh_password = data.get('sshPassword')

    if not server_ip or not client_ip or not duration:
        return jsonify({"status": "error", "message": "Server IP, Client IP, and duration are required"}), 400

    try:
        duration = int(duration)
        if duration < 2 or duration > 3000:
            return jsonify({"status": "error", "message": "Duration must be between 2 and 3000 seconds"}), 400
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid duration format"}), 400

    if direction not in ['uplink', 'downlink']:
        return jsonify({"status": "error", "message": "Invalid direction: must be 'uplink' or 'downlink'"}), 400

    flows = []
    for flow_type in ['VO', 'VI', 'BK', 'BE']:
        flow_data = data.get(flow_type)
        if flow_data:
            try:
                delay = float(flow_data.get('delay', '0'))
                if delay < 0:
                    return jsonify({"status": "error", "message": f"Delay for {flow_type} must be non-negative"}), 400
                data_size = float(flow_data.get('dataSize', '0'))
                if data_size < 0:
                    return jsonify({"status": "error", "message": f"Data rate for {flow_type} must be non-negative"}), 400
            except ValueError:
                return jsonify({"status": "error", "message": f"Invalid delay or data rate format for {flow_type}"}), 400
            flows.append({
                'type': flow_type,
                'port': flow_data.get('port'),
                'dscp': flow_data.get('dscp', '0'),
                'protocol': flow_data.get('protocol', 'tcp').lower(),
                'delay': delay,
                'dataSize': data_size
            })

    if len(flows) == 0:
        return jsonify({"status": "error", "message": "At least one traffic class must be selected"}), 400

    for flow in flows:
        port = flow['port']
        if not port or not str(port).isdigit() or int(port) < 1 or int(port) > 65535:
            return jsonify({"status": "error", "message": f"Invalid port for {flow['type']} flow: must be a number between 1 and 65535"}), 400
        dscp = flow['dscp']
        if not str(dscp).isdigit() or int(dscp) < 0 or int(dscp) > 200:
            return jsonify({"status": "error", "message": f"Invalid DSCP for {flow['type']} flow: must be a number between 0 and 200"}), 400

    ports = [flow['port'] for flow in flows]
    if len(set(ports)) != len(ports):
        return jsonify({"status": "error", "message": "All flow ports must be different"}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

    if not os.access(iperf_path, os.X_OK):
        print(f"iPerf3 executable at {iperf_path} is not executable")
        return jsonify({"status": "error", "message": f"iPerf3 executable at {iperf_path} is not executable"}), 500

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
        if direction == "downlink":
            cmd.append("-R")
        if flow['protocol'] == "udp":
            cmd.append("-u")
            if flow['dataSize'] > 0:
                cmd.extend(["-b", f"{flow['dataSize']}M"])
            else:
                cmd.extend(["-b", "10M" if flow['type'] == 'VI' else "3M"])
        elif flow['dataSize'] > 0:
            cmd.extend(["-b", f"{flow['dataSize']}M"])
        cmd.extend(["-t", str(duration), "-i", "1"])
        return cmd

    server_process_list = []
    ssh_client = None
    if server_control == 'ssh':
        if not remote_server_ip or not ssh_username or not ssh_password:
            return jsonify({"status": "error", "message": "Remote Server IP, SSH Username, and SSH Password are required for SSH control"}), 400

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

        REMOTE_IPERF_PATH = "/usr/bin/iperf3"
        def start_ssh_server_thread(port, flow_type, server_process_list, ssh_client):
            try:
                check_cmd = f"ss -tuln | grep :{port} || echo 'Port free'"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                check_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode()
                if 'Port free' not in check_output:
                    print(f"Port {port} is already in use on {remote_server_ip} for {flow_type}: {check_output}")
                    return None

                cmd = f"{REMOTE_IPERF_PATH} -s -p {port} --daemon"
                print(f"Starting iPerf server on remote host {remote_server_ip} for {flow_type} on port {port}: {cmd}")
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                stderr_output = stderr.read().decode().strip()
                time.sleep(3)
                if stderr_output:
                    print(f"Error starting iPerf server on port {port} for {flow_type}: {stderr_output}")
                    return None
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

        server_threads = []
        for flow in flows:
            thread = threading.Thread(
                target=start_ssh_server_thread,
                args=(flow['port'], flow['type'], server_process_list, ssh_client)
            )
            server_threads.append(thread)
            thread.start()

        for thread in server_threads:
            thread.join()

        if len(server_process_list) != len(flows):
            print(f"Failed to start all iPerf servers: only {len(server_process_list)} started")
            if ssh_client:
                for _, pid in server_process_list:
                    try:
                        ssh_client.exec_command(f"kill -9 {pid}")
                        print(f"Terminated iPerf server with PID {pid}")
                    except Exception as e:
                        print(f"Error killing PID {pid}: {e}")
                ssh_client.close()
            return jsonify({"status": "error", "message": f"Failed to start all iPerf servers: only {len(server_process_list)} of {len(flows)} started"}), 500

    else:
        print(f"Manual server control: assuming iPerf3 servers are running on {server_ip} at ports {', '.join(str(flow['port']) for flow in flows)}")

    result_queues = [queue.Queue() for _ in range(len(flows))]
    client_threads = []
    delays = [flow['delay'] for flow in flows]
    min_delay = min([d for d in delays if d > 0], default=0)

    for i, flow in enumerate(flows):
        cmd = build_iperf_command(flow)
        print(f"Preparing client command for {flow['type']} flow with delay {flow['delay']}s: {' '.join(cmd)}")
        thread = threading.Thread(
            target=run_iperf_command,
            args=(cmd, result_queues[i], flow['delay'])
        )
        client_threads.append(thread)
        thread.start()

    timeout = duration + max(delays, default=0) + 10
    start_time = time.time()
    for thread in client_threads:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            print("Client thread timeout reached")
            break
        thread.join(remaining)

    results = []
    for i, flow in enumerate(flows):
        try:
            if not result_queues[i].empty():
                metrics, per_second, summary = result_queues[i].get_nowait()
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

    if server_control == 'ssh' and ssh_client:
        for _, pid in server_process_list:
            try:
                ssh_client.exec_command(f"kill -9 {pid}")
                print(f"Terminated iPerf server with PID {pid}")
            except Exception as e:
                print(f"Error killing PID {pid}: {e}")
        ssh_client.close()

    session["iperf_results"] = results
    session["test_config"] = data
    print("Stored results in session, redirecting to queuingresult")
    return jsonify({
        "status": "success",
        "redirect_url": url_for('qos.queuingresult')
    })

@qos_bp.route('/close_ssh_session', methods=['POST'])
def close_ssh_session():
    return jsonify({"status": "success", "message": "SSH session closed (placeholder)"})