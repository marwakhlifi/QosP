# app/qoscheck/routes.py
from flask import Blueprint, request, jsonify, session, render_template, url_for
import threading
import queue
import subprocess
import os
import ipaddress
import re  

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
    throughput_match = re.search(r'(\d+\.\d+)\s+Mbits/sec', output)
    if throughput_match:
        metrics['throughput'] = float(throughput_match.group(1))
    
    # Jitter (ms) - only for UDP
    jitter_match = re.search(r'(\d+\.\d+)\s+ms', output)
    if jitter_match:
        metrics['jitter'] = float(jitter_match.group(1))
    
    # Packet Loss (%)
    loss_match = re.search(r'(\d+\.\d+)%', output)
    if loss_match:
        metrics['packet_loss'] = float(loss_match.group(1))
    
    return metrics

def run_iperf_command(cmd, result_queue):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        parsed = parse_iperf_output(result.stdout)
        result_queue.put(parsed)
    except subprocess.CalledProcessError as e:
        parsed = parse_iperf_output(e.stderr)
        parsed['error'] = True
        result_queue.put(parsed)

@qos_bp.route('/queuing')
def queuing():
    return render_template('queuing.html')

@qos_bp.route('/qostype')
def qostype():
    return render_template('qostype.html')

@qos_bp.route('/queuingresult')
def queuingresult():
    results = session.get('iperf_results', [])
    
    # Prepare data for charts
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

    server_ip = data.get('serverIp')
    client_ip = data.get('clientIp')
    duration = data.get('duration')

    if not server_ip or not client_ip or not duration:
        return jsonify({"status": "error", "message": "Server IP, Client IP and duration are required"}), 400

    # Get flow configurations
    flows = []
    for flow_type in ['VO', 'VI', 'BK', 'BE']:
        flow_data = data.get(flow_type, {})
        if flow_data:
            flows.append({
                'type': flow_type,
                'port': flow_data.get('port'),
                'dscp': flow_data.get('dscp'),
                'protocol': flow_data.get('protocol', 'tcp').lower()
            })

    if len(flows) != 4:
        return jsonify({"status": "error", "message": "Configuration for all 4 flows is required"}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

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
            cmd.extend(["-b", "10M"])  # Add bandwidth limit for UDP tests
        cmd.extend(["-t", str(duration), "-i", "1"])
        return cmd

    # Create queues and threads for each flow
    result_queues = [queue.Queue() for _ in range(4)]
    threads = []

    for i, flow in enumerate(flows):
        cmd = build_iperf_command(flow)
        print(f"Running command for {flow['type']} flow: {' '.join(cmd)}")
        thread = threading.Thread(
            target=run_iperf_command,
            args=(cmd, result_queues[i])
        )
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect results
    results = []
    for i, flow in enumerate(flows):
        metrics = result_queues[i].get()
        results.append({
            "type": flow['type'],
            "client_ip": client_ip,
            "server_ip": server_ip,
            "port": flow['port'],
            "dscp": flow['dscp'],
            "protocol": flow['protocol'],
            "metrics": metrics  # Changed from 'result' to 'metrics'
        })

    session["iperf_results"] = results
    return jsonify({
        "status": "success",
        "redirect_url": url_for('qos.queuingresult')
    })
