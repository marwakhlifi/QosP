from flask import render_template, request, redirect, url_for, session, jsonify
from . import iperf_bp
import subprocess
import threading
import queue
import os
import json
import re
import ipaddress
import time


# Global queue to store iPerf results
iperf_result_queue = queue.Queue()

@iperf_bp.route('/index')
def index():
    selected_ip = request.args.get('ip')
    print(f"Selected IP: {selected_ip}")
    return render_template('index.html', selected_ip=selected_ip)

@iperf_bp.route('/index11')
def index11():
    return render_template('index11.html')

@iperf_bp.route('/index2')
def index2():
    return render_template('index2.html')

@iperf_bp.route('/index22')
def index22():
    return render_template('index22.html')

@iperf_bp.route('/index222')
def index222():
    return render_template('index222.html')

@iperf_bp.route('/index3')
def index3():
    result = session.get("iperf_result", "No results available.")
    telnet_result = session.get("telnet_result", "No telnet results available.")
    device_id = "ID_DU_DISPOSITIF"
    return render_template('index3.html', result=result, device_id=device_id)

@iperf_bp.route('/index33')
def index33():
    results = session.get("iperf_results", [])
    telnet_result = session.get("telnet_result", "No telnet results available.")
    
    return render_template('index33.html', results=results)

@iperf_bp.route('/index333')
def index333():
    results = session.get("iperf_results", [])
    telnet_result = session.get("telnet_result", "No telnet results available.")
    return render_template('index333.html', results=results)


def run_telnet_command(host="192.168.1.1", command="wlctl -i wl0 pktq_stats"):
    try:
        # Create a temporary script file
        script_content = f"""
open {host}
root
sah
{command}
exit
"""
        script_path = "telnet_script.txt"
        with open(script_path, "w", encoding='utf-8') as f:
            f.write(script_content)
        
        # Run telnet with the script
        result = subprocess.run(
            ["telnet", "-f", script_path],
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=15,
            shell=True  # Required for Windows
        )
        
        # Clean up
        os.remove(script_path)
        
        if result.returncode != 0:
            return f"Error: {result.stderr}"
        return result.stdout
        
    except subprocess.TimeoutExpired:
        return "Telnet command timed out"
    except Exception as e:
        return f"Telnet error: {str(e)}"
    
    
def run_iperf_command(cmd, result_queue):
    try:
        process = subprocess.run(cmd, capture_output=True, text=True)
        output = process.stdout
        print("===== iPerf3 Output =====")
        print(output)
        print("===== End of Output =====")
        if process.returncode == 0:
            result_queue.put(output)
        else:
            result_queue.put(process.stderr)
    except Exception as e:
        print(f"Error: {e}")
        result_queue.put(str(e))

@iperf_bp.route('/run_iperf', methods=['POST'])
def run_iperf():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip = data.get('clientIp')
    port = str(data.get('port'))
    dscp_tos = str(data.get('dscp', '0'))
    protocol = data.get('protocol', 'tcp')
    direction = data.get('direction')
    taille = data.get('taille')
    duration = data.get('duration')

    if not server_ip or not client_ip or not port.isdigit():
        return jsonify({"status": "error", "message": "Invalid input. Server and Client IPs and a valid port are required"}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

    # Check if IP is IPv6
    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    cmd = [iperf_path]
    if is_ipv6(server_ip) or is_ipv6(client_ip):
        cmd.append("-6")
    cmd.extend(["-c", server_ip, "-p", port, "-S", dscp_tos])
    
    if direction == "downlink":
        cmd.append("-R")
    if protocol == "udp":
        cmd.append("-u")
    if taille:
        cmd.extend(["-n", taille])
    if duration:
        cmd.extend(["-t", str(duration)])

    print(f"Running command: {' '.join(cmd)}")
    thread = threading.Thread(target=run_iperf_command, args=(cmd, iperf_result_queue))
    thread.start()
    thread.join()
    result = iperf_result_queue.get()
    telnet_result = run_telnet_command()
    session["iperf_result"] = result
    session["telnet_result"] = telnet_result
    return jsonify({"status": "success", "redirect_url": url_for('iperf.index3')})




@iperf_bp.route('/run_iperf_two_clients', methods=['POST'])
def run_iperf_two_clients():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip1 = data.get('clientIp1')
    client_ip2 = data.get('clientIp2')

    if not server_ip or not client_ip1 or not client_ip2:
        return jsonify({"status": "error", "message": "Invalid input. Server and Client IPs are required"}), 400

    port1 = str(data.get('port1'))
    if not port1 or not port1.isdigit():
        return jsonify({"status": "error", "message": "Invalid port for client 1"}), 400

    port2 = str(data.get('port2'))
    if not port2 or not port2.isdigit():
        return jsonify({"status": "error", "message": "Invalid port for client 2"}), 400

    dscp_tos1 = str(data.get('dscp1', '0'))
    protocol1 = data.get('protocol1', 'tcp')
    direction1 = data.get('direction1', 'uplink')
    taille1 = data.get('dataSize1')
    duration1 = data.get('duration1')

    dscp_tos2 = str(data.get('dscp2', '0'))
    protocol2 = data.get('protocol2', 'tcp')
    direction2 = data.get('direction2', 'uplink')
    taille2 = data.get('dataSize2')
    duration2 = data.get('duration2')

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def build_iperf_command(client_ip, port, dscp_tos, protocol, direction, taille, duration):
        cmd = [iperf_path]
        if is_ipv6(server_ip) or is_ipv6(client_ip):
            cmd.append("-6")
        cmd.extend(["-c", server_ip, "-p", port, "-S", dscp_tos])
        if direction == "downlink":
            cmd.append("-R")
        if protocol == "udp":
            cmd.append("-u")
        if taille:
            cmd.extend(["-n", taille])
        if duration:
            cmd.extend(["-t", str(duration)])
        cmd.extend(["-i", "1"])
        return cmd

    result_queue1 = queue.Queue()
    result_queue2 = queue.Queue()

    cmd1 = build_iperf_command(client_ip1, port1, dscp_tos1, protocol1, direction1, taille1, duration1)
    cmd2 = build_iperf_command(client_ip2, port2, dscp_tos2, protocol2, direction2, taille2, duration2)

    print(f"Running command for client 1: {' '.join(cmd1)}")
    print(f"Running command for client 2: {' '.join(cmd2)}")

    thread1 = threading.Thread(target=run_iperf_command, args=(cmd1, result_queue1))
    thread2 = threading.Thread(target=run_iperf_command, args=(cmd2, result_queue2))
    
    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()

    # Récupérer les résultats
    result1 = result_queue1.get()
    result2 = result_queue2.get()
    telnet_result = run_telnet_command()

    results = [
        {"client": "client1", "result": result1.replace('\n', '<br>')},
        {"client": "client2", "result": result2.replace('\n', '<br>')}
    ]

    session["iperf_results"] = results
    session["telnet_result"] = telnet_result
    return jsonify({"status": "success", "redirect_url": url_for('iperf.index33')})

@iperf_bp.route('/run_iperf_three_clients', methods=['POST'])
def run_iperf_three_clients():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip1 = data.get('clientIp1')
    client_ip2 = data.get('clientIp2')
    client_ip3 = data.get('clientIp3')

    if not server_ip or not client_ip1 or not client_ip2 or not client_ip3:
        return jsonify({"status": "error", "message": "Invalid input. Server and all Client IPs are required"}), 400

    port1 = str(data.get('port1'))
    if not port1 or not port1.isdigit():
        return jsonify({"status": "error", "message": "Invalid port for client 1"}), 400

    port2 = str(data.get('port2'))
    if not port2 or not port2.isdigit():
        return jsonify({"status": "error", "message": "Invalid port for client 2"}), 400

    port3 = str(data.get('port3'))
    if not port3 or not port3.isdigit():
        return jsonify({"status": "error", "message": "Invalid port for client 3"}), 400

    dscp_tos1 = str(data.get('dscp1', '0'))
    protocol1 = data.get('protocol1', 'tcp')
    direction1 = data.get('direction1', 'uplink')
    taille1 = data.get('dataSize1')
    duration1 = data.get('duration1')

    dscp_tos2 = str(data.get('dscp2', '0'))
    protocol2 = data.get('protocol2', 'tcp')
    direction2 = data.get('direction2', 'uplink')
    taille2 = data.get('dataSize2')
    duration2 = data.get('duration2')

    dscp_tos3 = str(data.get('dscp3', '0'))
    protocol3 = data.get('protocol3', 'tcp')
    direction3 = data.get('direction3', 'uplink')
    taille3 = data.get('dataSize3')
    duration3 = data.get('duration3')

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        return jsonify({"status": "error", "message": f"iperf3 executable not found at {iperf_path}"}), 500

    # Check if IP is IPv6
    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def build_iperf_command(client_ip, port, dscp_tos, protocol, direction, taille, duration):
        cmd = [iperf_path]
        if is_ipv6(server_ip) or is_ipv6(client_ip):
            cmd.append("-6")
        cmd.extend(["-c", server_ip, "-p", port, "-S", dscp_tos])
        if direction == "downlink":
            cmd.append("-R")
        if protocol == "udp":
            cmd.append("-u")
        if taille:
            cmd.extend(["-n", taille])
        if duration:
            cmd.extend(["-t", str(duration)])
        cmd.extend(["-i", "1"])
        return cmd

    result_queue1 = queue.Queue()
    result_queue2 = queue.Queue()
    result_queue3 = queue.Queue()

    cmd1 = build_iperf_command(client_ip1, port1, dscp_tos1, protocol1, direction1, taille1, duration1)
    cmd2 = build_iperf_command(client_ip2, port2, dscp_tos2, protocol2, direction2, taille2, duration2)
    cmd3 = build_iperf_command(client_ip3, port3, dscp_tos3, protocol3, direction3, taille3, duration3)

    print(f"Running command for client 1: {' '.join(cmd1)}")
    print(f"Running command for client 2: {' '.join(cmd2)}")
    print(f"Running command for client 3: {' '.join(cmd3)}")

    thread1 = threading.Thread(target=run_iperf_command, args=(cmd1, result_queue1))
    thread2 = threading.Thread(target=run_iperf_command, args=(cmd2, result_queue2))
    thread3 = threading.Thread(target=run_iperf_command, args=(cmd3, result_queue3))
    
    thread1.start()
    thread2.start()
    thread3.start()

    thread1.join()
    thread2.join()
    thread3.join()

    result1 = result_queue1.get()
    result2 = result_queue2.get()
    result3 = result_queue3.get()
    telnet_result = run_telnet_command()

    results = [
        {"client": "client1", "result": result1.replace('\n', '<br>')},
        {"client": "client2", "result": result2.replace('\n', '<br>')},
        {"client": "client3", "result": result3.replace('\n', '<br>')}
    ]

    session["iperf_results"] = results
    session["telnet_result"] = telnet_result
    return jsonify({"status": "success", "redirect_url": url_for('iperf.index333')})

def parse_iperf_output(output):
    pattern = re.compile(
        r'\[\s*\d+\]\s+(\d+\.\d+-\d+\.\d+)\s+sec\s+([\d.]+)\s+(MBytes|KBytes|GBytes)\s+([\d.]+)\s+(Mbits/sec|Kbits/sec|Gbits/sec)'
    )
    intervals = []
    bandwidths = []

    for line in output.splitlines():
        match = pattern.search(line)
        if match:
            interval = match.group(1)
            bandwidth = float(match.group(4))
            unit = match.group(5)
            if unit == "Gbits/sec":
                bandwidth *= 1000
            elif unit == "Kbits/sec":
                bandwidth /= 1000
            intervals.append(interval)
            bandwidths.append(bandwidth)

    return json.dumps({"intervals": intervals, "bandwidths": bandwidths})

def parse_iperf_output_multi(outputs):
    all_intervals = []
    all_bandwidths = []

    for output in outputs:
        intervals = []
        bandwidths = []
        pattern = re.compile(
            r'\[\s*\d+\]\s+(\d+\.\d+-\d+\.\d+)\s+sec\s+([\d.]+)\s+(MBytes|KBytes|GBytes)\s+([\d.]+)\s+(Mbits/sec|Kbits/sec|Gbits/sec)'
        )
        for line in output['result'].split('<br>'):
            match = pattern.search(line)
            if match:
                interval = match.group(1)
                bandwidth = float(match.group(4))
                unit = match.group(5)
                if unit == "Gbits/sec":
                    bandwidth *= 1000
                elif unit == "Kbits/sec":
                    bandwidth /= 1000
                intervals.append(interval)
                bandwidths.append(bandwidth)
        all_intervals.append(intervals)
        all_bandwidths.append(bandwidths)

    return json.dumps({"intervals": all_intervals, "bandwidths": all_bandwidths})

@iperf_bp.route('/generate_graph_data')
def generate_graph_data():
    output = session.get("iperf_result", "")
    if not output:
        return jsonify({"status": "error", "message": "No data available"}), 400
    graph_data = parse_iperf_output(output)
    return jsonify(json.loads(graph_data))

@iperf_bp.route('/generate_graph_data_two_clients')
def generate_graph_data_two_clients():
    outputs = session.get("iperf_results", [])
    if not outputs:
        return jsonify({"status": "error", "message": "No data available"}), 400
    graph_data = parse_iperf_output_multi(outputs)
    return jsonify(json.loads(graph_data))

@iperf_bp.route('/generate_graph_data_three_clients')
def generate_graph_data_three_clients():
    outputs = session.get("iperf_results", [])
    if not outputs:
        return jsonify({"status": "error", "message": "No data available"}), 400
    graph_data = parse_iperf_output_multi(outputs)
    return jsonify(json.loads(graph_data))



@iperf_bp.route('/clientscount')
def count():
    return render_template('clientscount.html')

