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
import psutil
import paramiko
from ..validation.routes import simple_telnet

iperf_result_queue = queue.Queue()

REMOTE_IPERF_PATH = "/usr/bin/iperf3"  

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
    result = session.get("iperf_result", {
        "iperf_result": "No iPerf results available.",
        "telnet_result": ["No Telnet results available."],
        "traffic_type": "unknown",
        "parsed_hgw_lines": [],
        "dscp_value": "0"
    })
    device_id = "ID_DU_DISPOSITIF"
    print(f"Rendering index3.html with result: {result}")
    return render_template('index3.html', result=result, device_id=device_id, DSCP_TRAFFIC_MAP=DSCP_TRAFFIC_MAP)

@iperf_bp.route('/index33')
def index33():
    results = session.get("iperf_results", [])
    return render_template('index33.html', results=results)

@iperf_bp.route('/index333')
def index333():
    results = session.get("iperf_results", [])
    return render_template('index333.html', results=results)

@iperf_bp.route('/clientscount')
def count():
    return render_template('clientscount.html')



def run_iperf_server(port, server_process_list, server_control='manual', remote_server_ip=None, ssh_username=None, ssh_password=None):
    if server_control != 'ssh':
        print(f"Manual server control selected. Assuming iPerf3 server is running on port {port}.")
        return True

    if not remote_server_ip or not ssh_username or not ssh_password:
        print("Missing SSH credentials for server startup.")
        return None

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print(f"Verifying SSH connectivity to {remote_server_ip}")
        ssh.connect(
            remote_server_ip,
            username=ssh_username,
            password=ssh_password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )
        print(f"SSH connectivity verified to {remote_server_ip}")

        check_cmd = f"ss -tuln | grep :{port} || echo 'Port free'"
        stdin, stdout, stderr = ssh.exec_command(check_cmd)
        check_output = stdout.read().decode().strip()
        stderr_output = stderr.read().decode()
        if 'Port free' not in check_output:
            print(f"Port {port} is already in use on {remote_server_ip}: {check_output}")
            ssh.close()
            return None

        cmd = f"{REMOTE_IPERF_PATH} -s -p {port} --daemon"
        print(f"Starting iPerf server on remote host {remote_server_ip} with port {port}: {cmd}")
        stdin, stdout, stderr = ssh.exec_command(cmd)
        stderr_output = stderr.read().decode().strip()
        time.sleep(3)  # Ensure server starts
        if stderr_output:
            print(f"Error starting iPerf server on port {port}: {stderr_output}")
            ssh.close()
            return None

        # Get PID
        pid_cmd = f"pgrep -f 'iperf3.*-p {port}'"
        stdin, stdout, stderr = ssh.exec_command(pid_cmd)
        pid = stdout.read().decode().strip()
        stderr_output = stderr.read().decode()
        if not pid.isdigit():
            print(f"Failed to get PID for iPerf server on port {port}: {stderr_output}")
            ssh.close()
            return None

        print(f"iPerf server started with PID {pid} on port {port}")
        server_process_list.append((ssh, pid))
        return (ssh, pid)
    except Exception as e:
        print(f"Error starting iPerf server on port {port}: {e}")
        if 'ssh' in locals():
            ssh.close()
        return None

def terminate_server_processes(server_process_list):
    for ssh, pid in server_process_list:
        try:
            cmd = f"kill -9 {pid}"
            print(f"Terminating iPerf server process {pid}")
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stdout.read()
            stderr_output = stderr.read().decode()
            if stderr_output:
                print(f"Error during termination of PID {pid}: {stderr_output}")
            ssh.close()
            print(f"Closed SSH connection for PID {pid}")
        except Exception as e:
            print(f"Error terminating iPerf server process {pid}: {e}")
            ssh.close()
    server_process_list.clear()

def run_iperf_command(cmd, result_queue):
    try:
        print(f"Executing client command: {' '.join(cmd)}")
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = process.stdout
        error = process.stderr
        print("===== iPerf3 Output =====")
        print(output)
        if error:
            print(f"===== iPerf3 Error =====")
            print(error)
        print("===== End of Output =====")
        if process.returncode == 0:
            result_queue.put(output)
        else:
            result_queue.put(f"Error: {error}")
    except subprocess.TimeoutExpired:
        print("Client command timed out")
        result_queue.put("Error: iPerf3 client timed out")
    except Exception as e:
        print(f"Error executing client command: {e}")
        result_queue.put(f"Error: {e}")


@iperf_bp.route('/run_iperf', methods=['POST'])
def run_iperf():
    data = request.form
    server_ip = data.get('serverIp')
    client_ip = data.get('clientIp')
    port = str(data.get('port'))
    dscp_tos = str(data.get('dscp', '0'))
    protocol = data.get('protocol', 'tcp')
    direction = data.get('direction')
    taille = data.get('taille')
    duration = data.get('duration')
    server_control = data.get('serverControl', 'manual')
    remote_server_ip = data.get('remoteServerIp')
    ssh_username = data.get('sshUsername')
    ssh_password = data.get('sshPassword')
    traffic_type = data.get('trafficType')

    if server_control == 'ssh' and not server_ip:
        server_ip = remote_server_ip

    result_data = {
    "iperf_result": "No iPerf results available.",
    "telnet_result": ["No Telnet results available."],
    "traffic_type": traffic_type or "unknown",
    "parsed_hgw_lines": [],
    "dscp_value": dscp_tos or "0"
}

    if not server_ip or not client_ip or not port.isdigit():
        result_data["iperf_result"] = "Invalid input. Server and Client IPs and a valid port are required"
        print(result_data["iperf_result"])
        session["iperf_result"] = result_data
        return render_template('index3.html', result=result_data, device_id="ID_DU_DISPOSITIF")

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        result_data["iperf_result"] = f"iPerf3 executable not found at {iperf_path}"
        print(result_data["iperf_result"])
        session["iperf_result"] = result_data
        return render_template('index3.html', result=result_data, device_id="ID_DU_DISPOSITIF")

    server_process_list = []
    if server_control == 'ssh':
        server_process = run_iperf_server(port, server_process_list, server_control, remote_server_ip, ssh_username, ssh_password)
        if not server_process:
            terminate_server_processes(server_process_list)
            result_data["iperf_result"] = "Failed to start iPerf server via SSH"
            print(result_data["iperf_result"])
            session["iperf_result"] = result_data
            return render_template('index3.html', result=result_data, device_id="ID_DU_DISPOSITIF")
    else:
        print(f"Manual server control: assuming iPerf3 server is running on {server_ip}:{port}")

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
    if taille and taille.strip():
        cmd.extend(["-b", taille])
    if duration:
        cmd.extend(["-t", str(duration)])

    thread = threading.Thread(target=run_iperf_command, args=(cmd, iperf_result_queue))
    thread.start()
    thread.join()

    if not iperf_result_queue.empty():
        iperf_result = iperf_result_queue.get()
        print(f"Client iPerf result: {iperf_result[:100]}...")
        result_data["iperf_result"] = iperf_result
    else:
        result_data["iperf_result"] = "No results received from iPerf3 client"
        print(result_data["iperf_result"])

    if server_control == 'ssh':
        terminate_server_processes(server_process_list)

    try:
        if traffic_type == 'wlan5':
            telnet_command = 'wlctl -i wl0 pktq_stats'
        elif traffic_type == 'wlan2':
            telnet_command = 'wlctl -i wl1 pktq_stats'
        elif traffic_type == 'lan':
            telnet_command = 'bs /b/e egress_tm |grep -i lan0'
        else:
            telnet_command = None
            result_data["telnet_result"] = ["Invalid traffic type specified."]
        if telnet_command:
            telnet_output = simple_telnet(
                host="192.168.1.1",
                port=23,
                username="root",
                password="sah",
                command=telnet_command
            )
            result_data["telnet_result"] = telnet_output
            parsed_lines = parse_hgw_output(telnet_output, dscp_tos)
            result_data["parsed_hgw_lines"] = parsed_lines
    except Exception as e:
        result_data["telnet_result"] = [f"Telnet error: {str(e)}"]
        result_data["parsed_hgw_lines"] = []
        print(f"Telnet error: {str(e)}")

    session["iperf_result"] = result_data
    print("Stored results in session, rendering index3")
    return render_template('index3.html', result=result_data, device_id="ID_DU_DISPOSITIF")



@iperf_bp.route('/run_iperf_two_clients', methods=['POST'])
def run_iperf_two_clients():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip1 = data.get('clientIp1')
    client_ip2 = data.get('clientIp2')
    port1 = str(data.get('port1'))
    port2 = str(data.get('port2'))
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
    server_control = data.get('serverControl', 'manual')
    remote_server_ip = data.get('remoteServerIp')
    ssh_username = data.get('sshUsername')
    ssh_password = data.get('sshPassword')

    # Validate inputs
    if not server_ip or not client_ip1 or not client_ip2:
        error_msg = "Invalid input. Server and both Client IPs are required"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if not port1 or not port1.isdigit() or int(port1) < 1 or int(port1) > 65535:
        error_msg = "Invalid port for client 1: must be a number between 1 and 65535"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if not port2 or not port2.isdigit() or int(port2) < 1 or int(port2) > 65535:
        error_msg = "Invalid port for client 2: must be a number between 1 and 65535"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if port1 == port2:
        error_msg = "Port 1 and Port 2 must be different"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        error_msg = f"iperf3 executable not found at {iperf_path}"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500

    if not os.access(iperf_path, os.X_OK):
        error_msg = f"iPerf3 executable at {iperf_path} is not executable"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500

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
            cmd.extend(["-b", "10M"])  
        if taille and taille.strip():
            cmd.extend(["-b", taille])
        if duration:
            cmd.extend(["-t", str(duration)])
        cmd.extend(["-i", "1"])
        return cmd

    server_process_list = []
    ssh_client = None
    if server_control == 'ssh':
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"Verifying SSH connectivity to {remote_server_ip}")
            ssh_client.connect(
                remote_server_ip,
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

        def start_server_thread(port, server_process_list, ssh_client):
            try:
                check_cmd = f"ss -tuln | grep :{port} || echo 'Port free'"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                check_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode()
                if 'Port free' not in check_output:
                    print(f"Port {port} is already in use on {remote_server_ip}: {check_output}")
                    return None

                cmd = f"{REMOTE_IPERF_PATH} -s -p {port} --daemon"
                print(f"Starting iPerf server on remote host {remote_server_ip} with port {port}: {cmd}")
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                stderr_output = stderr.read().decode().strip()
                time.sleep(3)  # Ensure server starts
                if stderr_output:
                    print(f"Error starting iPerf server on port {port}: {stderr_output}")
                    return None
                pid_cmd = f"pgrep -f 'iperf3.*-p {port}'"
                stdin, stdout, stderr = ssh_client.exec_command(pid_cmd)
                pid = stdout.read().decode().strip()
                if not pid.isdigit():
                    print(f"Failed to get PID for iPerf server on port {port}: {stderr.read().decode()}")
                    return None
                print(f"iPerf server started with PID {pid} on port {port}")
                server_process_list.append((ssh_client, pid))
                return pid
            except Exception as e:
                print(f"Error starting iPerf server on port {port}: {e}")
                return None

        print(f"Launching iPerf servers on ports {port1} and {port2}")
        server_thread1 = threading.Thread(target=start_server_thread, args=(port1, server_process_list, ssh_client))
        server_thread2 = threading.Thread(target=start_server_thread, args=(port2, server_process_list, ssh_client))
        
        server_thread1.start()
        server_thread2.start()
        
        server_thread1.join()
        server_thread2.join()

        if len(server_process_list) != 2:
            print(f"Failed to start all iPerf servers: only {len(server_process_list)} started")
            if ssh_client:
                for _, pid in server_process_list:
                    try:
                        ssh_client.exec_command(f"kill -9 {pid}")
                        print(f"Terminated iPerf server with PID {pid}")
                    except Exception as e:
                        print(f"Error killing PID {pid}: {e}")
                ssh_client.close()
            return jsonify({"status": "error", "message": f"Failed to start all iPerf servers: only {len(server_process_list)} of 2 started"}), 500

    else:
        print(f"Manual server control: assuming iPerf3 servers are running on {server_ip}:{port1} and {server_ip}:{port2}")

    result_queue1 = queue.Queue()
    result_queue2 = queue.Queue()

    cmd1 = build_iperf_command(client_ip1, port1, dscp_tos1, protocol1, direction1, taille1, duration1)
    cmd2 = build_iperf_command(client_ip2, port2, dscp_tos2, protocol2, direction2, taille2, duration2)

    print(f"Preparing command for client 1: {' '.join(cmd1)}")
    print(f"Preparing command for client 2: {' '.join(cmd2)}")

    thread1 = threading.Thread(target=run_iperf_command, args=(cmd1, result_queue1))
    thread2 = threading.Thread(target=run_iperf_command, args=(cmd2, result_queue2))
    
    print("Starting client threads")
    thread1.start()
    thread2.start()

    timeout = max(float(duration1 or 10), float(duration2 or 10)) + 10
    start_time = time.time()
    for thread in [thread1, thread2]:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            print("Client thread timeout reached")
            break
        thread.join(remaining)
    print("Client threads completed")

    # Collect results
    results = []
    client_configs = [
        (result_queue1, client_ip1, port1, "client1"),
        (result_queue2, client_ip2, port2, "client2")
    ]
    for i, (result_queue, client_ip, port, client_name) in enumerate(client_configs):
        print(f"Processing results for {client_name} (IP: {client_ip}, Port: {port})")
        try:
            if not result_queue.empty():
                result = result_queue.get_nowait()
                print(f"Collected result for {client_name} (IP: {client_ip}, Port: {port}): {result[:100]}...")
                results.append({"client": client_name, "result": result.replace('\n', '<br>')})
            else:
                print(f"No result for {client_name} (IP: {client_ip}, Port: {port}): client may have failed or timed out")
                results.append({"client": client_name, "result": "Error: Client failed to return results"})
        except Exception as e:
            print(f"Error retrieving result for {client_name} (IP: {client_ip}, Port: {port}): {e}")
            results.append({"client": client_name, "result": f"Error: {str(e)}"})



    if server_control == 'ssh' and ssh_client:
        for _, pid in server_process_list:
            try:
                ssh_client.exec_command(f"kill -9 {pid}")
                print(f"Terminated iPerf server with PID {pid}")
            except Exception as e:
                print(f"Error killing PID {pid}: {e}")
        ssh_client.close()

    session["iperf_results"] = results
    print("Stored results in session, redirecting to index33")
    return jsonify({"status": "success", "redirect_url": url_for('iperf.index33')})


@iperf_bp.route('/run_iperf_three_clients', methods=['POST'])
def run_iperf_three_clients():
    data = request.get_json()
    print(f"Received data: {data}")

    server_ip = data.get('serverIp')
    client_ip1 = data.get('clientIp1')
    client_ip2 = data.get('clientIp2')
    client_ip3 = data.get('clientIp3')
    port1 = str(data.get('port1'))
    port2 = str(data.get('port2'))
    port3 = str(data.get('port3'))
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
    server_control = data.get('serverControl', 'manual')
    remote_server_ip = data.get('remoteServerIp')
    ssh_username = data.get('sshUsername')
    ssh_password = data.get('sshPassword')

    if not server_ip or not client_ip1 or not client_ip2 or not client_ip3:
        error_msg = "Invalid input. Server and all Client IPs are required"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if not port1 or not port1.isdigit() or int(port1) < 1 or int(port1) > 65535:
        error_msg = "Invalid port for client 1: must be a number between 1 and 65535"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if not port2 or not port2.isdigit() or int(port2) < 1 or int(port2) > 65535:
        error_msg = "Invalid port for client 2: must be a number between 1 and 65535"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if not port3 or not port3.isdigit() or int(port3) < 1 or int(port3) > 65535:
        error_msg = "Invalid port for client 3: must be a number between 1 and 65535"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    if len(set([port1, port2, port3])) != 3:
        error_msg = "All ports must be different"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 400

    iperf_path = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    if not os.path.exists(iperf_path):
        error_msg = f"iperf3 executable not found at {iperf_path}"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500

    if not os.access(iperf_path, os.X_OK):
        error_msg = f"iPerf3 executable at {iperf_path} is not executable"
        print(error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500

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
            cmd.extend(["-b", "10M"])  
        if taille and taille.strip():
            cmd.extend(["b", taille])
        if duration:
            cmd.extend(["-t", str(duration)])
        cmd.extend(["-i", "1"])
        return cmd

    server_process_list = []
    ssh_client = None
    if server_control == 'ssh':
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(f"Verifying SSH connectivity to {remote_server_ip}")
            ssh_client.connect(
                remote_server_ip,
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

        def start_server_thread(port, server_process_list, ssh_client):
            try:
                check_cmd = f"ss -tuln | grep :{port} || echo 'Port free'"
                stdin, stdout, stderr = ssh_client.exec_command(check_cmd)
                check_output = stdout.read().decode().strip()
                stderr_output = stderr.read().decode()
                if 'Port free' not in check_output:
                    print(f"Port {port} is already in use on {remote_server_ip}: {check_output}")
                    return None

                cmd = f"{REMOTE_IPERF_PATH} -s -p {port} --daemon"
                print(f"Starting iPerf server on remote host {remote_server_ip} with port {port}: {cmd}")
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                stderr_output = stderr.read().decode().strip()
                time.sleep(3)  # Ensure server starts
                if stderr_output:
                    print(f"Error starting iPerf server on port {port}: {stderr_output}")
                    return None
                pid_cmd = f"pgrep -f 'iperf3.*-p {port}'"
                stdin, stdout, stderr = ssh_client.exec_command(pid_cmd)
                pid = stdout.read().decode().strip()
                if not pid.isdigit():
                    print(f"Failed to get PID for iPerf server on port {port}: {stderr.read().decode()}")
                    return None
                print(f"iPerf server started with PID {pid} on port {port}")
                server_process_list.append((ssh_client, pid))
                return pid
            except Exception as e:
                print(f"Error starting iPerf server on port {port}: {e}")
                return None

        print(f"Launching iPerf servers on ports {port1}, {port2}, and {port3}")
        server_thread1 = threading.Thread(target=start_server_thread, args=(port1, server_process_list, ssh_client))
        server_thread2 = threading.Thread(target=start_server_thread, args=(port2, server_process_list, ssh_client))
        server_thread3 = threading.Thread(target=start_server_thread, args=(port3, server_process_list, ssh_client))
        
        server_thread1.start()
        server_thread2.start()
        server_thread3.start()
        
        server_thread1.join()
        server_thread2.join()
        server_thread3.join()

        if len(server_process_list) != 3:
            print(f"Failed to start all iPerf servers: only {len(server_process_list)} started")
            if ssh_client:
                for _, pid in server_process_list:
                    try:
                        ssh_client.exec_command(f"kill -9 {pid}")
                        print(f"Terminated iPerf server with PID {pid}")
                    except Exception as e:
                        print(f"Error killing PID {pid}: {e}")
                ssh_client.close()
            return jsonify({"status": "error", "message": f"Failed to start all iPerf servers: only {len(server_process_list)} of 3 started"}), 500

    else:
        print(f"Manual server control: assuming iPerf3 servers are running on {server_ip}:{port1}, {server_ip}:{port2}, and {server_ip}:{port3}")

    result_queue1 = queue.Queue()
    result_queue2 = queue.Queue()
    result_queue3 = queue.Queue()

    cmd1 = build_iperf_command(client_ip1, port1, dscp_tos1, protocol1, direction1, taille1, duration1)
    cmd2 = build_iperf_command(client_ip2, port2, dscp_tos2, protocol2, direction2, taille2, duration2)
    cmd3 = build_iperf_command(client_ip3, port3, dscp_tos3, protocol3, direction3, taille3, duration3)

    print(f"Preparing command for client 1: {' '.join(cmd1)}")
    print(f"Preparing command for client 2: {' '.join(cmd2)}")
    print(f"Preparing command for client 3: {' '.join(cmd3)}")

    thread1 = threading.Thread(target=run_iperf_command, args=(cmd1, result_queue1))
    thread2 = threading.Thread(target=run_iperf_command, args=(cmd2, result_queue2))
    thread3 = threading.Thread(target=run_iperf_command, args=(cmd3, result_queue3))
    
    print("Starting client threads")
    thread1.start()
    thread2.start()
    thread3.start()

    timeout = max(float(duration1 or 10), float(duration2 or 10), float(duration3 or 10)) + 10
    start_time = time.time()
    for thread in [thread1, thread2, thread3]:
        remaining = timeout - (time.time() - start_time)
        if remaining <= 0:
            print("Client thread timeout reached")
            break
        thread.join(remaining)
    print("Client threads completed")

    results = []
    client_configs = [
        (result_queue1, client_ip1, port1, "client1"),
        (result_queue2, client_ip2, port2, "client2"),
        (result_queue3, client_ip3, port3, "client3")
    ]
    for i, (result_queue, client_ip, port, client_name) in enumerate(client_configs):
        print(f"Processing results for {client_name} (IP: {client_ip}, Port: {port})")
        try:
            if not result_queue.empty():
                result = result_queue.get_nowait()
                print(f"Collected result for {client_name} (IP: {client_ip}, Port: {port}): {result[:100]}...")
                results.append({"client": client_name, "result": result.replace('\n', '<br>')})
            else:
                print(f"No result for {client_name} (IP: {client_ip}, Port: {port}): client may have failed or timed out")
                results.append({"client": client_name, "result": "Error: Client failed to return results"})
        except Exception as e:
            print(f"Error retrieving result for {client_name} (IP: {client_ip}, Port: {port}): {e}")
            results.append({"client": client_name, "result": f"Error: {str(e)}"})



    # Cleanup
    if server_control == 'ssh' and ssh_client:
        for _, pid in server_process_list:
            try:
                ssh_client.exec_command(f"kill -9 {pid}")
                print(f"Terminated iPerf server with PID {pid}")
            except Exception as e:
                print(f"Error killing PID {pid}: {e}")
        ssh_client.close()

    session["iperf_results"] = results
    print("Stored results in session, redirecting to index333")
    return jsonify({"status": "success", "redirect_url": url_for('iperf.index333')})




def parse_iperf_output(output):
    pattern = re.compile(
        r'\[\s*\d+\]\s+(\d+\.\d+-\d+\.\d+)\s+sec\s+([\d.]+)\s+(MBytes|KBytes|GBytes)\s+([\d.]+)\s+(Mbits/sec|Kbits/sec|Gbits/sec)\s*'
    )
    intervals = []
    bandwidths = []

    for line in output.splitlines():
        match = pattern.search(line.strip())
        if match:
            interval = match.group(1)  # e.g., 0.00-1.00
            bandwidth = float(match.group(4))  # e.g., 3.80
            bandwidth_unit = match.group(5)  # e.g., Gbits/sec
            # Convert to Mbits/sec
            if bandwidth_unit == "Gbits/sec":
                bandwidth *= 1000
            elif bandwidth_unit == "Kbits/sec":
                bandwidth /= 1000
            # Else, already in Mbits/sec
            intervals.append(interval)
            bandwidths.append(bandwidth)

    if not intervals:
        print("No valid iPerf intervals found in output")

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
    result = session.get("iperf_result", {})
    output = result.get("iperf_result", "")
    if not output:
        print("No iPerf output available in session")
        return jsonify({"status": "error", "message": "No data available", "intervals": [], "bandwidths": []}), 400
    try:
        graph_data = parse_iperf_output(output)
        return jsonify(json.loads(graph_data))
    except Exception as e:
        print(f"Error parsing iPerf output: {e}")
        return jsonify({"status": "error", "message": str(e), "intervals": [], "bandwidths": []}), 400
    

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

DSCP_TRAFFIC_MAP = {
    '184': 'VO',
    '136': 'VO',
    '104': 'VI',
    '40': 'VI',
    '0': 'BE',
    '32': 'BK'
}

def parse_hgw_output(telnet_output, dscp_tos):
    """
    Parse Telnet output into a list of dictionaries for HGW packet queue stats.
    Handles comma-separated lines like '00: BK         0,       0,       0,       0,       0,       0,       0,        0,    0,      0.00,      0.00,  -/ -/ -/ -,   0.0,    0.0'.
    Colors only the row with the highest rqstd value (green if queue_type matches expected DSCP traffic type, red if not).
    All other rows have color: 'none'.
    """
    parsed_lines = []
    expected_traffic = DSCP_TRAFFIC_MAP.get(dscp_tos, 'UNKNOWN')

    for line in telnet_output:
        line = line.strip()
        if not line or 'common queue' in line or 'prec:(AC)' in line:
            print(f"Skipping header or empty line: {line}")
            continue

        match = re.match(r'(\d+): (\S+)\s+(.+)', line)
        if not match:
            print(f"Skipping malformed line: {line}")
            continue

        queue_id, queue_type, fields = match.groups()
        parts = [p.strip() for p in fields.split(',')]

        if len(parts) < 11:
            print(f"Skipping line with insufficient fields: {line}")
            continue

        try:
            rqstd = int(parts[0]) if parts[0] != '-' else 0
            stored = int(parts[1]) if parts[1] != '-' else 0
            dropped = int(parts[2]) if parts[2] != '-' else 0
            retried = int(parts[3]) if parts[3] != '-' else 0
            rtsfail = int(parts[4]) if parts[4] != '-' else 0
            rtrydrop = int(parts[5]) if parts[5] != '-' else 0
            psretry = int(parts[6]) if parts[6] != '-' else 0
            acked = int(parts[7]) if parts[7] != '-' else 0
            data_mbits = float(parts[9]) if parts[9] != '-' else 0.0
            phy_mbits = float(parts[10]) if parts[10] != '-' else 0.0

            parsed_lines.append({
                'queue_id': queue_id,
                'queue_type': queue_type,
                'rqstd': str(rqstd),
                'stored': str(stored),
                'dropped': str(dropped),
                'retried': str(retried),
                'rtsfail': str(rtsfail),
                'rtrydrop': str(rtrydrop),
                'psretry': str(psretry),
                'acked': str(acked),
                'data_mbits': str(data_mbits),
                'phy_mbits': str(phy_mbits),
                'color': 'none'  
            })
        except (ValueError, IndexError) as e:
            print(f"Error parsing line '{line}': {e}")
            continue

    if parsed_lines:
        max_line = max(parsed_lines, key=lambda x: int(x['rqstd']))
        max_rqstd = int(max_line['rqstd'])
        if max_rqstd > 0:
            max_line['color'] = 'green' if max_line['queue_type'] == expected_traffic else 'red'
            print(f"Colored line with highest rqstd ({max_rqstd}): {max_line}")
        else:
            print(f"No line with rqstd > 0, no coloring applied")

    print(f"Parsed HGW lines: {parsed_lines}")
    return parsed_lines
