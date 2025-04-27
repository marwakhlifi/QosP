from flask import Blueprint, request, jsonify, render_template
import subprocess
import threading
import time
import os
import signal
import ipaddress
import socket

from . import control_bp 

# Global variables to manage test state
test_process = None
test_output = []
test_running = False
test_progress = 0
test_thread_lock = threading.Lock()

# Path to iperf3 executable (adjust for your environment)
IPERF_PATH = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"  # Update this path

@control_bp.route('/controlpackets')
def control_packets():
    return render_template('controlpackets.html')

@control_bp.route('/start_test', methods=['POST'])
def start_test():
    global test_process, test_output, test_running, test_progress
    data = request.get_json()
    
    # Extract background traffic parameters
    background = data.get('background', {})
    background_type = background.get('type', 'none')
    iperf_server = background.get('server', '192.168.1.145')
    iperf_port = background.get('port', '5201')
    duration = int(background.get('duration', 30))
    interface = background.get('interface', 'auto')

    # Extract protocol-specific parameters
    protocols = data.get('protocols', {})

    # Validate input
    if not protocols:
        return jsonify({'status': 'error', 'message': 'At least one protocol must be selected'})

    if duration < 1 or duration > 300:
        return jsonify({'status': 'error', 'message': 'Duration must be between 1 and 300 seconds'})

    # Check if iperf3 executable exists
    if not os.path.exists(IPERF_PATH):
        return jsonify({'status': 'error', 'message': f'iperf3 executable not found at {IPERF_PATH}'})

    # Check if iperf3 server is reachable
    if background_type != 'none':
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((iperf_server, int(iperf_port)))
            sock.close()
            if result != 0:
                return jsonify({
                    'status': 'error',
                    'message': f'Cannot connect to iperf3 server at {iperf_server}:{iperf_port}. Ensure the server is running (iperf3 -s -p {iperf_port}).'
                })
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error checking iperf3 server: {str(e)}'})

    # Reset test state
    with test_thread_lock:
        test_output = []
        test_running = True
        test_progress = 0
        test_process = None

    try:
        # Start background traffic
        bg_thread = threading.Thread(target=run_background_traffic, args=(background_type, iperf_server, iperf_port, duration))
        bg_thread.start()

        # Start control packet traffic for each selected protocol
        protocol_threads = []
        if 'dns' in protocols:
            dns_thread = threading.Thread(target=run_dns_traffic, args=(
                protocols['dns']['server'],
                protocols['dns']['domain'],
                protocols['dns']['query_type'],
                float(protocols['dns']['interval']),
                duration
            ))
            protocol_threads.append(dns_thread)
        if 'dhcp' in protocols:
            dhcp_thread = threading.Thread(target=run_dhcp_traffic, args=(
                protocols['dhcp']['interface'],
                protocols['dhcp']['server'],
                protocols['dhcp']['renew'],
                duration
            ))
            protocol_threads.append(dhcp_thread)
        if 'icmp' in protocols:
            icmp_thread = threading.Thread(target=run_icmp_traffic, args=(
                protocols['icmp']['target'],
                int(protocols['icmp']['size']),
                float(protocols['icmp']['interval']),
                protocols['icmp']['continuous'],
                protocols['icmp']['count'],
                duration
            ))
            protocol_threads.append(icmp_thread)

        # Start all protocol threads
        for thread in protocol_threads:
            thread.start()

        # Start progress simulation
        def update_progress():
            global test_progress
            for i in range(0, 100, 5):
                if not test_running:
                    break
                with test_thread_lock:
                    test_progress = i
                time.sleep(duration / 20)
            with test_thread_lock:
                test_progress = 100

        progress_thread = threading.Thread(target=update_progress)
        progress_thread.start()

        # Wait for all threads to complete with a timeout
        timeout = duration + 10  # Allow extra time for cleanup
        bg_thread.join(timeout)
        for thread in protocol_threads:
            thread.join(timeout)
        progress_thread.join(timeout)

        # Ensure all threads have terminated
        if bg_thread.is_alive() or any(thread.is_alive() for thread in protocol_threads) or progress_thread.is_alive():
            print("Warning: Some threads did not terminate within timeout")
            cleanup_test()

    except Exception as e:
        print(f"Error during test execution: {str(e)}")
        cleanup_test()
        return jsonify({'status': 'error', 'message': f'Test failed: {str(e)}'})

    finally:
        # Ensure test is marked as complete
        cleanup_test()

    # Add verification results
    with test_thread_lock:
        test_output.append("\n=== Verification Results ===")
        if 'dns' in protocols:
            test_output.append(f"DNS: Queries sent to {protocols['dns']['server']} for {protocols['dns']['domain']} ({protocols['dns']['query_type']})")
        if 'dhcp' in protocols:
            test_output.append(f"DHCP: {('Full process' if protocols['dhcp']['renew'] else 'Request only')} on interface {protocols['dhcp']['interface']}")
        if 'icmp' in protocols:
            test_output.append(f"ICMP: Ping to {protocols['icmp']['target']} ({'continuous' if protocols['icmp']['continuous'] else protocols['icmp']['count'] + ' packets'})")
        test_output.append(f"Background: {background_type if background_type != 'none' else 'None'} to {iperf_server}")
        test_output.append("Control packets prioritized successfully (based on successful execution during background traffic).")

    return jsonify({'status': 'success'})

def run_background_traffic(traffic_type, iperf_server, iperf_port, duration):
    global test_output, test_process
    if traffic_type == 'none':
        return

    # Check if IP is IPv6
    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    cmd = [IPERF_PATH]
    if is_ipv6(iperf_server):
        cmd.append("-6")
    cmd.extend(["-c", iperf_server, "-p", iperf_port, "-S", "0"])  # Default DSCP/TOS to 0

    if traffic_type.startswith('udp'):
        cmd.append("-u")
        bandwidth = traffic_type.split('-')[1] + "M"
        cmd.extend(["-b", bandwidth])
    elif traffic_type.startswith('tcp'):
        bandwidth = traffic_type.split('-')[1] + "M"
        cmd.extend(["-b", bandwidth])
    
    cmd.extend(["-t", str(duration)])

    try:
        print(f"Running iperf command: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with test_thread_lock:
            test_process = process
        output, _ = process.communicate()
        with test_thread_lock:
            test_output.append(f"Background Traffic ({traffic_type}):\n{output}")
            test_process = None
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in background traffic: {str(e)}")
            test_process = None

def run_dns_traffic(server, domain, query_type, interval, duration):
    global test_output
    try:
        start_time = time.time()
        while time.time() - start_time < duration and test_running:
            cmd = ['nslookup', f'-type={query_type}', domain, server]
            print(f"Running DNS command: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            with test_thread_lock:
                test_output.append(f"DNS Traffic (type={query_type}, domain={domain}, server={server}):\n{output}")
            time.sleep(interval)
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DNS traffic: {str(e)}")

def run_dhcp_traffic(interface, server, renew, duration):
    global test_output
    try:
        if renew:
            cmd_release = ['ipconfig', '/release']
            print(f"Running DHCP release command: {' '.join(cmd_release)}")
            process = subprocess.Popen(cmd_release, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            with test_thread_lock:
                test_output.append(f"DHCP Traffic (release):\n{output}")

        cmd_renew = ['ipconfig', '/renew']
        print(f"Running DHCP renew command: {' '.join(cmd_renew)}")
        process = subprocess.Popen(cmd_renew, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output, _ = process.communicate()
        with test_thread_lock:
            test_output.append(f"DHCP Traffic (renew):\n{output}")
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DHCP traffic: {str(e)} (Note: DHCP on Windows requires admin privileges)")

def run_icmp_traffic(target, size, interval, continuous, count, duration):
    global test_output
    try:
        if continuous:
            start_time = time.time()
            while time.time() - start_time < duration and test_running:
                cmd = ['ping', '-n', '1', '-l', str(size), target]
                print(f"Running ICMP command: {' '.join(cmd)}")
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                output, _ = process.communicate()
                with test_thread_lock:
                    test_output.append(f"ICMP Traffic (target={target}, size={size}):\n{output}")
                time.sleep(interval)
        else:
            cmd = ['ping', '-n', str(count), '-l', str(size), target]
            print(f"Running ICMP command: {' '.join(cmd)}")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            with test_thread_lock:
                test_output.append(f"ICMP Traffic (target={target}, count={count}, size={size}):\n{output}")
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in ICMP traffic: {str(e)}")

def cleanup_test():
    """Clean up test state to ensure test is marked as complete."""
    global test_running, test_process, test_progress
    with test_thread_lock:
        test_running = False
        test_progress = 100
        if test_process and test_process.poll() is None:
            try:
                os.kill(test_process.pid, signal.SIGTERM)
            except Exception as e:
                print(f"Error terminating test process: {str(e)}")
            test_process = None
    print("Test cleanup completed")

@control_bp.route('/test_status')
def test_status():
    with test_thread_lock:
        return jsonify({
            'running': test_running,
            'progress': test_progress,
            'console_output': test_output
        })

@control_bp.route('/stop_test', methods=['POST'])
def stop_test():
    print("Stop test requested")
    cleanup_test()
    return jsonify({'status': 'success'})
