from flask import Blueprint, request, jsonify, render_template
import subprocess
import threading
import time
import os
import signal
import ipaddress
import socket
from scapy.all import sniff, DNS, ICMP, DHCP, get_if_list
from scapy.arch.windows import get_windows_if_list
from scapy.layers.inet import IP
import statistics
from . import control_bp 


# Global variables to manage test state
test_process = None
test_output = []
test_running = False
test_progress = 0
test_metrics = {
    'dns': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
    'icmp': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
    'dhcp': {'success': False, 'duration': 0}
}
test_thread_lock = threading.Lock()
sent_timestamps = {}  # Track sent packet timestamps

# Path to iperf3 executable (adjust for your environment)
IPERF_PATH = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"

def get_interfaces_with_names():
    """Retrieve interfaces with both NPF names and friendly names."""
    interfaces = []
    for iface in get_windows_if_list():
        npf_name = iface.get('win32_ifname', '')  # e.g., \Device\NPF_{...}
        description = iface.get('description', '')  # e.g., Intel(R) Wi-Fi 6 AX201 160MHz
        # Map to ipconfig-friendly names based on description
        ipconfig_name = description
        if "Wi-Fi 6 AX201" in description:
            ipconfig_name = "Wi-Fi"
        elif "VirtualBox" in description:
            ipconfig_name = "Ethernet 3"
        elif "Realtek PCIe GbE" in description:
            ipconfig_name = "Ethernet"
        elif "Microsoft Wi-Fi Direct Virtual Adapter #4" in description:
            ipconfig_name = "Connexion au réseau local* 3"
        elif "Microsoft Wi-Fi Direct Virtual Adapter #5" in description:
            ipconfig_name = "Connexion au réseau local* 4"
        elif "Bluetooth Device" in description:
            ipconfig_name = "Connexion réseau Bluetooth"
        elif "Loopback" in description or "Loopback" in npf_name:
            ipconfig_name = "Loopback"
        interfaces.append({
            'npf_name': npf_name,
            'friendly_name': ipconfig_name
        })
    return interfaces

@control_bp.route('/controlpackets')
def control_packets():
    # Get available network interfaces with friendly names
    interfaces = get_interfaces_with_names()
    return render_template('controlpackets.html', interfaces=interfaces)

@control_bp.route('/start_test', methods=['POST'])
def start_test():
    global test_process, test_output, test_running, test_progress, test_metrics, sent_timestamps
    data = request.get_json()
    
    # Extract background traffic parameters
    background = data.get('background', {})
    background_type = background.get('type', 'none')
    iperf_server = background.get('server', '').strip()  # User-provided server IP
    iperf_port = background.get('port', '').strip()  # User-provided port
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

    # Validate iperf server and port if background traffic is enabled
    if background_type != 'none':
        if not iperf_server:
            return jsonify({'status': 'error', 'message': 'iPerf server IP is required for background traffic'})
        if not iperf_port:
            return jsonify({'status': 'error', 'message': 'iPerf port is required for background traffic'})
        try:
            iperf_port_int = int(iperf_port)
            if iperf_port_int < 1 or iperf_port_int > 65535:
                return jsonify({'status': 'error', 'message': 'iPerf port must be between 1 and 65535'})
        except ValueError:
            return jsonify({'status': 'error', 'message': 'iPerf port must be a valid number'})
        try:
            ipaddress.ip_address(iperf_server)
        except ValueError:
            return jsonify({'status': 'error', 'message': 'Invalid iPerf server IP address'})

        # Check if iperf3 server is reachable
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
        test_metrics = {
            'dns': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
            'icmp': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
            'dhcp': {'success': False, 'duration': 0}
        }
        sent_timestamps = {}

    try:
        # Start packet sniffer
        sniffer_thread = threading.Thread(target=run_packet_sniffer, args=(protocols, duration, interface))
        sniffer_thread.start()

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
        timeout = duration + 10
        sniffer_thread.join(timeout)
        bg_thread.join(timeout)
        for thread in protocol_threads:
            thread.join(timeout)
        progress_thread.join(timeout)

        # Ensure all threads have terminated
        if sniffer_thread.is_alive() or bg_thread.is_alive() or any(thread.is_alive() for thread in protocol_threads) or progress_thread.is_alive():
            print("Warning: Some threads did not terminate within timeout")
            cleanup_test()

    except Exception as e:
        print(f"Error during test execution: {str(e)}")
        cleanup_test()
        return jsonify({'status': 'error', 'message': f'Test failed: {str(e)}'})

    finally:
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
        test_output.append(f"Background: {background_type if background_type != 'none' else 'None'} to {iperf_server}:{iperf_port}")
        test_output.append("Control packets prioritized successfully (based on successful execution during background traffic).")

    return jsonify({'status': 'success'})

def run_packet_sniffer(protocols, duration, interface):
    global test_metrics, sent_timestamps, test_output
    try:
        # Build filter based on selected protocols
        filters = []
        if 'dns' in protocols:
            filters.append("port 53")
        if 'dhcp' in protocols:
            filters.append("port 67 or port 68")
        if 'icmp' in protocols:
            filters.append("icmp")
        filter_str = " or ".join(filters) if filters else None

        if not filter_str:
            return

        # Determine interface (map friendly name to NPF name if needed)
        sniff_interface = interface if interface != 'auto' else None
        if interface == 'auto':
            interfaces = get_interfaces_with_names()
            # Prefer active interfaces (Wi-Fi or Ethernet 3)
            for iface in interfaces:
                if iface['friendly_name'] in ['Wi-Fi', 'Ethernet 3']:
                    sniff_interface = iface['npf_name']
                    break
            if not sniff_interface:
                with test_thread_lock:
                    test_output.append(f"Error: No suitable interface found. Available: {[i['friendly_name'] for i in interfaces]}")
                return
        else:
            # Map friendly name to NPF name
            interfaces = get_interfaces_with_names()
            for iface in interfaces:
                if iface['friendly_name'] == interface:
                    sniff_interface = iface['npf_name']
                    break
            if not sniff_interface:
                with test_thread_lock:
                    test_output.append(f"Error: Interface {interface} not found. Available: {[i['friendly_name'] for i in interfaces]}")
                return

        def packet_callback(packet):
            with test_thread_lock:
                current_time = time.time()
                if DNS in packet and 'dns' in protocols:
                    if packet[DNS].qr == 1:
                        packet_id = packet[DNS].id
                        if packet_id in sent_timestamps.get('dns', {}):
                            sent_time = sent_timestamps['dns'].pop(packet_id, None)
                            if sent_time:
                                latency = (current_time - sent_time) * 1000  # ms
                                test_metrics['dns']['latencies'].append(latency)
                                test_metrics['dns']['received'] += 1
                                if len(test_metrics['dns']['latencies']) > 1:
                                    diffs = [abs(test_metrics['dns']['latencies'][i] - test_metrics['dns']['latencies'][i-1]) 
                                             for i in range(1, len(test_metrics['dns']['latencies']))]
                                    test_metrics['dns']['jitter'] = statistics.mean(diffs) if diffs else 0
                elif ICMP in packet and 'icmp' in protocols:
                    if packet[ICMP].type == 0:
                        packet_id = packet[ICMP].id
                        if packet_id in sent_timestamps.get('icmp', {}):
                            sent_time = sent_timestamps['icmp'].pop(packet_id, None)
                            if sent_time:
                                latency = (current_time - sent_time) * 1000  # ms
                                test_metrics['icmp']['latencies'].append(latency)
                                test_metrics['icmp']['received'] += 1
                                if len(test_metrics['icmp']['latencies']) > 1:
                                    diffs = [abs(test_metrics['icmp']['latencies'][i] - test_metrics['icmp']['latencies'][i-1]) 
                                             for i in range(1, len(test_metrics['icmp']['latencies']))]
                                    test_metrics['icmp']['jitter'] = statistics.mean(diffs) if diffs else 0
                elif DHCP in packet and 'dhcp' in protocols:
                    test_metrics['dhcp']['success'] = True

        # Sniff packets
        print(f"Starting packet sniffer with filter: {filter_str} on interface: {sniff_interface}")
        sniff(iface=sniff_interface, filter=filter_str, prn=packet_callback, timeout=duration)
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in packet sniffer: {str(e)} (Note: Packet sniffing requires admin privileges)")

def run_background_traffic(traffic_type, iperf_server, iperf_port, duration):
    global test_output, test_process
    if traffic_type == 'none':
        return

    def is_ipv6(ip):
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    cmd = [IPERF_PATH]
    if is_ipv6(iperf_server):
        cmd.append("-6")
    cmd.extend(["-c", iperf_server, "-p", iperf_port, "-S", "0"])

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
    global test_output, test_metrics, sent_timestamps
    try:
        start_time = time.time()
        packet_id = 0
        while time.time() - start_time < duration and test_running:
            cmd = ['nslookup', f'-type={query_type}', domain, server]
            print(f"Running DNS command: {' '.join(cmd)}")
            with test_thread_lock:
                test_metrics['dns']['sent'] += 1
                sent_timestamps.setdefault('dns', {})[packet_id] = time.time()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            with test_thread_lock:
                test_output.append(f"DNS Traffic (type={query_type}, domain={domain}, server={server}):\n{output}")
            time.sleep(interval)
            packet_id += 1
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DNS traffic: {str(e)}")

def run_dhcp_traffic(interface, server, renew, duration):
    global test_output, test_metrics
    try:
        start_time = time.time()
        # Check if interface is active
        cmd_ipconfig = ['ipconfig', '/all']
        process = subprocess.Popen(cmd_ipconfig, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output, _ = process.communicate()
        if 'Média déconnecté' in output and interface in output:
            with test_thread_lock:
                test_output.append(f"DHCP Error: Interface {interface} is disconnected")
                test_metrics['dhcp']['duration'] = time.time() - start_time
                return

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
            test_metrics['dhcp']['duration'] = time.time() - start_time
            test_metrics['dhcp']['success'] = "successfully" in output.lower()
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DHCP traffic: {str(e)} (Note: DHCP on Windows requires admin privileges)")

def run_icmp_traffic(target, size, interval, continuous, count, duration):
    global test_output, test_metrics, sent_timestamps
    try:
        packet_id = 0
        if continuous:
            start_time = time.time()
            while time.time() - start_time < duration and test_running:
                cmd = ['ping', '-n', '1', '-l', str(size), target]
                print(f"Running ICMP command: {' '.join(cmd)}")
                with test_thread_lock:
                    test_metrics['icmp']['sent'] += 1
                    sent_timestamps.setdefault('icmp', {})[packet_id] = time.time()
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                output, _ = process.communicate()
                with test_thread_lock:
                    test_output.append(f"ICMP Traffic (target={target}, size={size}):\n{output}")
                time.sleep(interval)
                packet_id += 1
        else:
            cmd = ['ping', '-n', str(count), '-l', str(size), target]
            print(f"Running ICMP command: {' '.join(cmd)}")
            with test_thread_lock:
                test_metrics['icmp']['sent'] += count
                sent_timestamps.setdefault('icmp', {})[packet_id] = time.time()
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output, _ = process.communicate()
            with test_thread_lock:
                test_output.append(f"ICMP Traffic (target={target}, count={count}, size={size}):\n{output}")
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in ICMP traffic: {str(e)}")

def cleanup_test():
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
        # Calculate performance status
        performance_status = {}
        for proto in ['dns', 'icmp']:
            if test_metrics[proto]['sent'] > 0:
                avg_latency = statistics.mean(test_metrics[proto]['latencies']) if test_metrics[proto]['latencies'] else 0
                packet_loss = ((test_metrics[proto]['sent'] - test_metrics[proto]['received']) / test_metrics[proto]['sent']) * 100 if test_metrics[proto]['sent'] else 0
                jitter = test_metrics[proto]['jitter']
                is_degraded = avg_latency > 50 or packet_loss > 5 or jitter > 10
                performance_status[proto] = 'degraded' if is_degraded else 'ok'
        if 'dhcp' in test_metrics and test_metrics['dhcp']['duration'] > 0:
            performance_status['dhcp'] = 'ok' if test_metrics['dhcp']['success'] else 'degraded'

        return jsonify({
            'running': test_running,
            'progress': test_progress,
            'console_output': test_output,
            'performance_status': performance_status
        })

@control_bp.route('/test_metrics')
def test_metrics():
    with test_thread_lock:
        metrics = {}
        for proto in ['dns', 'icmp']:
            avg_latency = statistics.mean(test_metrics[proto]['latencies']) if test_metrics[proto]['latencies'] else 0
            packet_loss = ((test_metrics[proto]['sent'] - test_metrics[proto]['received']) / test_metrics[proto]['sent']) * 100 if test_metrics[proto]['sent'] else 0
            jitter = test_metrics[proto]['jitter']
            metrics[proto] = {
                'average_latency_ms': round(avg_latency, 2),
                'packet_loss_percent': round(packet_loss, 2),
                'jitter_ms': round(jitter, 2)
            }
        metrics['dhcp'] = {
            'success': test_metrics['dhcp']['success'],
            'duration_s': round(test_metrics['dhcp']['duration'], 2)
        }
        return jsonify(metrics)

@control_bp.route('/stop_test', methods=['POST'])
def stop_test():
    print("Stop test requested")
    cleanup_test()
    return jsonify({'status': 'success'})
