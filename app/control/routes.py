import json
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
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP
import statistics
from collections import deque
from . import control_bp

# Global variables for test state and packet capture
dscp_packets = deque(maxlen=500)  # Store the last 50 packets with DSCP info
packet_sniffer_running = False
sniffer_thread = None
test_thread_lock = threading.Lock()
test_output = []
test_running = False
test_progress = 0
test_metrics = {
    'dns': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
    'icmp': {'latencies': [], 'sent': 0, 'received': 0, 'jitter': 0},
    'dhcp': {'success': False, 'duration': 0}
}
sent_timestamps = {}
test_process = None
IPERF_PATH = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"

def extract_dscp(packet):
    """Extract DSCP value from IP header"""
    if IP in packet:
        return packet[IP].tos >> 2
    return None

def packet_handler(packet):
    """Process each captured packet for DSCP values and metrics"""
    global dscp_packets
    if IP not in packet:
        return

    protocol = None
    dscp = extract_dscp(packet)
    current_time = time.time()

    # Identify protocol and update metrics
    if ICMP in packet:
        protocol = "ICMP"
        with test_thread_lock:
            if packet[ICMP].type == 0:  # Echo reply
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
    elif UDP in packet and (packet[UDP].sport == 53 or packet[UDP].dport == 53) and DNS in packet:
        protocol = "DNS"
        with test_thread_lock:
            if packet[DNS].qr == 1:  # DNS response
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
    elif UDP in packet and (packet[UDP].sport == 67 or packet[UDP].sport == 68 or
                           packet[UDP].dport == 67 or packet[UDP].dport == 68) and BOOTP in packet:
        protocol = "DHCP"
        with test_thread_lock:
            test_metrics['dhcp']['success'] = True

    if protocol:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        packet_info = {
            'timestamp': timestamp,
            'protocol': protocol,
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'dscp': dscp,
            'priority': "High" if dscp and dscp > 0 else "Default"
        }
        with test_thread_lock:
            dscp_packets.append(packet_info)

def start_packet_sniffer(protocols, interface):
    """Start packet sniffer in a separate thread"""
    global packet_sniffer_running
    packet_sniffer_running = True

    filters = []
    if 'dns' in protocols:
        filters.append("port 53")
    if 'dhcp' in protocols:
        filters.append("port 67 or port 68")
    if 'icmp' in protocols:
        filters.append("icmp")
    filter_str = " or ".join(filters) if filters else "ip"

    sniff_interface = None
    interfaces = get_interfaces_with_names()

    if interface == 'auto':
        for iface in interfaces:
            if iface['is_connected'] and 'Wi-Fi' in iface['friendly_name']:
                sniff_interface = iface['npf_name']
                break
        if not sniff_interface:
            for iface in interfaces:
                if iface['is_connected'] and 'Ethernet' in iface['friendly_name']:
                    sniff_interface = iface['npf_name']
                    break
        if not sniff_interface and interfaces:
            sniff_interface = interfaces[0]['npf_name']
    else:
        for iface in interfaces:
            if iface['friendly_name'].lower() == interface.lower():
                sniff_interface = iface['npf_name']
                break

    if not sniff_interface:
        with test_thread_lock:
            test_output.append(f"Error: Interface {interface} not found. Available: {[i['friendly_name'] for i in interfaces]}")
        packet_sniffer_running = False
        return

    try:
        print(f"Starting packet sniffer with filter: {filter_str} on interface: {sniff_interface}")
        sniff(iface=sniff_interface, filter=filter_str, prn=packet_handler, store=0)
    except PermissionError:
        with test_thread_lock:
            test_output.append("Error: Packet sniffing requires admin privileges. Run the app with sudo or as administrator.")
        packet_sniffer_running = False
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in packet sniffer: {str(e)}")
        packet_sniffer_running = False

def run_packet_sniffer(protocols, interface):
    """Run the packet sniffer that captures DSCP values"""
    global sniffer_thread
    sniffer_thread = threading.Thread(target=start_packet_sniffer, args=(protocols, interface))
    sniffer_thread.daemon = True
    sniffer_thread.start()

def get_interfaces_with_names():
    """Retrieve interfaces with both NPF names and friendly names, tailored to user's system."""
    interfaces = []
    seen_npfs = set()
    raw_interfaces = get_windows_if_list()
    scapy_ifaces = get_if_list()

    for iface in raw_interfaces:
        description = iface.get('description', '')
        name = iface.get('name', description)
        guid = iface.get('guid', '')
        ips = iface.get('ips', [])

        npf_name = None
        for scapy_iface in scapy_ifaces:
            if guid and guid.lower() in scapy_iface.lower():
                npf_name = scapy_iface
                break
        if not npf_name or npf_name in seen_npfs:
            continue
        seen_npfs.add(npf_name)

        is_connected = bool(ips and any(ip.startswith(('192.', '10.', '172.', 'fe80::', '169.254.')) for ip in ips))
        if not is_connected and not any(kw in description.lower() for kw in ['wi-fi', 'ethernet', 'virtualbox']):
            continue

        ipconfig_name = name
        if "Intel(R) Wi-Fi 6 AX201" in description:
            ipconfig_name = "Wi-Fi"
        elif "VirtualBox Host-Only" in description:
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
        elif "WAN Miniport" in description:
            continue
        elif any(fw in description for fw in ["WFP", "Npcap", "QoS", "VirtualBox NDIS", "Native WiFi"]):
            continue

        interfaces.append({
            'npf_name': npf_name,
            'friendly_name': ipconfig_name,
            'description': description,
            'is_connected': is_connected
        })

    return interfaces

@control_bp.route('/controlpackets')
def control_packets():
    interfaces = get_interfaces_with_names()
    return render_template('controlpackets.html', interfaces=interfaces)

@control_bp.route('/start_test', methods=['POST'])
def start_test():
    global test_process, test_output, test_running, test_progress, test_metrics, sent_timestamps
    data = request.get_json()

    background = data.get('background', {})
    background_type = background.get('type', 'none')
    iperf_server = background.get('server', '').strip()
    iperf_port = background.get('port', '').strip()
    duration = int(background.get('duration', 30))
    interface = background.get('interface', 'auto')

    protocols = data.get('protocols', {})

    if not protocols:
        return jsonify({'status': 'error', 'message': 'At least one protocol must be selected'})

    if duration < 1 or duration > 300:
        return jsonify({'status': 'error', 'message': 'Duration must be between 1 and 300 seconds'})

    if not os.path.exists(IPERF_PATH):
        return jsonify({'status': 'error', 'message': f'iperf3 executable not found at {IPERF_PATH}'})

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
        dscp_packets.clear()

    try:
        run_packet_sniffer(protocols, interface)
        bg_thread = threading.Thread(target=run_background_traffic, args=(background_type, iperf_server, iperf_port, duration))
        bg_thread.start()

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

        for thread in protocol_threads:
            thread.start()

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

        timeout = duration + 10
        bg_thread.join(timeout)
        for thread in protocol_threads:
            thread.join(timeout)
        progress_thread.join(timeout)

        if bg_thread.is_alive() or any(thread.is_alive() for thread in protocol_threads) or progress_thread.is_alive():
            print("Warning: Some threads did not terminate within timeout")
            cleanup_test()

    except Exception as e:
        print(f"Error during test execution: {str(e)}")
        cleanup_test()
        return jsonify({'status': 'error', 'message': f'Test failed: {str(e)}'})

    finally:
        cleanup_test()

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
            time.sleep(interval)
            packet_id += 1
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DNS traffic: {str(e)}")

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
            test_process = None
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in background traffic: {str(e)}")
            test_process = None

def run_dhcp_traffic(interface, server, renew, duration):
    global test_output, test_metrics
    try:
        start_time = time.time()
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

        cmd_renew = ['ipconfig', '/renew']
        print(f"Running DHCP renew command: {' '.join(cmd_renew)}")
        process = subprocess.Popen(cmd_renew, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        output, _ = process.communicate()
        with test_thread_lock:
            test_metrics['dhcp']['duration'] = time.time() - start_time
            test_metrics['dhcp']['success'] = "successfully" in output.lower()
    except Exception as e:
        with test_thread_lock:
            test_output.append(f"Error in DHCP traffic: {str(e)} (Note: DHCP on Windows requires admin privileges)")

def run_icmp_traffic(target, size, interval, continuous, count, duration):
    global test_output, test_metrics, sent_timestamps, test_running
    try:
        # Validate parameters
        size = int(size) if size else 32
        interval = float(interval) if interval else 1.0
        count = int(count) if count else 5
        duration = float(duration) if duration else 30.0
        if not target:
            raise ValueError("Target IP is empty or invalid")

        packet_id = 0
        if continuous:
            print(f"Starting continuous ICMP traffic to {target} for {count} pings, interval {interval}s")
            start_time = time.time()
            ping_count = 0
            while (time.time() - start_time < duration and 
                   ping_count < count and 
                   test_running):
                cmd = ['ping', '-n', '1', '-l', str(size), target]
                print(f"Executing: {' '.join(cmd)}")
                try:
                    with test_thread_lock:
                        test_metrics['icmp']['sent'] += 1
                        sent_timestamps.setdefault('icmp', {})[packet_id] = time.time()
                    process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.PIPE, 
                        text=True
                    )
                    output, error = process.communicate(timeout=10)  # Timeout to prevent hanging
                    with test_thread_lock:
                        test_output.append(output or error or "No output from ping")
                    if process.returncode != 0:
                        print(f"Ping failed: {error}")
                        test_output.append(f"Ping error: {error}")
                except subprocess.TimeoutExpired:
                    print("Ping timed out")
                    test_output.append("Ping timed out")
                    process.kill()
                except Exception as e:
                    print(f"Subprocess error: {str(e)}")
                    test_output.append(f"Subprocess error: {str(e)}")
                time.sleep(interval)
                packet_id += 1
                ping_count += 1
            print(f"Completed {ping_count} pings")
        else:
            cmd = ['ping', '-n', str(count), '-l', str(size), target]
            print(f"Executing: {' '.join(cmd)}")
            try:
                with test_thread_lock:
                    test_metrics['icmp']['sent'] += count
                    sent_timestamps.setdefault('icmp', {})[packet_id] = time.time()
                process = subprocess.Popen(
                    cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                output, error = process.communicate(timeout=count * 10)  # Adjust timeout
                with test_thread_lock:
                    test_output.append(output or error or "No output from ping")
                if process.returncode != 0:
                    print(f"Ping failed: {error}")
                    test_output.append(f"Ping error: {error}")
            except subprocess.TimeoutExpired:
                print("Ping timed out")
                test_output.append("Ping timed out")
                process.kill()
            except Exception as e:
                print(f"Subprocess error: {str(e)}")
                test_output.append(f"Subprocess error: {str(e)}")
    except Exception as e:
        error_msg = f"Error in ICMP traffic: {str(e)}"
        print(error_msg)
        with test_thread_lock:
            test_output.append(error_msg)
            

def cleanup_test():
    global test_running, test_process, test_progress, packet_sniffer_running, sniffer_thread
    with test_thread_lock:
        test_running = False
        test_progress = 100
        packet_sniffer_running = False
        if test_process and test_process.poll() is None:
            try:
                os.kill(test_process.pid, signal.SIGTERM)
            except Exception as e:
                print(f"Error terminating test process: {str(e)}")
            test_process = None
    if sniffer_thread and sniffer_thread.is_alive():
        sniffer_thread.join(timeout=2)
        sniffer_thread = None
    print("Test cleanup completed")

@control_bp.route('/test_status')
def test_status():
    with test_thread_lock:
        return jsonify({
            'running': test_running,
            'progress': test_progress,
            'console_output': test_output
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

@control_bp.route('/api/packets')
def get_packets():
    with test_thread_lock:
        return jsonify(list(dscp_packets))

@control_bp.route('/stop_test', methods=['POST'])
def stop_test():
    print("Stop test requested")
    cleanup_test()
    return jsonify({'status': 'success'})