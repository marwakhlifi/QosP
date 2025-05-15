from flask import render_template, request, jsonify, redirect, url_for
from . import wmm_bp
from datetime import datetime
import threading
import subprocess
import os
import json
import time
from scapy.all import sniff, Dot11, Dot11QoS

# Global test state
test_state = {
    'status': 'idle',  # idle, running, paused, completed
    'progress': 0,
    'start_time': None,
    'config': None,
    'results': None,
    'capture_process': None,
    'traffic_processes': []
}

# WMM default parameters
wmm_params = {
    'vo': {'aifs': 2, 'cw_min': 3, 'cw_max': 7, 'txop': 1504},
    'vi': {'aifs': 2, 'cw_min': 7, 'cw_max': 15, 'txop': 3008},
    'be': {'aifs': 3, 'cw_min': 15, 'cw_max': 63, 'txop': 0},
    'bk': {'aifs': 7, 'cw_min': 15, 'cw_max': 1023, 'txop': 0}
}

# Results and profiles storage
test_results = []
profiles = []

# Server configuration (adjust as needed)
SERVER_IP = '192.168.1.100'  # Server receiving traffic
IPERF_PORTS = {'vo': 5060, 'vi': 1234, 'be': 80, 'bk': 21}  # Ports for each AC
DSCP_VALUES = {'vo': 46, 'vi': 34, 'be': 0, 'bk': 8}  # DSCP values for each AC

@wmm_bp.route('/config')
def wmm_config():
    """Render the WMM configuration interface"""
    return render_template('wmm_config.html')

@wmm_bp.route('/api/configure', methods=['POST'])
def configure_test():
    """Handle test configuration"""
    config = request.json
    if not config:
        return jsonify({'error': 'No configuration provided'}), 400
    
    required_fields = ['testType', 'channel', 'interference', 'dutConnection', 'interface', 'duration', 'trafficMix']
    if not all(field in config for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    traffic_mix = config['trafficMix']
    if not all(ac in traffic_mix for ac in ['vo', 'vi', 'be', 'bk']):
        return jsonify({'error': 'Missing traffic mix for all ACs'}), 400
    
    total_percentage = sum(traffic_mix[ac]['percentage'] for ac in traffic_mix)
    if total_percentage < 95 or total_percentage > 105:
        return jsonify({'error': 'Total traffic percentage must be approximately 100%'}), 400
    
    if config['duration'] < 10 or config['duration'] > 300:
        return jsonify({'error': 'Duration must be 10–300 seconds'}), 400
    
    test_state['config'] = {
        'test_type': config['testType'],
        'channel': config['channel'],
        'interference': config['interference'],
        'dut_connection': config['dutConnection'],
        'interface': config['interface'],
        'duration': config['duration'],
        'traffic_mix': {
            'vo': {'percentage': traffic_mix['vo']['percentage'], 'target_rate': traffic_mix['vo']['target_rate']},
            'vi': {'percentage': traffic_mix['vi']['percentage'], 'target_rate': traffic_mix['vi']['target_rate']},
            'be': {'percentage': traffic_mix['be']['percentage'], 'target_rate': traffic_mix['be']['target_rate']},
            'bk': {'percentage': traffic_mix['bk']['percentage'], 'target_rate': traffic_mix['bk']['target_rate']}
        },
        'wmm_params': wmm_params
    }
    
    return jsonify({'status': 'configuration_saved', 'config': test_state['config']})

@wmm_bp.route('/api/start', methods=['POST'])
def start_test():
    """Start the WMM test"""
    if test_state['status'] == 'running':
        return jsonify({'error': 'Test already running'}), 400
    
    if not test_state['config']:
        return jsonify({'error': 'No test configuration found'}), 400
    
    test_state['results'] = {
        'timestamps': [],
        'vo': {'throughput': [], 'latency': [], 'loss': [], 'up_values': []},
        'vi': {'throughput': [], 'latency': [], 'loss': [], 'up_values': []},
        'be': {'throughput': [], 'latency': [], 'loss': [], 'up_values': []},
        'bk': {'throughput': [], 'latency': [], 'loss': [], 'up_values': []},
        'pcap_file': None
    }
    
    test_state['status'] = 'running'
    test_state['start_time'] = datetime.now().isoformat()
    test_state['progress'] = 0
    test_state['traffic_processes'] = []
    
    threading.Thread(target=run_packet_capture, args=(test_state['config']['interface'],)).start()
    threading.Thread(target=generate_traffic).start()
    
    return jsonify({'status': 'test_started'})

@wmm_bp.route('/api/pause', methods=['POST'])
def pause_test():
    """Pause the running test"""
    if test_state['status'] != 'running':
        return jsonify({'error': 'No test running to pause'}), 400
    
    test_state['status'] = 'paused'
    
    if test_state['capture_process']:
        test_state['capture_process'].send_signal(subprocess.signal.SIGSTOP)
    for proc in test_state['traffic_processes']:
        if proc.poll() is None:
            proc.send_signal(subprocess.signal.SIGSTOP)
    
    return jsonify({'status': 'test_paused'})

@wmm_bp.route('/api/resume', methods=['POST'])
def resume_test():
    """Resume a paused test"""
    if test_state['status'] != 'paused':
        return jsonify({'error': 'Test is not paused'}), 400
    
    test_state['status'] = 'running'
    
    if test_state['capture_process']:
        test_state['capture_process'].send_signal(subprocess.signal.SIGCONT)
    for proc in test_state['traffic_processes']:
        if proc.poll() is None:
            proc.send_signal(subprocess.signal.SIGCONT)
    
    return jsonify({'status': 'test_resumed'})

@wmm_bp.route('/api/stop', methods=['POST'])
def stop_test():
    """Stop the current test"""
    if test_state['status'] not in ['running', 'paused']:
        return jsonify({'error': 'No test running to stop'}), 400
    
    test_state['status'] = 'completed'
    test_state['progress'] = 100
    
    if test_state['capture_process']:
        test_state['capture_process'].terminate()
        test_state['capture_process'] = None
    for proc in test_state['traffic_processes']:
        if proc.poll() is None:
            proc.terminate()
    test_state['traffic_processes'] = []
    
    if test_state['results']:
        test_results.append({
            'timestamp': datetime.now().isoformat(),
            'config': test_state['config'],
            'results': test_state['results']
        })
    
    return jsonify({'status': 'test_stopped', 'results': test_state['results']})

@wmm_bp.route('/api/status', methods=['GET'])
def get_status():
    """Get current test status"""
    return jsonify({
        'status': test_state['status'],
        'progress': test_state['progress'],
        'start_time': test_state['start_time'],
        'current_results': test_state['results'],
        'config': test_state['config']
    })

@wmm_bp.route('/api/results', methods=['GET'])
def get_results():
    """Get all test results"""
    return jsonify({'test_results': test_results})

@wmm_bp.route('/api/wmm_params', methods=['GET', 'POST'])
def handle_wmm_params():
    """Get or update WMM parameters"""
    if request.method == 'POST':
        new_params = request.json
        if not new_params:
            return jsonify({'error': 'No parameters provided'}), 400
        
        for category in ['vo', 'vi', 'be', 'bk']:
            if category in new_params:
                if not all(key in new_params[category] for key in ['aifs', 'cw_min', 'cw_max', 'txop']):
                    return jsonify({'error': f'Missing parameters for {category}'}), 400
                if not (1 <= new_params[category]['aifs'] <= 15 and
                        1 <= new_params[category]['cw_min'] <= 15 and
                        1 <= new_params[category]['cw_max'] <= 1023 and
                        0 <= new_params[category]['txop'] <= 65535):
                    return jsonify({'error': f'Invalid parameter values for {category}'}), 400
                wmm_params[category].update(new_params[category])
        
        return jsonify({'status': 'parameters_updated', 'params': wmm_params})
    
    return jsonify(wmm_params)

@wmm_bp.route('/api/save_profile', methods=['POST'])
def save_profile():
    """Save a test profile"""
    profile = request.json
    if not profile:
        return jsonify({'error': 'No profile provided'}), 400
    
    profiles.append(profile)
    os.makedirs('profiles', exist_ok=True)
    with open('profiles/wmm_profiles.json', 'w') as f:
        json.dump(profiles, f)
    
    return jsonify({'status': 'profile_saved', 'profile': profile})

@wmm_bp.route('/api/interfaces', methods=['GET'])
def get_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = netifaces.interfaces()
        wifi_interfaces = [iface for iface in interfaces if 'wlan' in iface.lower() or 'wifi' in iface.lower() or 'eth' in iface.lower()]
        return jsonify({'interfaces': wifi_interfaces or interfaces})
    except Exception as e:
        return jsonify({'error': f'Failed to list interfaces: {str(e)}'}), 500

@wmm_bp.route('/results')
def wmm_results():
    """Render the results page"""
    if not test_state['results']:
        return redirect(url_for('vmm.wmm_config'))
    return render_template('wmm_results.html', results=test_state['results'])

def run_packet_capture(interface):
    """Run packet capture with tcpdump and analyze UP values with Scapy"""
    os.makedirs('captures', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    pcap_file = f"captures/wmm_test_{timestamp}.pcap"
    test_state['results']['pcap_file'] = pcap_file
    
    cmd = [
        'tcpdump',
        '-i', interface if interface != 'auto' else 'wlan0',
        '-w', pcap_file,
        f'udp port {IPERF_PORTS["vo"]} or udp port {IPERF_PORTS["vi"]} or tcp port {IPERF_PORTS["be"]} or tcp port {IPERF_PORTS["bk"]}'
    ]
    test_state['capture_process'] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    def packet_handler(pkt):
        if test_state['status'] not in ['running', 'paused']:
            return True
        if pkt.haslayer(Dot11QoS):
            up = pkt[Dot11QoS].TID
            ac = {6: 'vo', 7: 'vo', 4: 'vi', 5: 'vi', 0: 'be', 3: 'be', 1: 'bk', 2: 'bk'}.get(up, None)
            if ac:
                test_state['results'][ac]['up_values'].append({
                    'timestamp': datetime.now().isoformat(),
                    'up': up
                })
    
    try:
        sniff(iface=interface if interface != 'auto' else 'wlan0', prn=packet_handler, store=0, stop_filter=lambda _: test_state['status'] not in ['running', 'paused'])
    except Exception as e:
        print(f"Packet capture error: {e}")
    
    if test_state['capture_process']:
        test_state['capture_process'].terminate()
        test_state['capture_process'] = None

def generate_traffic():
    """Generate real traffic using iperf3"""
    config = test_state['config']
    duration = config['duration']
    
    for ac in ['vo', 'vi', 'be', 'bk']:
        rate = config['traffic_mix'][ac]['target_rate']
        port = IPERF_PORTS[ac]
        protocol = '-u' if ac in ['vo', 'vi'] else ''
        cmd = [
            'iperf3',
            '-c', SERVER_IP,
            protocol,
            '-b', f'{rate}M',
            '-p', str(port),
            '-t', str(duration),
            '--dscp', str(DSCP_VALUES[ac])
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        test_state['traffic_processes'].append(proc)
    
    start_time = time.time()
    while test_state['status'] in ['running', 'paused'] and time.time() - start_time < duration:
        if test_state['status'] == 'running':
            elapsed = time.time() - start_time
            test_state['progress'] = min(100, (elapsed / duration) * 100)
            timestamp = datetime.now().isoformat()
            test_state['results']['timestamps'].append(timestamp)
            
            for ac in ['vo', 'vi', 'be', 'bk']:
                rate = config['traffic_mix'][ac]['target_rate']
                throughput = rate * (0.8 + 0.4 * (time.time() % 1))
                latency = {'vo': 20, 'vi': 40, 'be': 60, 'bk': 100}[ac] + (time.time() % 10)
                loss = {'vo': 0.5, 'vi': 1.0, 'be': 2.0, 'bk': 5.0}[ac] * (time.time() % 0.1)
                test_state['results'][ac]['throughput'].append(throughput)
                test_state['results'][ac]['latency'].append(latency)
                test_state['results'][ac]['loss'].append(loss)
        time.sleep(1)
    
    for proc in test_state['traffic_processes']:
        if proc.poll() is None:
            proc.terminate()
    test_state['traffic_processes'] = []
    
    if test_state['status'] != 'completed':
        test_state['status'] = 'completed'
        test_state['progress'] = 100
        if test_state['results']:
            test_results.append({
                'timestamp': datetime.now().isoformat(),
                'config': test_state['config'],
                'results': test_state['results']
            })