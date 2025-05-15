from flask import Blueprint, jsonify, session, request
from flask_socketio import SocketIO, emit
from scapy.all import conf, sniff, IP, UDP, TCP
from datetime import datetime
import threading
import os

sniffing_bp = Blueprint('sniffing', __name__, template_folder='../../templates')
socketio = SocketIO()

# Global variables
sniffing = False
capture_thread = None
packet_cache = []
INTERFACE = None

def get_available_interfaces():
    """Get list of available capture interfaces using Scapy"""
    try:
        conf.ifaces.reload()
        interfaces = []
        for iface in conf.ifaces.data.values():
            if hasattr(iface, 'description') and iface.description:
                interfaces.append({
                    'guid': iface.name,
                    'friendly_name': iface.description
                })
        return interfaces if interfaces else [{"guid": None, "friendly_name": "No interfaces found - Run as Administrator?"}]
    except Exception as e:
        print(f"Interface detection error: {e}")
        return [{"guid": None, "friendly_name": "No interfaces found - Run as Administrator?"}]

def find_best_interface():
    """Select the best interface for capturing traffic"""
    interfaces = get_available_interfaces()
    print("Available interfaces:", interfaces)
    for iface in interfaces:
        if iface['guid'] is None:
            continue
        if 'Wi-Fi' in iface['friendly_name'] or 'Ethernet' in iface['friendly_name']:
            return iface['guid']
    return interfaces[0]['guid'] if interfaces[0]['guid'] else None

def capture_packets(server_ip, dscp_values):
    """Capture packets with filter for server IP and send via WebSocket"""
    global sniffing, INTERFACE, packet_cache
    
    if INTERFACE is None:
        socketio.emit('error', {'message': 'No interface selected'})
        return
    
    print(f"Starting capture on {INTERFACE} with filter: host {server_ip}")
    
    def packet_callback(packet):
        if IP in packet and (packet[IP].src == server_ip or packet[IP].dst == server_ip):
            protocol = 'Unknown'
            if UDP in packet:
                protocol = 'UDP'
            elif TCP in packet:
                protocol = 'TCP'
            tos = packet[IP].tos
            dscp = tos >> 2
            is_dscp_valid = str(dscp) in dscp_values
            new_packet = {
                'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src': packet[IP].src,
                'dest': packet[IP].dst,
                'protocol': protocol,
                'dscp': dscp,
                'is_dscp_valid': is_dscp_valid
            }
            print(f"Packet captured: {new_packet['src']} -> {new_packet['dest']}, Protocol: {protocol}, DSCP: {dscp}, Valid: {is_dscp_valid}")
            packet_cache.append(new_packet)
            if len(packet_cache) > 50:
                packet_cache.pop(0)
            socketio.emit('packet_update', new_packet)
    
    try:
        sniff(iface=INTERFACE, filter=f"host {server_ip}", prn=packet_callback, store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        print(f"Capture error: {e}")
        socketio.emit('error', {'message': f'Capture error: {str(e)}'})

@sniffing_bp.route('/store_sniffing_params', methods=['POST'])
def store_sniffing_params():
    """Store server IP and DSCP values in session for sniffing"""
    data = request.json
    session['server_ip'] = data.get('server_ip')
    session['dscp_values'] = data.get('dscp_values', [])
    return jsonify({'status': 'Parameters stored'})

@sniffing_bp.route('/start_sniffing_two_clients', methods=['POST'])
def start_sniffing_two_clients():
    """Start packet capture for two clients"""
    global sniffing, capture_thread, INTERFACE
    
    if not INTERFACE:
        INTERFACE = find_best_interface()
        if not INTERFACE:
            return jsonify({'status': 'No valid interface found'}), 400
    
    if not sniffing:
        server_ip = session.get('server_ip')
        dscp_values = session.get('dscp_values', [])
        if not server_ip or not dscp_values:
            return jsonify({'status': 'Server IP or DSCP values not set in session'}), 400
        
        sniffing = True
        capture_thread = threading.Thread(target=capture_packets, args=(server_ip, dscp_values))
        capture_thread.start()
        return jsonify({'status': 'Sniffing started', 'interface': INTERFACE})
    return jsonify({'status': 'Already sniffing'})

@sniffing_bp.route('/stop_sniffing_two_clients', methods=['POST'])
def stop_sniffing_two_clients():
    """Stop packet capture"""
    global sniffing, packet_cache
    
    if sniffing:
        sniffing = False
        if capture_thread:
            capture_thread.join()
        packet_cache = []
        return jsonify({'status': 'Sniffing stopped'})
    return jsonify({'status': 'Not sniffing'})

@sniffing_bp.route('/get_sniffed_packets', methods=['GET'])
def get_sniffed_packets():
    """Get captured packets (polling fallback)"""
    global packet_cache
    return jsonify({'packets': packet_cache})

@sniffing_bp.route('/get_interfaces', methods=['GET'])
def get_interfaces():
    """Get available interfaces"""
    interfaces = get_available_interfaces()
    return jsonify({
        'interfaces': [iface['friendly_name'] for iface in interfaces],
        'interface_details': interfaces,
        'recommended': find_best_interface()
    })

@socketio.on('connect')
def handle_connect():
    print("Client connected to WebSocket")
    emit('test_message', {'message': 'WebSocket connected'})