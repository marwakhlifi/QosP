from flask import Blueprint, request, jsonify
from flask_socketio import emit
from .. import socketio  # Import global socketio
from scapy.all import conf, sniff, IP, UDP, TCP
from datetime import datetime
import threading
import logging
import time
from . import sniffing_bp

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Global variables
INTERFACE = None
sniffing = False
capture_thread = None
packet_cache = []
SERVER_IP = None  # Store the server IP for filtering

def get_available_interfaces():
    """Get list of available capture interfaces using scapy"""
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
        logger.error(f"Interface detection error: {e}")
        return [{"guid": None, "friendly_name": "No interfaces found - Run as Administrator?"}]

def find_wifi_interface():
    """Select the Wi-Fi interface for capturing traffic"""
    interfaces = get_available_interfaces()
    for iface in interfaces:
        if iface['guid'] is None:
            continue
        if 'Wi-Fi' in iface['friendly_name']:
            return iface['guid']
    return None

def capture_packets():
    """Capture IP packets on Wi-Fi interface with destination matching SERVER_IP and send via WebSocket"""
    global sniffing, INTERFACE, packet_cache, SERVER_IP
    
    if INTERFACE is None:
        logger.error("No Wi-Fi interface selected")
        socketio.emit('error', {'message': 'No Wi-Fi interface selected'}, namespace='/')
        return
    
    if SERVER_IP is None:
        logger.error("No server IP specified")
        socketio.emit('error', {'message': 'No server IP specified'}, namespace='/')
        return
    
    logger.info(f"Starting capture on {INTERFACE} (filtering for dst={SERVER_IP})")
    
    def packet_callback(packet):
        if IP in packet and packet[IP].dst == SERVER_IP:
            protocol = 'Unknown'
            if UDP in packet:
                protocol = 'UDP'
            elif TCP in packet:
                protocol = 'TCP'
            tos = packet[IP].tos
            dscp = tos >> 2
            new_packet = {
                'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src': packet[IP].src,
                'dest': packet[IP].dst,
                'protocol': protocol,
                'dscp': dscp,
                'length': len(packet)
            }
            logger.debug(f"Packet captured: {new_packet['src']} -> {new_packet['dest']}, Protocol: {protocol}, DSCP: {dscp}")
            packet_cache.append(new_packet)
            if len(packet_cache) > 100:
                packet_cache.pop(0)
            try:
                socketio.emit('packet_update', new_packet, namespace='/')
                logger.debug(f"Emitted packet_update: {new_packet}")
            except Exception as e:
                logger.error(f"SocketIO emit error: {e}")
    
    try:
        sniff(iface=INTERFACE, filter=f"ip and dst {SERVER_IP}", prn=packet_callback, store=False, stop_filter=lambda x: not sniffing)
    except Exception as e:
        logger.error(f"Capture error: {e}")
        socketio.emit('error', {'message': f'Capture error: {str(e)}'}, namespace='/')
        sniffing = False

# Periodic test packet for WebSocket debugging
def send_test_packet():
    global SERVER_IP
    while True:
        if sniffing and SERVER_IP:
            test_packet = {
                'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'src': 'TEST',
                'dest': SERVER_IP,  # Use SERVER_IP as destination
                'protocol': 'TEST',
                'dscp': 0,
                'length': 0
            }
            logger.debug("Emitting test packet")
            socketio.emit('packet_update', test_packet, namespace='/')
        time.sleep(5)

@sniffing_bp.route('/set_interface', methods=['POST'])
def set_interface():
    """Set the capture interface"""
    global INTERFACE
    data = request.json
    INTERFACE = data.get('interface') or find_wifi_interface()
    if INTERFACE is None:
        return jsonify({'status': 'No Wi-Fi interface found'}), 400
    logger.info(f"Interface set to {INTERFACE}")
    return jsonify({'status': f'Interface set to {INTERFACE}'})

@sniffing_bp.route('/start_sniffing', methods=['POST'])
def start_sniffing():
    """Start packet capture with server IP filter"""
    global sniffing, capture_thread, INTERFACE, SERVER_IP
    
    if INTERFACE is None:
        INTERFACE = find_wifi_interface()
        if INTERFACE is None:
            logger.error("No Wi-Fi interface found")
            return jsonify({'status': 'No Wi-Fi interface found'}), 400
    
    if not request.is_json:
        logger.error("Request Content-Type is not application/json")
        return jsonify({'status': 'Content-Type must be application/json'}), 415
    
    data = request.get_json()
    SERVER_IP = data.get('serverIp')
    if not SERVER_IP:
        logger.error("No server IP provided")
        return jsonify({'status': 'Server IP is required'}), 400
    
    if not sniffing:
        sniffing = True
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()
        logger.info(f"Sniffing started on interface {INTERFACE} with filter dst={SERVER_IP}")
        return jsonify({'status': 'Sniffing started', 'interface': INTERFACE})
    return jsonify({'status': 'Already sniffing'})

@sniffing_bp.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    """Stop packet capture"""
    global sniffing, packet_cache
    
    if sniffing:
        sniffing = False
        if capture_thread:
            capture_thread.join()
        packet_cache = []
        logger.info("Sniffing stopped")
        return jsonify({'status': 'Sniffing stopped'})
    return jsonify({'status': 'Not sniffing'})

@sniffing_bp.route('/get_packets', methods=['GET'])
def get_packets():
    """Get captured packets (polling fallback)"""
    global packet_cache
    logger.debug(f"Returning {len(packet_cache)} packets")
    return jsonify({'packets': packet_cache})

@sniffing_bp.route('/get_interfaces', methods=['GET'])
def get_interfaces():
    """Get available interfaces"""
    interfaces = get_available_interfaces()
    recommended = find_wifi_interface()
    logger.debug(f"Available interfaces: {interfaces}")
    return jsonify({
        'interfaces': [iface['friendly_name'] for iface in interfaces],
        'interface_details': interfaces,
        'recommended': recommended
    })

@socketio.on('connect', namespace='/')
def handle_connect():
    """Handle WebSocket connection"""
    logger.info("Client connected to WebSocket")
    emit('test_message', {'message': 'WebSocket connected'}, namespace='/')

# Start test packet thread
threading.Thread(target=send_test_packet, daemon=True).start()