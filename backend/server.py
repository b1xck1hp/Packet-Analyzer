from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, DNS, Raw
import keyboard
import logging
import threading
from datetime import datetime, timedelta
import json
from flask import Flask, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import requests
import uuid
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import socket
import sys
from cowrie_manager import CowrieManager
from wsl_manager import WSLManager

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

API_KEY = os.getenv('ABUSEIPDB_API_KEY')
BASE_URL = os.getenv('ABUSEIPDB_BASE_URL')

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
SENDER_PASSWORD = os.getenv('SENDER_PASSWORD')
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL')
ALERT_COOLDOWN_MINUTES = int(os.getenv('ALERT_COOLDOWN_MINUTES', 5))

# Cache and blocked items storage
CACHE_FILE = os.getenv('CACHE_FILE', 'ip_cache.json')
BLOCKED_ITEMS_FILE = os.getenv('BLOCKED_ITEMS_FILE', 'blocked_items.json')
CACHE_EXPIRY_DAYS = int(os.getenv('CACHE_EXPIRY_DAYS', 7))  # Cache results for 7 days

class IPCache:
    def __init__(self):
        self.cache = {}
        self.load_cache()

    def load_cache(self):
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, 'r') as f:
                    cached_data = json.load(f)
                    # Filter out expired entries
                    current_time = datetime.now()
                    self.cache = {
                        ip: data for ip, data in cached_data.items()
                        if datetime.fromisoformat(data['timestamp']) + timedelta(days=CACHE_EXPIRY_DAYS) > current_time
                    }
        except Exception as e:
            logging.error(f"Error loading IP cache: {e}")
            self.cache = {}

    def save_cache(self):
        try:
            with open(CACHE_FILE, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            logging.error(f"Error saving IP cache: {e}")

    def get(self, ip):
        if ip in self.cache:
            cached_time = datetime.fromisoformat(self.cache[ip]['timestamp'])
            if cached_time + timedelta(days=CACHE_EXPIRY_DAYS) > datetime.now():
                return self.cache[ip]['suspicious']
        return None

    def set(self, ip, suspicious):
        self.cache[ip] = {
            'suspicious': suspicious,
            'timestamp': datetime.now().isoformat()
        }
        # Save to file periodically (every 10 new entries)
        if len(self.cache) % 10 == 0:
            self.save_cache()

ip_cache = IPCache()
blocked_ips = []
blocked_ports = []

def load_blocked_items():
    global blocked_ips, blocked_ports
    try:
        if os.path.exists(BLOCKED_ITEMS_FILE):
            with open(BLOCKED_ITEMS_FILE, 'r') as f:
                data = json.load(f)
                blocked_ips = data.get('blocked_ips', [])
                blocked_ports = data.get('blocked_ports', [])
    except Exception as e:
        logging.error(f"Error loading blocked items: {e}")
        blocked_ips = []
        blocked_ports = []

def save_blocked_items():
    try:
        with open(BLOCKED_ITEMS_FILE, 'w') as f:
            json.dump({
                'blocked_ips': blocked_ips,
                'blocked_ports': blocked_ports
            }, f, indent=2)
    except Exception as e:
        logging.error(f"Error saving blocked items: {e}")

class AlertTracker:
    def __init__(self):
        self.alerts = {}  # Format: {'alert_type_key': {'last_sent': timestamp, 'details': str}}
        
    def should_send_alert(self, alert_type_key):
        if alert_type_key not in self.alerts:
            return True
            
        last_sent = self.alerts[alert_type_key]['last_sent']
        time_diff = datetime.now() - last_sent
        return time_diff.total_seconds() >= (ALERT_COOLDOWN_MINUTES * 60)
        
    def update_alert_timestamp(self, alert_type_key, details):
        self.alerts[alert_type_key] = {
            'last_sent': datetime.now(),
            'details': details
        }

def send_email_alert(subject, body_data):
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = f"🚨 SILENT GUARDIANS - CRITICAL SECURITY ALERT: {subject}"

        # Create HTML version of the email
        html = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    line-height: 1.6;
                    color: #2d3748;
                    margin: 0;
                    padding: 20px;
                    background-color: #f7fafc;
                }}
                .container {{
                    max-width: 700px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    padding: 0;
                    border-radius: 8px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                }}
                .header {{
                    background: linear-gradient(135deg, #1a365d 0%, #2c5282 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px 8px 0 0;
                    text-align: center;
                }}
                .team-name {{
                    font-size: 18px;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                    margin-bottom: 10px;
                    color: #e2e8f0;
                }}
                .warning-icon {{
                    font-size: 56px;
                    margin-bottom: 10px;
                }}
                .alert-title {{
                    font-size: 24px;
                    font-weight: 600;
                    margin: 0;
                }}
                .severity-indicator {{
                    display: inline-block;
                    padding: 8px 16px;
                    background-color: #fee2e2;
                    color: #dc2626;
                    border-radius: 20px;
                    font-weight: 600;
                    margin: 10px 0;
                }}
                .action-required {{
                    background-color: #fef2f2;
                    border: 2px solid #dc2626;
                    padding: 15px;
                    margin: 20px 0;
                    border-radius: 8px;
                    text-align: center;
                }}
                .action-title {{
                    color: #dc2626;
                    font-size: 20px;
                    font-weight: 600;
                    margin-bottom: 10px;
                }}
                .action-text {{
                    font-size: 16px;
                    color: #1a202c;
                }}
                .details-section {{
                    background-color: #f8fafc;
                    padding: 20px;
                    border-radius: 6px;
                    margin: 15px 0;
                    border: 1px solid #e2e8f0;
                }}
                .section-title {{
                    color: #1e40af;
                    font-size: 18px;
                    font-weight: 600;
                    margin-bottom: 15px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }}
                .info-grid {{
                    display: grid;
                    grid-template-columns: repeat(2, 1fr);
                    gap: 15px;
                }}
                .info-item {{
                    background: white;
                    padding: 12px;
                    border-radius: 4px;
                    border: 1px solid #e2e8f0;
                }}
                .label {{
                    font-weight: 600;
                    color: #4a5568;
                    display: block;
                    margin-bottom: 4px;
                }}
                .value {{
                    color: #1a202c;
                    word-break: break-all;
                }}
                .value.danger {{
                    color: #dc2626;
                    font-weight: 600;
                }}
                .timestamp {{
                    text-align: right;
                    color: #718096;
                    font-size: 13px;
                    margin-top: 20px;
                    font-family: monospace;
                }}
                .footer {{
                    background-color: #f8fafc;
                    padding: 15px;
                    text-align: center;
                    font-size: 13px;
                    color: #4a5568;
                    border-top: 1px solid #e2e8f0;
                    border-radius: 0 0 8px 8px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div class="team-name">Silent Guardians</div>
                    <div class="warning-icon">🚨</div>
                    <h1 class="alert-title">Security Incident Detected</h1>
                    <div class="severity-indicator">IMMEDIATE ACTION REQUIRED</div>
                </div>
                
                <div class="content">
                    <div class="action-required">
                        <div class="action-title">🏃‍♂️ IMMEDIATE PHYSICAL PRESENCE REQUIRED</div>
                        <div class="action-text">
                            Please proceed to the <strong>Silent Guardians Main Building</strong> immediately.<br>
                            Your immediate attention to this security incident is required.
                        </div>
                    </div>

                    <div class="details-section">
                        <div class="section-title">
                            <span>🎯 Incident Overview</span>
                        </div>
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="label">Alert Type</span>
                                <span class="value danger">{body_data['type']}</span>
                            </div>
                            <div class="info-item">
                                <span class="label">Priority</span>
                                <span class="value danger">CRITICAL</span>
                            </div>
                        </div>
                        <div class="info-item" style="margin-top: 15px;">
                            <span class="label">Description</span>
                            <span class="value">{body_data['details']}</span>
                        </div>
                    </div>

                    <div class="details-section">
                        <div class="section-title">
                            <span>🔍 Technical Details</span>
                        </div>
                        <div class="info-grid">
                            <div class="info-item">
                                <span class="label">Source IP</span>
                                <span class="value">{body_data['source_ip'] if body_data['source_ip'] else 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="label">Destination IP</span>
                                <span class="value">{body_data['dest_ip'] if body_data['dest_ip'] else 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="label">Protocol</span>
                                <span class="value">{body_data['protocol'] if body_data['protocol'] else 'N/A'}</span>
                            </div>
                            <div class="info-item">
                                <span class="label">Port</span>
                                <span class="value">{body_data['port'] if body_data['port'] else 'N/A'}</span>
                            </div>
                        </div>
                    </div>

                    <div class="timestamp">
                        <strong>Detection Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </div>
                </div>

                <div class="footer">
                    <p><strong>🔐 Silent Guardians - Security Operations Center</strong><br>
                    This is a critical security alert requiring immediate physical presence.<br>
                    Please proceed to the main building immediately.</p>
                    <p style="margin: 0;">Incident ID: SG-{uuid.uuid4().hex[:8].upper()}</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Create plain text version as fallback
        text = f"""
SILENT GUARDIANS - CRITICAL SECURITY ALERT: {subject}

⚠️ IMMEDIATE PHYSICAL PRESENCE REQUIRED ⚠️

ACTION REQUIRED:
Please proceed to the Silent Guardians Main Building immediately.
Your immediate attention to this security incident is required.

INCIDENT OVERVIEW:
----------------
Alert Type: {body_data['type']}
Priority: CRITICAL
Description: {body_data['details']}

TECHNICAL DETAILS:
----------------
Source IP: {body_data['source_ip'] if body_data['source_ip'] else 'N/A'}
Destination IP: {body_data['dest_ip'] if body_data['dest_ip'] else 'N/A'}
Protocol: {body_data['protocol'] if body_data['protocol'] else 'N/A'}
Port: {body_data['port'] if body_data['port'] else 'N/A'}

Detection Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
Incident ID: SG-{uuid.uuid4().hex[:8].upper()}

🔐 Silent Guardians - Security Operations Center
This is a critical security alert requiring immediate physical presence.
Please proceed to the main building immediately.
        """

        # Attach both plain text and HTML versions
        msg.attach(MIMEText(text, 'plain'))
        msg.attach(MIMEText(html, 'html'))
        
        # Add high importance headers
        msg['X-Priority'] = '1'
        msg['X-MSMail-Priority'] = 'High'
        msg['Importance'] = 'High'
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        logging.info(f"Silent Guardians security alert email sent successfully - Subject: {subject}")
    except Exception as e:
        logging.error(f"Failed to send security alert email: {str(e)}", exc_info=True)
        raise

def handle_suspicious_activity(activity_type, details, source_ip=None, dest_ip=None, protocol=None, port=None):
    """
    Handle suspicious activity and send alerts if needed
    """
    # Create a unique key for this type of alert
    alert_components = []
    if source_ip:
        alert_components.append(f"src:{source_ip}")
    if dest_ip:
        alert_components.append(f"dst:{dest_ip}")
    if protocol:
        alert_components.append(f"proto:{protocol}")
    if port:
        alert_components.append(f"port:{port}")
    
    alert_key = f"{activity_type}_{'.'.join(alert_components)}"
    
    if alert_tracker.should_send_alert(alert_key):
        subject = f"{activity_type}"
        body_data = {
            'type': activity_type,
            'details': details,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'protocol': protocol,
            'port': port
        }
        send_email_alert(subject, body_data)
        alert_tracker.update_alert_timestamp(alert_key, details)

# Initialize alert tracker
alert_tracker = AlertTracker()

# Initialize WSL manager and get password
wsl_manager = WSLManager()
if not wsl_manager.initialize():
    logging.error("Failed to initialize WSL. Exiting...")
    sys.exit(1)

# Initialize Cowrie Manager
cowrie = CowrieManager(wsl_manager)

# Load blocked items from file
load_blocked_items()

def check_ip_suspicious(ip_address, packet_data=None):
    """
    Check if an IP is suspicious
    packet_data: Optional dictionary containing full packet information
    """
    # Check if IP is blocked
    if any(blocked_ip['ip'] == ip_address for blocked_ip in blocked_ips):
        if packet_data:
            handle_suspicious_activity(
                "Blocked IP Detected",
                f"Connection attempt from blocked IP: {ip_address}",
                source_ip=packet_data['sourceIP'],
                dest_ip=packet_data['destinationIP'],
                protocol=packet_data['protocol'],
                port=f"{packet_data['sourcePort']}->{packet_data['destinationPort']}" if packet_data['sourcePort'] and packet_data['destinationPort'] else None
            )
        return True

    # Check in-memory/file cache first
    cached_result = ip_cache.get(ip_address)
    if cached_result is not None:
        if cached_result and packet_data:  # If IP is suspicious
            handle_suspicious_activity(
                "Suspicious IP Activity",
                f"Connection from previously identified suspicious IP: {ip_address}",
                source_ip=packet_data['sourceIP'],
                dest_ip=packet_data['destinationIP'],
                protocol=packet_data['protocol'],
                port=f"{packet_data['sourcePort']}->{packet_data['destinationPort']}" if packet_data['sourcePort'] and packet_data['destinationPort'] else None
            )
        return cached_result

    # If not in cache, check with API
    headers = {
        'Key': API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90',
    }
    try:
        response = requests.get(BASE_URL, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                ip_info = data['data']
                is_suspicious = ip_info.get('abuseConfidenceScore', 0) > 50
                # Cache the result
                ip_cache.set(ip_address, is_suspicious)
                return is_suspicious
    except Exception as e:
        logging.error(f"Error checking IP {ip_address}: {e}")
        return False
    
    return False

def check_port_suspicious(source_port, dest_port):
    # Check if ports are blocked
    is_suspicious = any(
        (blocked_port['port'] == source_port and blocked_port['type'] == 'source') or
        (blocked_port['port'] == dest_port and blocked_port['type'] == 'destination')
        for blocked_port in blocked_ports
    )
    
    if is_suspicious:
        handle_suspicious_activity(
            "Blocked Port Activity",
            f"Connection attempt using blocked port(s): source={source_port}, dest={dest_port}",
            port=f"{source_port}->{dest_port}"
        )
    
    return is_suspicious

def detect_application_protocol(packet, sport, dport):
    common_ports = {
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        110: 'POP3',
        143: 'IMAP',
        3306: 'MySQL',
        5432: 'PostgreSQL'
    }
    
    # Check if either port is a well-known port
    if sport in common_ports:
        return common_ports[sport]
    if dport in common_ports:
        return common_ports[dport]
        
    # Try to detect HTTP/HTTPS from payload
    if Raw in packet:
        payload = str(packet[Raw].load)
        if any(method in payload for method in ['GET ', 'POST ', 'HTTP/']):
            return 'HTTP'
    
    # If no application protocol detected, return transport protocol
    if TCP in packet:
        return 'TCP'
    elif UDP in packet:
        return 'UDP'
    elif ICMP in packet:
        return 'ICMP'
    
    return 'UNKNOWN'

class PacketSniffer:
    def __init__(self):
        self.packet_count = 0
        self.continue_capture = True

    def process_packet(self, packet):
        self.packet_count += 1
        packet_data = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.fromtimestamp(packet.time).isoformat(),
            'sourcePort': None,
            'destinationPort': None,
            'sourceIP': None,
            'destinationIP': None,
            'protocol': None,
            'size': len(packet),
            'isSuspicious': False
        }

        # Extract all packet information first
        if IP in packet:
            packet_data['sourceIP'] = packet[IP].src
            packet_data['destinationIP'] = packet[IP].dst
            
            # Get source and destination ports
            if TCP in packet:
                packet_data['sourcePort'] = packet[TCP].sport
                packet_data['destinationPort'] = packet[TCP].dport
            elif UDP in packet:
                packet_data['sourcePort'] = packet[UDP].sport
                packet_data['destinationPort'] = packet[UDP].dport

            # Detect protocol
            packet_data['protocol'] = detect_application_protocol(
                packet,
                packet_data['sourcePort'],
                packet_data['destinationPort']
            )

            # Check IPs and track suspicious activity with full packet data
            source_suspicious = check_ip_suspicious(packet_data['sourceIP'], packet_data)
            dest_suspicious = check_ip_suspicious(packet_data['destinationIP'], packet_data)
            packet_data['isSuspicious'] = source_suspicious or dest_suspicious

            # Check if ports are suspicious
            if packet_data['sourcePort'] and packet_data['destinationPort']:
                port_suspicious = check_port_suspicious(packet_data['sourcePort'], packet_data['destinationPort'])
                if port_suspicious:
                    packet_data['isSuspicious'] = True
                    handle_suspicious_activity(
                        "Suspicious Port Activity",
                        f"Connection attempt using suspicious port(s): source={packet_data['sourcePort']}, dest={packet_data['destinationPort']}",
                        source_ip=packet_data['sourceIP'],
                        dest_ip=packet_data['destinationIP'],
                        protocol=packet_data['protocol'],
                        port=f"{packet_data['sourcePort']}->{packet_data['destinationPort']}"
                    )

        socketio.emit('packet', packet_data)

    def capture_packets(self):
        logging.info("Starting packet capture...")
        sniff(prn=self.process_packet, store=0)

    def stop_capture(self):
        self.continue_capture = False
        logging.info("Packet capture stopped.")

@app.route('/health')
def health_check():
    return {'status': 'healthy'}

# Admin Socket.IO events
@socketio.on('getBlockedIPs')
def handle_get_blocked_ips():
    socketio.emit('blockedIPs', blocked_ips)

@socketio.on('getBlockedPorts')
def handle_get_blocked_ports():
    socketio.emit('blockedPorts', blocked_ports)

@socketio.on('addBlockedIP')
def handle_add_blocked_ip(ip):
    if ip not in [item['ip'] for item in blocked_ips]:
        blocked_ips.append({
            'ip': ip,
            'timestamp': datetime.now().isoformat()
        })
        save_blocked_items()
        socketio.emit('blockedIPs', blocked_ips)
    return {'status': 'success', 'blocked_ips': blocked_ips}

@socketio.on('removeBlockedIP')
def handle_remove_blocked_ip(ip):
    global blocked_ips
    blocked_ips = [item for item in blocked_ips if item['ip'] != ip]
    save_blocked_items()
    socketio.emit('blockedIPs', blocked_ips)
    return {'status': 'success', 'blocked_ips': blocked_ips}

@socketio.on('addBlockedPort')
def handle_add_blocked_port(data):
    port = data.get('port')
    port_type = data.get('type', 'source')
    if not any(item['port'] == port and item['type'] == port_type for item in blocked_ports):
        blocked_ports.append({
            'port': port,
            'type': port_type,
            'timestamp': datetime.now().isoformat()
        })
        save_blocked_items()
        socketio.emit('blockedPorts', blocked_ports)
    return {'status': 'success', 'blocked_ports': blocked_ports}

@socketio.on('removeBlockedPort')
def handle_remove_blocked_port(data):
    global blocked_ports
    port = data.get('port')
    port_type = data.get('type', 'source')
    blocked_ports = [item for item in blocked_ports if not (item['port'] == port and item['type'] == port_type)]
    save_blocked_items()
    socketio.emit('blockedPorts', blocked_ports)
    return {'status': 'success', 'blocked_ports': blocked_ports}

# Server configuration
SERVER_PORT = int(os.getenv('SERVER_PORT', 5000))
MAX_PORT_ATTEMPTS = int(os.getenv('MAX_PORT_ATTEMPTS', 5))

def find_available_port(start_port, max_attempts):
    """Try to find an available port starting from start_port"""
    for port in range(start_port, start_port + max_attempts):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.bind(('0.0.0.0', port))
            test_socket.close()
            return port
        except OSError:
            continue
    return None

if __name__ == "__main__":
    # Initialize managers
    sniffer = PacketSniffer()
    cowrie = CowrieManager(wsl_manager)
    
    # Start packet capture
    capture_thread = threading.Thread(target=sniffer.capture_packets)
    capture_thread.daemon = True
    capture_thread.start()

    # Start Cowrie honeypot
    if not cowrie.start_cowrie():
        logging.error("Failed to start Cowrie honeypot")
    
    try:
        port = find_available_port(SERVER_PORT, MAX_PORT_ATTEMPTS)
        if port:
            socketio.run(app, host='0.0.0.0', port=port, debug=True, use_reloader=False)
        else:
            logging.error(f"Could not find an available port after {MAX_PORT_ATTEMPTS} attempts")
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
        sniffer.stop_capture()
        cowrie.stop_cowrie()
    except Exception as e:
        logging.error(f"Server error: {e}")
        sniffer.stop_capture()
        cowrie.stop_cowrie()