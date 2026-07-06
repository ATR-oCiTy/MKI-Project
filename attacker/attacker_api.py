# attacker_api.py
from flask import Flask, jsonify, request
import subprocess
import ipaddress
import logging
import os
import threading
import time

import random

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [Attacker] %(message)s', handlers=[logging.FileHandler("attacker.log"), logging.StreamHandler()])
logger = logging.getLogger(__name__)

active_attacks = {}

def validate_ip(ip_string):
    """Validate that the input is a legitimate IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

def generate_flow(attack_type, target_ip, base_source_ip="10.5.1.10", randomize_source=False):
    """Dynamically generates continuous packets to mathematically align with the UNSW-NB15 ML bounds."""
    from scapy.all import IP, TCP, UDP, sendp, Ether
    
    profiles = {
        'dos': {'proto': 'udp', 'spkts': 20, 'dpkts': 18, 'smean': 174, 'dmean': 121, 'dur': 1.88},
        'backdoors': {'proto': 'udp', 'spkts': 7, 'dpkts': 2, 'smean': 103, 'dmean': 18, 'dur': 2.6},
        'fuzzers': {'proto': 'tcp', 'spkts': 10, 'dpkts': 6, 'smean': 91, 'dmean': 45, 'dur': 0.21},
        'exploits': {'proto': 'tcp', 'spkts': 10, 'dpkts': 8, 'smean': 100, 'dmean': 44, 'dur': 0.84},
        'port_sweep': {'proto': 'tcp', 'spkts': 10, 'dpkts': 6, 'smean': 84, 'dmean': 45, 'dur': 0.18}
    }
    
    if attack_type not in profiles:
        return
        
    prof = profiles[attack_type]
    header_len = 40 if prof['proto'] == 'tcp' else 28
    ether_len = 14
    
    # Layer 2 headers ARE counted by NFStream, so we must subtract them from the payload!
    s_payload_len = max(0, prof['smean'] - header_len - ether_len)
    d_payload_len = max(0, prof['dmean'] - header_len - ether_len)
    
    total_pkts = prof['spkts'] + prof['dpkts']
    sleep_time = prof['dur'] / total_pkts if total_pkts > 0 else 0
        
    logger.info(f"Initiating {attack_type} continuous simulation loop...")
    
    while active_attacks.get(attack_type, False):
        if randomize_source:
            # Generate a random IP within the DMZ subnet to simulate spoofing or distributed attacks
            src_ip = f"10.5.1.{random.randint(2, 254)}"
        else:
            src_ip = base_source_ip
            
        sequence = []
        s_cnt = prof['spkts']
        d_cnt = prof['dpkts']
        
        while s_cnt > 0 or d_cnt > 0:
            if s_cnt > 0:
                if prof['proto'] == 'tcp':
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst=target_ip)/TCP(sport=12345, dport=80)/("X" * s_payload_len)
                else:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=src_ip, dst=target_ip)/UDP(sport=12345, dport=80)/("X" * s_payload_len)
                sequence.append(pkt)
                s_cnt -= 1
                
            if d_cnt > 0:
                if prof['proto'] == 'tcp':
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=target_ip, dst=src_ip)/TCP(sport=80, dport=12345)/("Y" * d_payload_len)
                else:
                    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=target_ip, dst=src_ip)/UDP(sport=80, dport=12345)/("Y" * d_payload_len)
                sequence.append(pkt)
                d_cnt -= 1
                
        for pkt in sequence:
            if not active_attacks.get(attack_type, False):
                break
            sendp(pkt, iface='eth0', verbose=False)
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        # Add a slight 1-second delay between flows to allow the SOC sensor to flush the flow and evaluate it
        time.sleep(1.0)
        
    logger.info(f"Attack {attack_type} thread terminated.")

# Attack types that have a validated real-tool implementation below. Anything
# else falls back to the synthetic Scapy engine even if real_tools is requested.
REAL_TOOL_SUPPORTED = {'dos', 'port_sweep'}

def generate_real_dos(target_ip, source_ip="10.5.1.10", randomize_source=False):
    """Real hping3 traffic instead of hand-crafted Scapy packets. Uses bounded
    bursts (-c 500) rather than --flood: an unbounded flood was observed to
    never surface as a completed NFStream flow at all (untested how long it
    would eventually take, if ever, under this environment's resource limits),
    while a few-hundred-packet burst reliably closes within NFStream's active
    timeout and gets classified as an attack with >90% confidence."""
    logger.info(f"Initiating REAL hping3 DoS simulation loop against {target_ip}...")
    while active_attacks.get('dos', False):
        src = f"10.5.1.{random.randint(2, 254)}" if randomize_source else source_ip
        cmd = ["hping3", "--udp", "-p", "80", "-c", "500", "-i", "u2000"]
        if src != "10.5.1.10":
            cmd += ["--spoof", src]
        cmd.append(target_ip)
        try:
            subprocess.run(cmd, capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            pass
        if not active_attacks.get('dos', False):
            break
        time.sleep(1.0)
    logger.info("Real DoS attack thread terminated.")

def generate_real_port_sweep(target_ip):
    """Real nmap scan. A genuine multi-port sweep is many separate 1-2 packet
    flows that look statistically identical to short ordinary connections to
    a per-flow classifier, so this relies on the SOC sensor's cross-flow
    burst-correlation detector (live_sensor.py) rather than the RF models to
    get flagged. Source-IP spoofing isn't supported here - nmap's spoofing
    needs raw ARP/interface tricks and won't receive replies - so this always
    scans from the attacker-node's real address."""
    logger.info(f"Initiating REAL nmap port sweep loop against {target_ip}...")
    while active_attacks.get('port_sweep', False):
        try:
            subprocess.run(["nmap", "-sT", "-p", "1-100", target_ip], capture_output=True, timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if not active_attacks.get('port_sweep', False):
            break
        time.sleep(2.0)
    logger.info("Real port sweep thread terminated.")

@app.route('/attack', methods=['POST'])
def trigger_attack():
    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "Missing target"}), 400

    target_ip = data['target']
    if not validate_ip(target_ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    attack_type = data.get('type', 'dos')
    source_ip = data.get('source_ip', '10.5.1.10')
    randomize_source = data.get('randomize_ip', False)
    use_real_tools = bool(data.get('real_tools', False))

    if attack_type in ['dos', 'port_sweep', 'exploits', 'fuzzers', 'backdoors']:
        if active_attacks.get(attack_type, False):
            return jsonify({"status": f"{attack_type} is already running."})

        active_attacks[attack_type] = True
        real_mode_active = use_real_tools and attack_type in REAL_TOOL_SUPPORTED
        tool_label = " [REAL TOOL]" if real_mode_active else ""
        logger.info(f"Initiating {attack_type} simulation against {target_ip} (Source: {source_ip}, Randomize: {randomize_source}){tool_label}")

        if real_mode_active and attack_type == 'dos':
            threading.Thread(target=generate_real_dos, args=(target_ip, source_ip, randomize_source), daemon=True).start()
        elif real_mode_active and attack_type == 'port_sweep':
            threading.Thread(target=generate_real_port_sweep, args=(target_ip,), daemon=True).start()
        else:
            if use_real_tools:
                logger.info(f"Real-tool mode requested for {attack_type}, but only {sorted(REAL_TOOL_SUPPORTED)} have a real-tool implementation - falling back to the synthetic engine.")
            threading.Thread(target=generate_flow, args=(attack_type, target_ip, source_ip, randomize_source), daemon=True).start()

        return jsonify({"status": f"{attack_type} simulation initiated against HR Portal.{tool_label}"})

    return jsonify({"error": "Unknown attack type"}), 400

@app.route('/stop_attack', methods=['POST'])
def stop_single_attack():
    data = request.get_json()
    if not data or 'type' not in data:
        return jsonify({"error": "Missing attack type"}), 400
        
    attack_type = data['type']
    if attack_type in active_attacks:
        active_attacks[attack_type] = False
        logger.info(f"Stopping {attack_type} simulation...")
        return jsonify({"status": "SUCCESS", "message": f"{attack_type} stopped."})
        
    return jsonify({"error": "Attack not running."}), 400

@app.route('/stop', methods=['POST'])
def stop_attacks():
    logger.info("Stopping all ongoing attacks...")
    for key in list(active_attacks.keys()):
        active_attacks[key] = False
    
    subprocess.run(["pkill", "-9", "hping3"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "nmap"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return jsonify({"status": "SUCCESS", "message": "All attacks stopped on Attacker Node"})

@app.route('/logs', methods=['GET'])
def get_logs():
    logs = []
    if os.path.exists("attacker.log"):
        with open("attacker.log", "r") as f:
            lines = f.readlines()
            logs = lines[-100:]
    return jsonify({"logs": [line.strip() for line in logs]})

@app.route('/clear_logs', methods=['POST'])
def clear_logs():
    open('attacker.log', 'w').close()
    return jsonify({"status": "SUCCESS"})

if __name__ == '__main__':
    # Disable werkzeug access logs for cleaner output
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5001)
