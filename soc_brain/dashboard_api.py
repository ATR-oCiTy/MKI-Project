# dashboard_api.py
from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import logging
import os
import urllib.request
import json
import ipaddress
from event_store import store
from orchestrator import blocked_ips

def validate_ip(ip_string):
    """Validate that the input is a legitimate IPv4 address."""
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

app = Flask(__name__)
CORS(app) # Enable CORS for the React frontend
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s', handlers=[logging.FileHandler("system.log"), logging.StreamHandler()], force=True)
logger = logging.getLogger('API')

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify(store.get_alerts())

@app.route('/api/mitigations', methods=['GET'])
def get_mitigations():
    return jsonify(store.get_mitigations())

@app.route('/api/flow', methods=['GET'])
def get_flow_events():
    return jsonify(store.get_flow_events())


@app.route('/api/logs', methods=['GET'])
def get_logs():
    logs = []
    if os.path.exists("system.log"):
        with open("system.log", "r") as f:
            lines = f.readlines()
            logs = lines[-200:]
    return jsonify({"logs": [line.strip() for line in logs]})

@app.route('/api/attacker_logs', methods=['GET'])
def get_attacker_logs():
    try:
        req = urllib.request.Request("http://10.5.1.10:5001/logs", method="GET")
        response = urllib.request.urlopen(req, timeout=2)
        return jsonify(json.loads(response.read().decode('utf-8')))
    except Exception as e:
        logger.error(f"Failed to fetch attacker logs: {e}")
        return jsonify({"logs": [f"Error fetching attacker logs: {str(e)}"]})

@app.route('/api/trigger', methods=['POST'])
def trigger_block():
    data = request.get_json()
    if not data or 'ip_address' not in data:
        return jsonify({"error": "Missing 'ip_address' in payload"}), 400
        
    source_ip = data['ip_address']
    if not validate_ip(source_ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    
    try:
        # Check if the IP is already blocked
        check_cmd = ["iptables", "-C", "FORWARD", "-s", source_ip, "-j", "DROP"]
        if subprocess.run(check_cmd, capture_output=True).returncode == 0:
            return jsonify({"status": "INFO", "message": f"IP {source_ip} is already blocked."})

        # Append a DROP rule
        command = ["iptables", "-A", "FORWARD", "-s", source_ip, "-j", "DROP"]
        subprocess.run(command, check=True, capture_output=True, text=True)
        
        # Log manual mitigation
        store.add_mitigation({
            "target_ip": source_ip,
            "action": "Manual Block",
            "status": "SUCCESS"
        })
        
        return jsonify({"status": "SUCCESS", "message": f"Manual block deployed for {source_ip}."})
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to execute manual iptables block: {e.stderr}")
        return jsonify({"status": "FAILED", "message": f"Could not execute iptables command: {e.stderr}"}), 500


@app.route('/api/simulate_attack', methods=['POST'])
def simulate_attack():
    try:
        data = request.get_json()
        req = urllib.request.Request("http://10.5.1.10:5001/attack", 
                                     data=json.dumps(data).encode('utf-8'), 
                                     headers={'Content-Type': 'application/json'})
        response = urllib.request.urlopen(req)
        return jsonify(json.loads(response.read().decode('utf-8')))
    except Exception as e:
        logger.error(f"Failed to trigger attack on attacker-node: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/stop_attack', methods=['POST'])
def stop_single_attack():
    try:
        data = request.get_json()
        req = urllib.request.Request("http://10.5.1.10:5001/stop_attack", 
                                     data=json.dumps(data).encode('utf-8'), 
                                     headers={'Content-Type': 'application/json'})
        response = urllib.request.urlopen(req)
        return jsonify(json.loads(response.read().decode('utf-8')))
    except Exception as e:
        logger.error(f"Failed to stop single attack on attacker-node: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def reset_environment():
    try:
        # Stop attacks on attacker node
        req = urllib.request.Request("http://10.5.1.10:5001/stop", method="POST")
        urllib.request.urlopen(req)
        
        # Flush iptables FORWARD chain
        subprocess.run(["iptables", "-F", "FORWARD"], check=False)
        
        # Clear in-memory store and LLM IP blocks
        store.reset()
        blocked_ips.clear()
        
        logger.info("Environment reset successfully.")
        return jsonify({"status": "SUCCESS", "message": "Environment reset. All attacks stopped and mitigations cleared."})
    except Exception as e:
        logger.error(f"Failed to reset environment: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/clear_logs', methods=['POST'])
def clear_logs():
    data = request.get_json() or {}
    category = data.get('category', 'All')
    
    if category in ['All', 'Attacker']:
        try:
            req = urllib.request.Request("http://10.5.1.10:5001/clear_logs", method="POST")
            urllib.request.urlopen(req, timeout=2)
        except Exception as e:
            logger.error(f"Failed to clear attacker logs: {e}")
            
    if category != 'Attacker':
        if category == 'All':
            open('system.log', 'w').close()
        else:
            if os.path.exists('system.log'):
                with open('system.log', 'r') as f:
                    lines = f.readlines()
                with open('system.log', 'w') as f:
                    for line in lines:
                        if f"[{category}]" not in line:
                            f.write(line)
                            
    return jsonify({"status": "SUCCESS"})

def run_dashboard_server():
    # Disable werkzeug logging for cleaner stdout
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    app.run(host='0.0.0.0', port=5000, threaded=True)
