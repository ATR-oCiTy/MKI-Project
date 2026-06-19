# live_sensor.py
# Execution: Real-time dual-interface packet capture and ML inference.
import pickle
import numpy as np
import threading
import logging
import sys
import os
from nfstream import NFStreamer
from orchestrator import trigger_swarm
from event_store import store

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - [%(name)s] %(message)s', handlers=[logging.FileHandler("system.log"), logging.StreamHandler()], force=True)
logger = logging.getLogger('Sensor')

def load_models():
    """Loads the serialized Random Forest models."""
    logger.info("Loading serialized models (rf_binary.pkl, rf_multi.pkl)...")
    if not os.path.exists("rf_binary.pkl") or not os.path.exists("rf_multi.pkl"):
        logger.error("Model files not found! Ensure train_model.py has run successfully.")
        sys.exit(1)
        
    try:
        with open("rf_binary.pkl", "rb") as f:
            model_binary = pickle.load(f)
        with open("rf_multi.pkl", "rb") as f:
            model_multi = pickle.load(f)
        return model_binary, model_multi
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        sys.exit(1)

def analyze_traffic(interface, model_binary, model_multi):
    """
    Spawns an NFStreamer instance on the designated network interface.
    Extracts NFlow metrics and executes real-time Random Forest inference.
    """
    logger.info(f"Initiating packet capture on interface: {interface}")
    
    try:
        # Initialize the streamer. Enable statistical analysis for the 11 authentic features.
        streamer = NFStreamer(source=interface, statistical_analysis=True, active_timeout=10, idle_timeout=5)
        
        for flow in streamer:
            # Discard stale flows that were captured before the environment was reset
            if (flow.bidirectional_last_seen_ms / 1000.0) < store.last_reset_time:
                continue
                
            # Isolate traffic strictly to the internal Docker network to ignore external internet noise
            if not flow.src_ip.startswith("10.5."):
                continue

            # Calculate derived features for the robust ML model
            spkts = flow.src2dst_packets
            dpkts = flow.dst2src_packets
            sbytes = flow.src2dst_bytes
            dbytes = flow.dst2src_bytes
            
            # The flow rate is total packets / duration in seconds
            dur_sec = flow.bidirectional_duration_ms / 1000.0
            rate = (spkts + dpkts) / (dur_sec if dur_sec > 0 else 0.000001)

            # Extract features matching the SMOTE-augmented model
            features = np.array([[
                flow.protocol,
                np.log1p(dur_sec),          # log_duration
                np.log1p(rate),             # log_rate
                np.log1p(sbytes),           # log_sbytes
                np.log1p(dbytes),           # log_dbytes
                dpkts / (spkts + 1e-5),     # packet_ratio
                dbytes / (sbytes + 1e-5),   # byte_ratio
                flow.src2dst_mean_ps,       # smean
                flow.dst2src_mean_ps        # dmean
            ]])
            
            # STAGE 1: Binary Inference (Normal vs Attack)
            binary_probs = model_binary.predict_proba(features)[0]
            binary_class = model_binary.classes_[np.argmax(binary_probs)]
            binary_conf = np.max(binary_probs)
            
            if binary_class == 'Attack':
                # STAGE 2: Multi-Class Categorization
                multi_probs = model_multi.predict_proba(features)[0]
                predicted_class = model_multi.classes_[np.argmax(multi_probs)]
                attack_confidence = np.max(multi_probs)
                
                logger.info(f"Flow: {flow.src_ip} -> {flow.dst_ip} | Proto: {flow.protocol} | Pkts: {flow.bidirectional_packets} | Bytes: {flow.bidirectional_bytes} | Class: {predicted_class} | BinConf: {binary_conf:.2f} | MultiConf: {attack_confidence:.2f}")
                
                # Because Stage 1 (Binary Classifier) definitively flagged this as an Anomaly,
                # we trigger the Agentic Swarm Orchestrator with the classification!
                if binary_conf >= 0.55:
                    logger.warning(f"High-confidence anomaly ({predicted_class}) detected on {interface}!")
                    logger.warning(f"Source: {flow.src_ip}:{flow.src_port} -> Dest: {flow.dst_ip}:{flow.dst_port}")
                    logger.warning(f"Type: {predicted_class} | BinConf: {binary_conf * 100:.2f}% | MultiConf: {attack_confidence * 100:.2f}%")
                    
                    # Formulate the alert payload for the Agentic Swarm
                    alert_data = {
                        "source_ip": flow.src_ip,
                        "source_port": flow.src_port,
                        "destination_ip": flow.dst_ip,
                        "destination_port": flow.dst_port,
                        "protocol": flow.protocol,
                        "confidence": float(round(attack_confidence, 4)),
                        "attack_type": str(predicted_class),
                        "duration_ms": flow.bidirectional_duration_ms,
                        "total_bytes": flow.bidirectional_bytes
                    }
                    
                    # Push to in-memory dashboard store
                    store.add_alert(alert_data)
                    
                    # Offload to the CrewAI orchestrator asynchronously
                    threading.Thread(target=trigger_swarm, args=(alert_data,), daemon=True).start()
            else:
                logger.info(f"Flow: {flow.src_ip} -> {flow.dst_ip} | Proto: {flow.protocol} | Pkts: {flow.bidirectional_packets} | Bytes: {flow.bidirectional_bytes} | Class: Normal | BinConf: {binary_conf:.2f}")
                
    except Exception as e:
        logger.error(f"Error during packet capture on interface {interface}: {e}")

if __name__ == "__main__":
    model_binary, model_multi = load_models()
    
    # eth0 connects to the DMZ (10.5.1.0/24) capturing ingress traffic.
    # eth1 connects to the Internal Network (10.5.2.0/24) capturing lateral movement.
    interfaces = ["eth0", "eth1"]
    threads = []
    
    # Spawn a dedicated background thread for each interface
    for iface in interfaces:
        capture_thread = threading.Thread(target=analyze_traffic, args=(iface, model_binary, model_multi))
        capture_thread.daemon = True
        capture_thread.start()
        threads.append(capture_thread)
    
    # Keep the main process alive to sustain the daemon threads
    try:
        while True:
            for t in threads:
                t.join(timeout=1.0)
    except KeyboardInterrupt:
        logger.info("Halting execution gracefully.")
        sys.exit(0)
