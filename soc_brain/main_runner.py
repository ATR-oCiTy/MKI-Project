# main_runner.py
import threading
from live_sensor import analyze_traffic, load_models
from dashboard_api import run_dashboard_server
import time
import sys
import logging

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting Autonomous SOC Platform...")
    
    # 1. Start the Dashboard API in a background thread
    api_thread = threading.Thread(target=run_dashboard_server, daemon=True)
    api_thread.start()
    
    # 2. Load ML Models
    model_binary, model_multi = load_models()
    
    # 3. Start packet capture threads
    interfaces = ["eth0", "eth1"]
    capture_threads = []
    
    for iface in interfaces:
        capture_thread = threading.Thread(target=analyze_traffic, args=(iface, model_binary, model_multi), daemon=True)
        capture_thread.start()
        capture_threads.append(capture_thread)
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Halting execution gracefully.")
        sys.exit(0)
