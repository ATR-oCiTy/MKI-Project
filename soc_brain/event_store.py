# event_store.py
# A simple in-memory data store for the dashboard API
import threading
import time
from datetime import datetime

class EventStore:
    def __init__(self):
        self.alerts = []
        self.mitigations = []
        self.flow_events = []
        self.lock = threading.Lock()
        self.last_reset_time = 0.0

    def add_alert(self, alert_data):
        with self.lock:
            alert_data["timestamp"] = datetime.now().isoformat()
            self.alerts.insert(0, alert_data)
            # Keep only the last 100 alerts
            if len(self.alerts) > 100:
                self.alerts.pop()

    def add_mitigation(self, mitigation_data):
        with self.lock:
            mitigation_data["timestamp"] = datetime.now().isoformat()
            self.mitigations.insert(0, mitigation_data)
            # Keep only the last 100 mitigations
            if len(self.mitigations) > 100:
                self.mitigations.pop()

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def get_mitigations(self):
        with self.lock:
            return list(self.mitigations)
            
    def add_flow_event(self, event_data):
        with self.lock:
            event_data["timestamp"] = datetime.now().isoformat()
            self.flow_events.append(event_data)
            if len(self.flow_events) > 50:
                self.flow_events.pop(0)
                
    def get_flow_events(self):
        with self.lock:
            return list(self.flow_events)

    def reset(self):
        with self.lock:
            self.alerts = []
            self.mitigations = []
            self.flow_events = []
            self.last_reset_time = time.time()

# Global singleton
store = EventStore()
