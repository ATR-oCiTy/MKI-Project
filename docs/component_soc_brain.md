# Component Documentation: SOC Sensor Brain

The **SOC Sensor Brain** is the central nervous system of the cyber range. It acts as a network router, a deep packet inspector, a machine learning inferencer, and an autonomous mitigation agent. 

## Core Modules

### 1. `live_sensor.py` (The Eyes)
This module is responsible for real-time packet capture and feature extraction.
- **NFStream Integration**: Sniffs traffic directly from the `eth0` and `eth1` interfaces. It groups raw packets into bidirectional flows based on a 10-second active timeout and a 5-second idle timeout.
- **Traffic Isolation**: Implements an explicit filter (`if not flow.src_ip.startswith("10.5.")`) to completely ignore ambient internet noise hitting the host OS, ensuring the pipeline only evaluates intra-container network traffic.
- **ML Inference**: Uses `joblib` to load the pre-trained Random Forest models. It dynamically calculates derived features (like logarithmic bytes and payload ratios) and predicts the class of the live flow.
- **Trigger**: If the binary model confidence exceeds `0.90`, it packages the flow data and triggers the `orchestrator.py` swarm asynchronously.

### 2. `orchestrator.py` (The Brain)
This module houses the LangGraph AI swarm that reasons about threats and takes action.
- **State Graph**: Defines a three-node AI workflow (`triage` -> `context` -> `response`).
- **Agents**: Uses `ChatGoogleGenerativeAI` (Gemini) equipped with structured system prompts. The agents are instructed to think like elite security engineers, evaluating blast radius and system criticality.
- **Tools**: The Response agent has access to a Python `@tool` named `block_ip`. When invoked, this tool executes a native Linux `iptables -A FORWARD -s <ip> -j DROP` command, physically blocking the attacker.
- **Protections**: 
  - **Debouncer**: Implements a strict 30-second global cooldown to prevent LLM API flooding from volumetric DoS attacks.
  - **IP Blacklist**: Maintains an in-memory `blocked_ips` set. If an attacker's IP is already mitigated, the orchestrator instantly bypasses the LLM execution for all future packets from that source.

### 3. `dashboard_api.py` (The Interface)
A Flask REST API that bridges the backend security engine with the React frontend.
- Runs in a background thread within the same process as the live sensor, allowing it to seamlessly access the in-memory `event_store`.
- **Endpoints**:
  - `/api/alerts`, `/api/mitigations`, `/api/flow`: Serves live JSON data to the UI.
  - `/api/logs`: Streams the tail of `system.log`.
  - `/api/clear_logs`: Dynamically reads `system.log`, filters out lines matching the requested category tab, and overwrites the file to clear UI logs instantly.
  - `/api/simulate_attack` & `/api/stop_attack`: Proxies attack commands directly to the isolated Attacker Node in the DMZ.
  - `/api/reset`: Flushes `iptables`, clears the `event_store`, clears the `blocked_ips` set, and stops all attacks.

### 4. `event_store.py` (The Memory)
A simple, thread-safe in-memory data structure that holds the last 100 alerts, mitigations, and LangGraph workflow events. It is continuously polled by the React dashboard.
