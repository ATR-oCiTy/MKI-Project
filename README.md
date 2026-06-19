# Autonomous SOC: Containerized Cyber Range

This repository deploys a fully self-contained, segmented enterprise network operating an **Autonomous Security Operations Center (SOC)**. 

It utilizes a custom **Random Forest Machine Learning Gatekeeper** trained purely on the organic *UNSW-NB15* dataset for real-time packet inspection, combined with a **LangGraph (Gemini 2.5 Flash)** multi-agent swarm for automated threat context, reasoning, and physical firewall mitigation. 

The entire environment is orchestrated within Docker Compose, simulating a hostile DMZ and a secure Internal Network, bridged entirely by a highly privileged routing container that acts as the Brain.

## Project Structure

- **`/soc_brain`**: The core AI appliance. Captures packets via `NFStream`, evaluates them against dual Random Forest models, and spawns the LangGraph swarm to execute physical `iptables` commands.
- **`/attacker`**: An isolated node in the DMZ. Runs a multi-threaded Python engine to forge mathematically-aligned raw Ethernet frames using `Scapy` and fires them into the SOC.
- **`/dashboard-ui`**: A stateless, ultra-fast React + TypeScript frontend that polls the backend APIs to display real-time network traffic, LangGraph agent workflows, and active mitigations.
- **`/docs`**: Contains the full ML Engineering Report and a standalone HTML presentation outlining the architecture and data engineering.

## Prerequisites

- Docker and Docker Compose installed on a Linux or macOS host system.
- An active Gemini API key. The LangGraph agents require API access to perform cognitive reasoning and tool execution.

## 1. Environment Configuration

Copy the example environment file and provide your API key. This key will be passed securely into the sensor container.

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY="your-actual-api-key-here"
```

## 2. Bootstrapping the Architecture

Initialize the segmented network and build the Docker images.

```bash
docker compose up --build -d
```

> **Note:** Upon initialization, the `soc-sensor-brain` container will parse the dataset, dynamically train the Random Forest models, bind to `eth0` and `eth1`, and start the Flask API. Wait approximately 10-15 seconds for this internal pipeline to finish before launching attacks.

## 3. Accessing the Command Center

You no longer need to use `docker logs` or manual shell commands to interact with the environment.

Open your browser and navigate to the React Dashboard:
**[http://localhost:5173](http://localhost:5173)**

## 4. Simulating Attacks

From the **Attacker Simulator** panel on the right side of the dashboard:
1. Select an attack vector (e.g., *Volumetric DoS*, *Exploits*, *Reconnaissance*, *Backdoor*).
2. Choose whether to use a static DMZ IP or enable **Randomize Source IP** to test volumetric defense.
3. Click **Deploy Attack**.

The dashboard will instantly communicate with the isolated `attacker-node`, which will begin forging raw Layer-2 packets and blasting them at the internal network.

## 5. The Defense Pipeline in Action

As the attack fires, watch the dashboard:
1. **Network Anomaly Chart**: You will see live bandwidth spikes exactly as the NFStream engine captures them.
2. **Machine Learning Logs**: The ML pipeline will detect the anomaly, bypass the background noise, and categorize the specific threat vector in real-time.
3. **Agentic Orchestration**: The LangGraph pipeline tracker will light up. Hover over the nodes (Detection, Triage, Context, Response) to see the exact Markdown chain-of-thought the Gemini agents are generating.
4. **Autonomous Mitigation**: The Response agent will execute a Python tool to physically alter the Linux `iptables` routing tables.
5. **Mitigation Success**: The attack traffic will instantly flatline on the chart, and the attacker's IP will appear in the **Active Mitigations** table.

You can view the comprehensive, formatted markdown outputs of every single AI decision in the **AI Intelligence Reports** tab.

## Complete Wipe / Reset

To flush all `iptables` rules, clear the agent memory, and stop all active Scapy threads, simply click the red **Reset Environment** button at the top of the dashboard.
