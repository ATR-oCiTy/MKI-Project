# Autonomous SOC: Live-Traffic Containerized Cyber Range

This repository deploys a fully self-contained, segmented enterprise network operating an autonomous Security Operations Center (SOC). It utilizes a custom Random Forest machine learning model for anomaly detection and a CrewAI multi-agent swarm for automated threat context and firewall mitigation. The infrastructure is entirely contained within Docker Compose, simulating a DMZ and an Internal Secure Network bridged by a highly privileged routing container.

## Prerequisites

- Docker and Docker Compose installed on a Linux or macOS host system.
- An active Gemini API key for the CrewAI swarm. The agents require API access to perform their cognitive reasoning steps.

## 1. Environment Configuration

Copy the example environment file and provide your API key. This key will be passed into the sensor container.

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY="your-actual-api-key-here"
```

## 2. Bootstrapping the Architecture

Initialize the segmented network and build the Alpine-based ML/Sensor image.

```bash
docker-compose up --build -d
```

> **Note:** Upon successful initialization, the `soc-sensor-brain` container will immediately begin generating the synthetic UNSW-NB15 dataset, training the Random Forest model, serializing the `.pkl` file, and initiating live packet ingestion on both `eth0` and `eth1`.

## 3. Monitoring the Autonomous SOC

To view the output of the ML inference engine and the CrewAI orchestrator in real-time, attach to the sensor's logs. Leave this terminal window open during testing.

```bash
docker logs -f soc-sensor-brain
```

## 4. Simulating a Live Attack

The environment is designed to route traffic through the sensor. To test the detection pipeline, we will simulate a volumetric DoS attack from the attacker-node (located in the DMZ) targeting the highly critical hr-portal (located in the Internal Secure Network).

Open a secondary terminal window and access the shell of the attacker node:

```bash
docker exec -it attacker-node sh
```

Verify that the static routes are functioning by pinging the HR portal:

```bash
ping -c 3 10.5.2.30
```

Execute a rapid packet injection using `hping3` to trigger the ML anomaly threshold. The `--flood` flag sends packets as fast as possible, simulating the high packet velocity and duration characteristics typical of Class 1 attack traffic in our Random Forest training dataset.

```bash
hping3 -S -p 80 --flood 10.5.2.30
```

Allow the flood to run for approximately 10 seconds, then press `Ctrl+C` to terminate it.

## 5. Validating the Mitigation

Switch back to the terminal window monitoring the `soc-sensor-brain` logs. You will observe the following sequence of events:

1. **Detection:** The log will indicate that NFStream captured the massive flow passing between `eth0` and `eth1`. The Random Forest model will evaluate the statistical array (duration, packets, bytes) and classify it as anomalous with >85% confidence.
2. **Orchestration:** You will observe the CrewAI LLM swarm initializing. The agents will print their chain-of-thought to the console.
3. **Contextualization:** The Context Agent will execute the `lookup_asset` tool, identifying `10.5.2.30` as the hr-portal, a "High" criticality asset.
4. **Mitigation:** The Response Agent will determine that a critical asset is under active attack and execute the `block_ip` tool against the attacker's IP (`10.5.1.10`).
5. **Validation:** The log will print the "AUTONOMOUS SOC RESOLUTION REPORT".

### Verification

Return to the `attacker-node` shell and attempt to contact the portal again:

```bash
curl --connect-timeout 5 http://10.5.2.30
```

This request will now result in a definitive timeout. The `FORWARD` chain rule inside the sensor router has successfully dropped the routing path, proving that the Autonomous SOC successfully detected, contextualized, and mitigated the live threat.
