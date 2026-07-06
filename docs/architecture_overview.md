# Autonomous SOC Brain - Architecture Overview

## Executive Summary
The **Autonomous SOC Brain** is a containerized, AI-driven cybersecurity range that simulates a complete enterprise network environment. It integrates traditional Machine Learning (Random Forest) for real-time packet inspection with Agentic Generative AI (LangGraph/Gemini) for context-aware threat intelligence and autonomous mitigation.

## High-Level Architecture

The environment is orchestrated via Docker Compose and is strictly segmented into two isolated virtual networks:

1. **DMZ Network (`10.5.1.0/24`)**: Houses external-facing and malicious actors.
   - **Attacker Node (`10.5.1.10`)**: Simulates external threat actors injecting malicious flows.
   - **DMZ Web (`10.5.1.20`)**: A vulnerable Nginx web server.

2. **Internal Network (`10.5.2.0/24`)**: Houses sensitive, internal enterprise assets.
   - **Internal HR Portal (`10.5.2.30`)**: A mock Python HTTP server simulating a critical internal app.
   - **Internal DB (`10.5.2.20`)**: A Redis database representing sensitive data stores.

3. **SOC Sensor Brain (`10.5.1.254` & `10.5.2.254`)**: The core security appliance. It sits exactly between the DMZ and the Internal network acting as the gateway/router. All traffic flowing between the DMZ and Internal assets *must* pass through the SOC Sensor.

## The Defense Pipeline

The SOC Brain operates on a highly optimized three-stage pipeline:

### Stage 1: NFStream Deep Packet Inspection
The `live_sensor.py` script binds directly to the container's network interfaces (`eth0`, `eth1`) at Layer 2. Using `NFStream`, it continuously captures live network traffic, groups raw packets into bidirectional flows, and calculates 20+ statistical features (e.g., bytes, duration, packet inter-arrival times) on the fly.

### Stage 2: Machine Learning Gatekeeper
Instead of relying on rigid static signatures, every network flow is passed through a pre-trained **Random Forest Classifier**.
- **Binary Classification**: Determines if the flow is `Normal` or an `Anomaly` (confidence threshold 0.55).
- **Multi-Class Classification**: If anomalous, categorizes the attack (e.g., `DoS`, `Reconnaissance`, `Exploits`).
- **Port-scan correlator**: A second, independent path that catches real multi-port scans by looking *across* flows (5+ distinct destination ports from one source within 5 seconds) rather than within a single flow - a genuine port scan looks identical to an ordinary short connection one flow at a time, so this pattern can't be caught by the classifiers above alone.

This stage filters out the overwhelming majority of background noise, ensuring the LLM is only invoked for genuine threats.

### Stage 3: Agentic Orchestration (LangGraph)
When an anomaly is confidently detected, the flow metadata is passed to `orchestrator.py`. A three-node LangGraph pipeline (powered by Gemini) takes over:
1. **Triage**: Analyzes the flow parameters and determines the severity.
2. **Context**: Evaluates the target asset (e.g., HR Portal vs Database) to assess business impact.
3. **Response**: Decides whether to deploy an active mitigation. If authorized (and not deferred - see below), it executes physical `iptables` DROP rules directly on the Linux kernel to sever the attacker's connection.

**Blocks are not permanent.** Every automated block carries a TTL (one hour by default) and is auto-reviewed by a background sweep, and attacks against `Critical`/`High` criticality assets are queued for a human to approve or dismiss rather than auto-resolving. Combined with a protected allow-list (the sensor's own addresses and every registered asset can never be blocked) and a rolling rate limit on blocks per minute, these guardrails are what keep the system safely autonomous rather than unconditionally autonomous - see [`triage_resolution_flows.md`](triage_resolution_flows.md) for the full decision tree.

## System Components

For deep dives into the individual codebases, refer to the component documentation:
- [SOC Sensor Brain & APIs](component_soc_brain.md)
- [Attacker Simulation Node](component_attacker_node.md)
- [Frontend Dashboard UI](component_dashboard_ui.md)
- [Machine Learning Training Pipeline](ml_model_report.md)
- [ML Training Notebook (executed, with real metrics/plots)](../soc_brain/ml_training_notebook.ipynb)
- [Triage & Resolution Flows](triage_resolution_flows.md)
- [**Master Documentation (PDF)**](Master_Documentation.pdf) — single end-to-end reference covering every component, the ML pipeline, the guardrails, and the real bugs found and fixed during development. Start here.
