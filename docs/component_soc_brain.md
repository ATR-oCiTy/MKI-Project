# Component Documentation: SOC Sensor Brain

The **SOC Sensor Brain** is the central nervous system of the cyber range. It acts as a network router, a deep packet inspector, a machine learning inferencer, and an autonomous mitigation agent.

> [!TIP]
> For the full decision-tree walkthrough of how a single alert moves from detection to a resolved outcome, see [`triage_resolution_flows.md`](triage_resolution_flows.md). This document covers each module's responsibilities; that one covers the end-to-end flow across all of them.

## Core Modules

### 1. `live_sensor.py` (The Eyes)
This module is responsible for real-time packet capture, feature extraction, and a second, independent detection path.
- **NFStream Integration**: Sniffs traffic directly from the `eth0` and `eth1` interfaces (one background thread per interface). It groups raw packets into bidirectional flows based on a 10-second active timeout and a 5-second idle timeout.
- **Traffic Isolation**: Implements an explicit filter (`if not flow.src_ip.startswith("10.5.")`) to completely ignore ambient internet noise hitting the host OS, ensuring the pipeline only evaluates intra-container network traffic. It also discards any flow that predates the last environment reset.
- **ML Inference**: Loads the pre-trained Random Forest models via `pickle`. It dynamically calculates 9 derived features (log-scaled duration/rate/bytes, packet/byte ratios, mean packet sizes) and predicts the class of the live flow.
- **Trigger**: If the binary model's confidence is **≥ 0.55** *and* it predicts `Attack`, the multi-class model assigns a specific category and the flow data is packaged and handed to `orchestrator.py`'s `trigger_swarm()` asynchronously.
- **Port-scan correlator**: A second, independent detection path that runs on flows the binary model called `Normal`. A real port scan is many separate 1-2 packet flows - each one looks like an ordinary short connection to a classifier that only ever sees one flow at a time, so the scan signature ("many destination ports touched by one source in a short window") is checked *across* flows instead, using a 5-second rolling window per source IP. Crossing 5 distinct targets with small (≤4-packet) flows fires a synthetic `Reconnaissance` alert directly, independent of the RF models. This exists because real `nmap` scans were going completely undetected before it was added.

### 2. `orchestrator.py` (The Brain)
This module houses the LangGraph pipeline that reasons about threats and takes action, plus every safety guardrail.
- **State Graph**: Defines a three-node workflow (`triage` &rarr; `context` &rarr; `response` &rarr; `END`). Each node has a dry-run branch (canned text, the default, so testing doesn't consume Gemini quota) and a real branch that calls Gemini.
- **Tools**: `lookup_asset_tool` (bound in the Context node) and a `block_ip_tool` built fresh per alert via `make_block_ip_tool()` (bound in the Response node) - built fresh, not once at import time, because it needs to close over that specific alert's context. Both use a single `bind_tools()` call rather than `create_react_agent`'s automatic two-turn loop, specifically to keep Gemini API usage down (see "Quota management" below).
- **Guardrails** - five independent mechanisms, all converging on the same `block_ip()` / `request_approval()` functions so none of them can be bypassed by taking a different code path:
  - **Protected allow-list**: the sensor's own gateway addresses plus every IP in the registered asset database can never be blocked, regardless of what an alert or the LLM recommends. Extensible via the `PROTECTED_IPS` environment variable.
  - **Rate limiting**: a rolling 60-second window capped at `MAX_BLOCKS_PER_WINDOW` (default 20). Over the cap, further blocks are refused and logged for manual review instead of executed.
  - **Tiered autonomy**: attacks targeting a `Critical` or `High` criticality asset are queued in `pending_approvals` for a human decision instead of auto-resolving.
  - **Block TTL expiry**: every automated block carries an expiry (`BLOCK_TTL_SECONDS`, default one hour), swept by a background thread every 30 seconds.
  - **Per-source cooldown**: 30 seconds between LangGraph invocations for the same source IP - keyed per source, not globally, so one attacker's cooldown never hides a different, unrelated attacker's alert.
- **Quota management**: `get_llm()` returns a singleton `ChatGoogleGenerativeAI` client with `max_retries=0` - a 429 (quota exhausted) used to be auto-retried by the client, burning more of the same rate-limit budget re-attempting a call that would fail again. Each node's own try/except already provides a graceful canned fallback on any failure, so a fast single failure is preferable to a wasted retry.

### 3. `dashboard_api.py` (The Interface)
A Flask REST API that bridges the backend security engine with the React frontend, run in a background thread inside the same process as the live sensor so it shares the in-memory `event_store` directly.
- **Read endpoints**: `/api/alerts`, `/api/mitigations`, `/api/flow`, `/api/pending_approvals`, `/api/active_blocks`, `/api/logs`, `/api/attacker_logs`.
- **Action endpoints**: `/api/trigger` (manual block, routed through the same guarded `block_ip()` as the automated path), `/api/unblock`, `/api/approve`, `/api/deny`, `/api/simulate_attack` & `/api/stop_attack` (proxy to the Attacker Node), `/api/reset` (flushes `iptables`, clears all in-memory state, stops all attacks), `/api/clear_logs`.

### 4. `event_store.py` (The Memory)
A simple, thread-safe (single `threading.Lock`) in-memory data structure holding the last 100 alerts, the last 100 mitigations, and the last **50** LangGraph flow events, plus a `last_reset_time` timestamp used by `live_sensor.py` to discard stale flows. It is continuously polled by the React dashboard. There is no database - a container restart loses all history, which is an accepted limitation for a cyber range demo.

### 5. `train_model.py` (The Teacher)
Downloads UNSW-NB15 if not already present, engineers the 9 features used everywhere else in the pipeline, injects jittered synthetic anchor rows so the demo attacker's forged traffic reliably lands inside a recognized class (see [`ml_model_report.md`](ml_model_report.md) for why jittered rather than exact-duplicate anchors), and trains both Random Forests. Skips training entirely if `rf_binary.pkl`/`rf_multi.pkl` already exist.

### 6. `calibrate_tool.py` (The Real-Traffic Calibrator)
A standalone script, not part of the live pipeline. Real attack tools (`nmap`, `hping3`) produce genuinely different flow statistics than the hand-crafted Scapy packets the model was originally calibrated against. Run inside this container while a real tool fires from the attacker node, it captures the resulting NFStream feature vector and prints it ready to paste into `train_model.py`'s injection list.

### 7. `main_runner.py` (The Entrypoint)
Starts the dashboard API in a background thread, loads the two pickled models, then starts one packet-capture thread per interface. Deliberately thin - almost all real logic lives in the modules it imports.
