# Component Documentation: Attacker Node

The **Attacker Node** is an isolated Alpine Linux container situated in the DMZ network (`10.5.1.10`). It is deliberately disconnected from the internal network, meaning all its traffic must physically route through the SOC Sensor Brain to reach its targets.

It serves as the offensive engine for the Cyber Range, and now supports **two separate attack generation methods**: a synthetic engine (the original design) and, for two attack types, genuine real-tool traffic.

## `attacker_api.py`

This module exposes a REST API that the Dashboard UI uses to orchestrate attacks remotely.

### Synthetic Attack Generation Engine (default)
For all five attack types, `generate_flow()` uses `scapy` to forge raw Ethernet frames and IP packets from scratch, bypassing the OS TCP/IP stack entirely.
- **Mathematical Alignment**: The packets are forged based on strict statistical profiles derived directly from the UNSW-NB15 dataset (e.g., specific combinations of `smean`, `dmean`, `spkts`, `dpkts`, and `dur`).
- **Layer 2 Injection**: The packets are injected directly onto the `eth0` interface at Layer 2 using `sendp()`. This bypasses local routing tables and forces the packets onto the wire, guaranteeing the SOC Sensor captures them exactly as forged.

### Real Attack Tools (`real_tools` flag)
Two attack types have a **validated, working real-tool path**, toggled by a `real_tools` flag in the `/attack` request body (surfaced in the dashboard as "Use Real Attack Tools"):

- **`dos`** &rarr; `generate_real_dos()` drives real `hping3`, in **bounded bursts of 500 packets** rather than an unbounded flood - an unbounded `--flood` was tested and never produced a completed, classifiable NFStream flow at all. Confirmed to reliably classify as `DoS`. Uses `-k -s <fixed port>` to pin the source port, since `hping3`'s default behavior of incrementing it on every packet was found to fragment what should be one aggregated flow into many single-packet flows.
- **`port_sweep`** &rarr; `generate_real_port_sweep()` drives real `nmap -sT`, looped continuously. A genuine multi-port scan fragments into many separate 1-2 packet flows the per-flow classifier can't see the pattern across - this is caught by the sensor's cross-flow port-scan correlator (`live_sensor.py`) instead of the RF models.

`exploits`, `fuzzers`, and `backdoors` remain on the synthetic engine even with `real_tools` enabled - real `hping3`/TCP-handshake traffic for these was tested and produces a genuinely different statistical footprint (real SYN/ACK/RST sequences vs. hand-crafted packets with no OS-level handshake) that isn't reliably recognized by the current calibration. `REAL_TOOL_SUPPORTED = {'dos', 'port_sweep'}` in the code is the source of truth for which types actually get a real tool; requesting `real_tools` for anything else silently falls back to the synthetic engine.

### Continuous Threading
When an attack is launched (synthetic or real), it runs inside a dedicated `threading.Thread`.
- **`active_attacks` State**: A global dictionary tracks the state of each attack type (`dos`, `exploits`, etc.).
- **While Loop**: The thread loops while the flag is set, continuously generating a fresh packet sequence or tool invocation, with a short pause between iterations to let the NFStream sensor flush and evaluate the flow. The loop terminates as soon as the UI sends a STOP command.

### Source IP Spoofing
The API accepts a custom `source_ip` or a `randomize_ip` boolean, applied to the synthetic engine and to the real `hping3` path (via `--spoof`).
- If random spoofing is enabled, the generation loop assigns a random IP within the DMZ block (`10.5.1.x`) to the source address for every iteration of the attack loop.
- This tests the SOC Brain's ability to detect distributed attacks and evaluate flows from massive numbers of unique IPs simultaneously. Note the rate-limit guardrail in `orchestrator.py` (default 20 blocks/60s) is deliberately generous specifically so this demo can show many legitimate blocks succeeding in quick succession without tripping it.
- Real `nmap` scans do **not** support spoofing here - `nmap`'s source spoofing needs raw ARP/interface tricks and won't receive replies, so the real port-sweep path always scans from the attacker node's genuine address.

### Endpoints
- **`/attack`**: Spawns a continuous attack thread (synthetic or real, per `real_tools`).
- **`/stop_attack`**: Kills a specific attack thread by flipping its boolean flag.
- **`/stop`**: Flushes all threads and force-kills any legacy processes (`pkill -9 hping3`, `pkill -9 nmap`).
- **`/logs`**: Serves the attacker's internal logs.
- **`/clear_logs`**: Physically truncates the `attacker.log` file when requested by the UI.
