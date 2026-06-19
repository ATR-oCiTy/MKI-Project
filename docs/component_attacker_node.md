# Component Documentation: Attacker Node

The **Attacker Node** is an isolated Alpine Linux container situated in the DMZ network (`10.5.1.10`). It is deliberately disconnected from the internal network, meaning all its traffic must physically route through the SOC Sensor Brain to reach its targets.

It serves as the offensive engine for the Cyber Range, executing highly specific, mathematically-forged packet flows designed to trigger the ML models.

## `attacker_api.py`

This module exposes a REST API that the Dashboard UI uses to orchestrate attacks remotely.

### Attack Generation Engine
Instead of using chaotic, off-the-shelf offensive tools (like standard `nmap` or `hping3`), the engine uses `scapy` to forge raw Ethernet frames and IP packets from scratch.
- **Mathematical Alignment**: The packets are forged based on strict statistical profiles derived directly from the UNSW-NB15 dataset (e.g., specific combinations of `smean`, `dmean`, `spkts`, `dpkts`, and `dur`).
- **Layer 2 Injection**: The packets are injected directly onto the `eth0` interface at Layer 2 using `sendp()`. This bypasses local routing tables and forces the packets onto the wire, guaranteeing the SOC Sensor captures them exactly as forged.

### Continuous Threading
When an attack is launched, it runs inside a dedicated `threading.Thread`. 
- **`active_attacks` State**: A global dictionary tracks the state of each attack type (`dos`, `exploits`, etc.).
- **While Loop**: The thread loops indefinitely, continuously generating the mathematically-aligned packet sequence, sleeping for `1.0` seconds between sequences to allow the NFStream sensor to flush and evaluate the flow. The loop terminates instantly if the UI sends a STOP command.

### Source IP Spoofing
The API accepts a custom `source_ip` or a `randomize_source` boolean. 
- If random spoofing is enabled, the generation loop assigns a random IP within the DMZ block (`10.5.1.x`) to the `src` field of the IP header *for every iteration of the attack loop*.
- This tests the SOC Brain's ability to detect distributed attacks and evaluate flows from massive numbers of unique IPs simultaneously.

### Endpoints
- **`/attack`**: Spawns a continuous attack thread.
- **`/stop_attack`**: Kills a specific attack thread by flipping its boolean flag.
- **`/stop`**: Flushes all threads and force-kills any legacy processes (`pkill -9 hping3`).
- **`/logs`**: Serves the attacker's internal logs.
- **`/clear_logs`**: Physically truncates the `attacker.log` file when requested by the UI.
