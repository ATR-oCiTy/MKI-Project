# calibrate_tool.py
# Captures the REAL NFStream feature vector produced by a live attack tool
# (nmap, hping3, msfconsole, etc.) run from attacker-node, so train_model.py
# can be calibrated against genuine tool traffic instead of guessed constants.
#
# Usage (run from inside the soc-sensor-brain container):
#   docker exec -it soc-sensor-brain python calibrate_tool.py --duration 15
#
# While it's capturing, run the real tool from attacker-node in another shell, e.g.:
#   docker exec -it attacker-node nmap -sS -p 80 10.5.2.30
#   docker exec -it attacker-node hping3 --flood --udp -p 80 10.5.2.30
#
# It prints every captured flow's feature vector using the exact same
# transforms as live_sensor.py/train_model.py, plus a ready-to-paste Python
# dict for train_model.py's inject_data list.

import argparse
import time
import numpy as np
from nfstream import NFStreamer


def flow_to_features(flow):
    spkts = flow.src2dst_packets
    dpkts = flow.dst2src_packets
    sbytes = flow.src2dst_bytes
    dbytes = flow.dst2src_bytes
    dur_sec = flow.bidirectional_duration_ms / 1000.0
    rate = (spkts + dpkts) / (dur_sec if dur_sec > 0 else 0.000001)

    return {
        "protocol": flow.protocol,
        "log_duration": float(np.log1p(dur_sec)),
        "log_rate": float(np.log1p(rate)),
        "log_sbytes": float(np.log1p(sbytes)),
        "log_dbytes": float(np.log1p(dbytes)),
        "packet_ratio": dpkts / (spkts + 1e-5),
        "byte_ratio": dbytes / (sbytes + 1e-5),
        "smean": flow.src2dst_mean_ps,
        "dmean": flow.dst2src_mean_ps,
    }


def main():
    parser = argparse.ArgumentParser(description="Capture real attack-tool traffic and print its NFStream feature vector.")
    parser.add_argument("--interface", default="eth0", help="Interface to capture on (eth0=DMZ, eth1=Internal)")
    parser.add_argument("--duration", type=int, default=15, help="Capture window in seconds")
    parser.add_argument("--label", default="Calibrated", help="Attack label to print in the suggested dict (e.g. Reconnaissance)")
    args = parser.parse_args()

    print(f"Capturing on {args.interface} for {args.duration}s. Run your real attack tool from attacker-node now...")
    streamer = NFStreamer(source=args.interface, statistical_analysis=True, active_timeout=10, idle_timeout=5)

    seen = 0
    start_time = time.time()
    for flow in streamer:
        if time.time() - start_time > args.duration:
            print(f"\nCapture window ({args.duration}s) elapsed, stopping.")
            break
        if not flow.src_ip.startswith("10.5."):
            continue
        seen += 1
        features = flow_to_features(flow)
        print(f"\n--- Flow {seen}: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} "
              f"(pkts={flow.bidirectional_packets}, bytes={flow.bidirectional_bytes}, dur={flow.bidirectional_duration_ms}ms) ---")
        for k, v in features.items():
            print(f"  {k}: {v}")

    if seen == 0:
        print("\nNo flows captured from 10.5.x sources. Confirm the real tool was run FROM INSIDE attacker-node "
              "(docker exec -it attacker-node ...), not from the host machine - traffic originating "
              "outside the 10.5.x subnet is filtered out by live_sensor.py and won't be detected either.")
        return

    print(f"\nCaptured {seen} flow(s). Pick the flow that best represents the tool's typical behavior and paste "
          f"its values into train_model.py's inject_data list, e.g.:\n")
    print(f"    {{'protocol': <p>, 'log_duration': <ld>, 'log_rate': <lr>, 'log_sbytes': <ls>, "
          f"'log_dbytes': <ld2>, 'packet_ratio': <pr>, 'byte_ratio': <br>, 'smean': <sm>, 'dmean': <dm>}},  # {args.label}")


if __name__ == "__main__":
    main()
