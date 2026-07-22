# target_capture.py
#
# Focused capture for a single chosen target. Sniffs only traffic to/from the
# target IP, saves the raw packets to a .pcap (re-openable in Wireshark), runs
# deep packet inspection over them, and records the capture in the database.
import os
import time

from scapy.all import sniff, wrpcap

import dpi
import db_manager

CAPTURE_DIR = os.path.join(os.path.dirname(__file__), "captures")


def capture_target(ip, count=50, timeout=30):
    os.makedirs(CAPTURE_DIR, exist_ok=True)

    # Make sure TLS is dissectable so we can pull SNI from handshakes.
    dpi.enable_tls()

    print(
        f"\nCapturing up to {count} packets to/from {ip} "
        f"(stops after {timeout}s of no completion)."
    )
    print("Generate some traffic to/from that host now...")

    try:
        packets = sniff(filter=f"host {ip}", count=count, timeout=timeout)
    except Exception as e:
        print("Capture failed:", e)
        return None, [], []

    if not packets:
        print("No packets captured for that target.")
        return None, [], []

    # Save the raw packets to a pcap file.
    stamp = time.strftime("%Y%m%d_%H%M%S")
    safe = ip.replace(":", "_").replace(".", "_")
    pcap_path = os.path.join(CAPTURE_DIR, f"target_{safe}_{stamp}.pcap")
    try:
        wrpcap(pcap_path, packets)
    except Exception as e:
        print("Could not write pcap:", e)
        pcap_path = ""

    # Deep packet inspection over the captured packets.
    findings = [dpi.inspect(p) for p in packets]
    summary = dpi.summarize(findings)

    # Index the capture in the database.
    try:
        db_manager.insert_capture(
            target=ip,
            pcap_path=pcap_path,
            packet_count=len(packets),
            dpi_summary=summary,
            captured_at=stamp,
        )
    except Exception as e:
        print("Could not record capture in the database:", e)

    return pcap_path, list(packets), findings
