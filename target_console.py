# target_console.py
#
# Interactive console that runs after the live dashboard closes. It lets you
# drill into a specific target: list devices on the LAN, capture + inspect a
# chosen target IP, and print a tcpdump-style breakdown of any captured packet.
import network_discovery
import target_capture
import db_manager
import dpi


def _print_devices(devices):
    if not devices:
        print("No devices found.")
        return
    print(f"\n{len(devices)} device(s) on the network:")
    print(f"  {'IP':<16} {'MAC':<18} {'HOST / VENDOR'}")
    for d in devices:
        label = d.get("hostname") or d.get("vendor") or ""
        print(f"  {d['ip']:<16} {d.get('mac', ''):<18} {label}")


def _print_findings(packets, findings):
    print(f"\nCaptured {len(packets)} packets. Deep packet inspection:")
    shown = 0
    for i, (pkt, f) in enumerate(zip(packets, findings)):
        if not f:
            continue
        bits = []
        if "dns_query" in f:
            bits.append(f"DNS={f['dns_query']}")
        if "tls_sni" in f:
            bits.append(f"SNI={f['tls_sni']}")
        if "http" in f:
            bits.append(f"HTTP={f['http']}")
        if "payload_preview" in f:
            bits.append(f"payload='{f['payload_preview']}'")
        print(f"  #{i:<4} {pkt.summary()}")
        if bits:
            print(f"        {' | '.join(bits)}")
        shown += 1
    if shown == 0:
        print("  (no application-layer details extracted - likely all encrypted)")


def _list_packets(packets):
    print(f"\n{len(packets)} packets available:")
    for i, pkt in enumerate(packets):
        print(f"  #{i:<4} {pkt.summary()}")


def _ask_int(prompt, default):
    raw = input(f"{prompt} [{default}]: ").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def run():
    last_packets = []
    last_findings = []

    print("\n=== Target inspection console ===")
    while True:
        print("\n  1) List devices on the network")
        print("  2) Capture + inspect a target IP")
        print("  3) Dump a packet from the last capture (tcpdump view)")
        print("  4) Show stored captures")
        print("  5) Done")
        try:
            choice = input("Select: ").strip()
        except EOFError:
            break

        if choice == "1":
            devices = network_discovery.scan_network()
            _print_devices(devices)
            db_manager.store_devices(devices)

        elif choice == "2":
            ip = input("Target IP: ").strip()
            if not ip:
                print("No IP entered.")
                continue
            count = _ask_int("How many packets", 50)
            timeout = _ask_int("Timeout seconds", 30)
            pcap_path, last_packets, last_findings = target_capture.capture_target(
                ip, count=count, timeout=timeout
            )
            if last_packets:
                _print_findings(last_packets, last_findings)
                if pcap_path:
                    print(f"\nSaved to {pcap_path}")

        elif choice == "3":
            if not last_packets:
                print("No capture yet - run option 2 first.")
                continue
            _list_packets(last_packets)
            idx = _ask_int("Packet # to dump", 0)
            if 0 <= idx < len(last_packets):
                print("\n" + "=" * 60)
                print(dpi.dump(last_packets[idx]))
                print("=" * 60)
            else:
                print("Index out of range.")

        elif choice == "4":
            rows = db_manager.get_captures()
            if not rows:
                print("No stored captures yet.")
            else:
                print(f"\n{len(rows)} stored capture(s):")
                for r in rows:
                    print(
                        f"  [{r['captured_at']}] {r['target']} - "
                        f"{r['packet_count']} pkts -> {r['pcap_path']}"
                    )
                    if r.get("dpi_summary"):
                        print(f"      DPI: {r['dpi_summary']}")

        elif choice == "5":
            break
        else:
            print("Pick 1-5.")
