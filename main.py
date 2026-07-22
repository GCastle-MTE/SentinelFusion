# main.py
import os

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.animation import FuncAnimation

import db_manager
import threat_detection
import scan_detector
import geo_lookup
import process_lookup
import soar_integration
import report_generator
import target_console
import client_info


# Colour for each traffic group (where it is coming from).
SCOPE_COLORS = {
    "local": "#1D9E75",      # LAN / private addresses
    "external": "#D85A30",   # public internet
    "multicast": "#534AB7",  # multicast / discovery
    "loopback": "#888780",
    "unknown": "#888780",
}


def _draw_barh(ax, items, color, label_fontsize=8):
    # Draw a horizontal bar chart with value labels.
    # items is a list of (label, value) ordered bottom -> top.
    labels = [k for k, _ in items]
    values = [v for _, v in items]
    bars = ax.barh(labels, values, color=color)
    top = max(values)
    ax.set_xlim(0, top * 1.18 + 1)
    for rect, v in zip(bars, values):
        ax.text(
            rect.get_width() + top * 0.01 + 0.1,
            rect.get_y() + rect.get_height() / 2,
            str(v),
            va="center",
            fontsize=label_fontsize,
        )


def show_live_chart():
    fig, (ax_src, ax_geo, ax_app) = plt.subplots(
        3, 1, figsize=(10, 10), constrained_layout=True
    )
    fig.canvas.manager.set_window_title("Sentinel Fusion")

    icon_path = os.path.join(os.path.dirname(__file__), "SentinelFusion.ico")
    try:
        fig.canvas.manager.window.wm_iconbitmap(icon_path)
    except Exception:
        pass

    def update(_frame):
        try:
            src_snapshot = dict(threat_detection.source_counts)
            proc_snapshot = dict(threat_detection.process_counts)
        except RuntimeError:
            return  # counters changed mid-copy; skip this frame

        # --- Panel 1: where traffic is coming from (top sources) ---
        ax_src.clear()
        ax_src.set_title("Where traffic is coming from (top sources)")
        ax_src.set_xlabel("Packets")
        top = sorted(src_snapshot.items(), key=lambda kv: kv[1], reverse=True)[:10]
        if top:
            top = top[::-1]
            scopes = [threat_detection.classify_ip(ip) for ip, _ in top]
            colors = [SCOPE_COLORS.get(s, "#888780") for s in scopes]
            _draw_barh(ax_src, top, colors)
            present = list(dict.fromkeys(scopes))
            handles = [
                mpatches.Patch(color=SCOPE_COLORS.get(s, "#888780"), label=s)
                for s in present
            ]
            ax_src.legend(handles=handles, loc="lower right", fontsize=8, title="grouped by")
        else:
            ax_src.set_xlim(0, 1)
            ax_src.text(0.5, 0.5, "Waiting for packets...",
                        ha="center", va="center", transform=ax_src.transAxes)

        # --- Panel 2: external traffic by country (fills in live) ---
        ax_geo.clear()
        ax_geo.set_title("External traffic by country")
        ax_geo.set_xlabel("Packets")
        by_country = geo_lookup.group_by_country(threat_detection.external_endpoints())
        if by_country:
            items = sorted(by_country.items(), key=lambda kv: kv[1], reverse=True)[:10]
            items = items[::-1]
            colors = [
                "#888780" if lbl in ("Resolving...", "Unknown") else "#185FA5"
                for lbl, _ in items
            ]
            _draw_barh(ax_geo, items, colors)
        else:
            ax_geo.set_xlim(0, 1)
            ax_geo.text(0.5, 0.5, "No external traffic yet",
                        ha="center", va="center", transform=ax_geo.transAxes)

        # --- Panel 3: top applications (which programs own the traffic) ---
        ax_app.clear()
        ax_app.set_title("Top applications (by packets)")
        ax_app.set_xlabel("Packets")
        top_app = sorted(proc_snapshot.items(), key=lambda kv: kv[1], reverse=True)[:10]
        if top_app:
            top_app = top_app[::-1]
            _draw_barh(ax_app, top_app, "#7F77DD")
        else:
            ax_app.set_xlim(0, 1)
            ax_app.text(0.5, 0.5, "Identifying applications...",
                        ha="center", va="center", transform=ax_app.transAxes)

        # --- Banner: port-scan status ---
        n = scan_detector.active_alert_count()
        if n:
            fig.suptitle(
                f"[!]  {n} possible port scan(s) detected",
                color="#A32D2D", fontsize=13, fontweight="bold",
            )
        else:
            fig.suptitle(
                "Monitoring - no port scans detected",
                color="#5F5E5A", fontsize=11,
            )

    fig._live_animation = FuncAnimation(
        fig, update, interval=1000, cache_frame_data=False
    )
    plt.show()  # blocks until the window is closed


def main():
    # 1. Start tracking which local application owns each connection.
    process_lookup.start()

    # 2. Start live packet capture in the background (needs Npcap + admin).
    sniffer = threat_detection.start_async_monitor()

    # 3. Start resolving external IPs to locations in the background.
    geo_lookup.start_resolver(threat_detection.external_endpoints, interval=5)

    # 4. Local IP of this host.
    client_ip_address = client_info.get_ip_address()
    print("Client IP:", client_ip_address)

    # 5. Live chart; capture + resolution run until you close the window.
    show_live_chart()

    # 6. Stop the background workers.
    try:
        sniffer.stop()
    except Exception:
        pass
    geo_lookup.stop_resolver()
    process_lookup.stop()

    # 6. One final catch-up resolution so the report is complete.
    ext = threat_detection.external_endpoints()
    pending = [ip for ip in ext if not geo_lookup.get(ip)]
    if pending:
        print(f"Resolving {len(pending)} remaining external IPs for the report...")
        geo_lookup.resolve(pending)

    # 7. Build the traffic summary (now including geography).
    summary = threat_detection.traffic_summary()
    summary["by_country"] = geo_lookup.group_by_country(ext)
    top_ext = sorted(ext.items(), key=lambda kv: kv[1], reverse=True)[:10]
    summary["top_external"] = [
        (ip, cnt, geo_lookup.get(ip).get("country") or "?", geo_lookup.get(ip).get("isp") or "")
        for ip, cnt in top_ext
    ]
    # Application breakdown (which programs the packets belong to).
    proc_counts = threat_detection._safe_copy(threat_detection.process_counts)
    summary["by_process"] = sorted(
        proc_counts.items(), key=lambda kv: kv[1], reverse=True
    )[:10]

    print(
        f"\nCaptured {summary['total_packets']} packets "
        f"from {summary['unique_sources']} unique sources."
    )
    print("Grouped by scope:", summary["by_scope"])
    print("Protocols:", summary["protocols"])
    print("External traffic by country:", summary["by_country"])
    print("Top applications:")
    for name, cnt in summary["by_process"]:
        print(f"  {name:<28} {cnt:>7}")

    # 8. Turn any detected port scans into real incidents.
    alerts = scan_detector.get_alerts()
    if alerts:
        print(f"\n{len(alerts)} port-scan incident(s) detected:")
        for a in alerts:
            src = a["src"]
            geo = geo_lookup.get(src)
            where = geo.get("country") or threat_detection.classify_ip(src)
            isp = geo.get("isp")
            sample = ", ".join(str(p) for p in a["ports_sample"])
            details = (
                f"Port scan: {src} -> {a['dst']} | {a['port_count']} TCP ports "
                f"in <= {scan_detector.WINDOW_SECONDS}s | ports: {sample}"
            )
            if where:
                details += f" | {where}"
            if isp:
                details += f" ({isp})"
            print("  -", details)
            db_manager.insert_incident({"status": "open", "details": details})
    else:
        print("\nNo port scans detected this run.")

    # 9. Drop into the interactive target-inspection console (devices,
    #    focused per-target capture + DPI, per-packet tcpdump).
    target_console.run()

    # 10. Read incidents back and report.
    print("\nGetting all incidents...")
    incidents = db_manager.get_all_incidents()
    print(f"{len(incidents)} incident(s) in the database.")

    # Best-effort threat-intel enrichment (SOAR endpoint is still a stub).
    for incident in incidents:
        try:
            incident["threat_intelligence"] = soar_integration.get_threat_intelligence(
                incident["details"]
            )
        except Exception as e:
            print("Threat intelligence lookup failed:", e)
            incident["threat_intelligence"] = None
        break  # limit to a single lookup

    # 11. Generate the PDF report (now including devices + captures).
    devices = db_manager.get_devices()
    captures = db_manager.get_captures()
    print("Generating PDF report...")
    report_generator.generate_pdf_report(
        incidents, traffic=summary, devices=devices, captures=captures
    )


if __name__ == "__main__":
    main()
