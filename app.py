# app.py
#
# SentinelFusion desktop application (Tkinter).
#
# This is the GUI shell on top of the existing engine modules. The capture
# engine keeps running on its background threads; the GUI polls the shared
# state once a second and repaints. Closing the window stops the engine.
#
# Tabs:
#   Metrics    - live charts + port-scan banner + the communication-web map.
#   Inspection - device scan / focused capture / packet dump (wired next cut).
#
# Run as administrator (capture needs it):
#   python app.py
import threading
import time
import os
import ipaddress
from collections import deque
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox

from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.ticker import FuncFormatter

import threat_detection
import scan_detector
import anomaly_detectors
import geo_lookup
import process_lookup
import network_discovery
import lan_monitor
import asset_registry
import host_resolve
import port_scanner
import dhcp_monitor
import target_capture
import dpi
import db_manager
import report_generator
import events
import threat_intel
import wifi_osint
import wifi_wids
import settings
import stream_follow
import pcap_io
import geoip_local
import watchlist
import allowlist
import net_proxy
import ja3_intel
import cred_sniffer
import tls_certs
import dns_log
import protocol_id
import capture_review
import http_log
import flow_tracker
import service_roles
import infra_rollup
import rtt_tracker
import novelty
import flow_analytics
import correlation
import playbook_engine
import case_manager
import cve_lookup
import service_fingerprint
import integrations
import forensics
import hunt_playbooks
import ml_anomaly
import feedback_loop
import log_sources
import log_ingest
import config_io
import health_monitor
import soc_metrics
import detection_rules
import enrichment
import alert_export
from ops_map import OpsMap


SCOPE_COLORS = {
    "local": "#1D9E75",
    "external": "#D85A30",
    "multicast": "#534AB7",
    "loopback": "#888780",
    "unknown": "#888780",
}

MAP_MAX_ENDPOINTS = 50  # how many top talkers to plot on the map

# Theme palette - neutral SOC / enterprise dark. Shared by _apply_theme, HUD, menus.
# Calm slate surfaces, a single steel-blue accent, muted semantic colours - the
# restraint you see in tools like Sentinel, Chronicle, or Grafana rather than a
# high-contrast tactical HUD.
THEME_BG = "#0f141a"        # slate charcoal page background
THEME_PANEL = "#171e26"     # lifted slate panel / readout surface
THEME_HEAD = "#0b1015"      # darkest chrome (top bar, table headings)
THEME_FG = "#d4dae0"        # clean light-grey primary text
THEME_MUTED = "#7c8a96"     # captions / secondary text
THEME_ACCENT = "#5b9dd9"    # steel blue (primary accent)
THEME_GLOW = "#7fb8e6"      # brighter blue for emphasis / selection text
THEME_GOLD = "#d9a441"      # muted amber-gold (used sparingly)
THEME_SEL = "#1d3245"       # selection wash (desaturated blue-grey)
THEME_BORDER = "#28323d"    # neutral slate panel edge
THEME_RED = "#e8544e"       # danger / hostile (muted from hot red)
THEME_AMBER = "#e0993a"     # warning (muted amber)
THEME_GREEN = "#4fb477"     # healthy / normal / monitoring
THEME_HEADFG = "#e8edf1"    # brightest heading text
THEME_BTN = "#202a34"       # button face
THEME_BTN_BORDER = "#3a4652"  # button edge (slightly stronger than panel border)
# Consistent spacing scale (px) so tabs/panels share the same rhythm.
PAD_SM, PAD_MD, PAD_LG = 6, 10, 16
# Clean enterprise font stack: Segoe UI for chrome, Consolas for data readouts.
FONT_HEAD = "Segoe UI Semibold"   # section headers / wordmark
FONT_UI = "Segoe UI"              # general interface text
FONT_DATA = "Consolas"            # monospace data (IPs, counts, tables)


def _human_count(n):
    try:
        n = float(n)
    except Exception:
        return "0"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return f"{n:.0f}"


def _human_bytes(n):
    try:
        n = float(n or 0)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _clock(ts):
    if not ts:
        return "-"
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except Exception:
        return "-"


class _Tooltip:
    """A small hover tooltip for any widget - helps a new user learn the UI."""

    def __init__(self, widget, text, delay=500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after = None
        self._tip = None
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self._hide, add="+")
        widget.bind("<ButtonPress>", self._hide, add="+")

    def _schedule(self, _e=None):
        self._cancel()
        self._after = self.widget.after(self.delay, self._show)

    def _cancel(self):
        if self._after:
            try:
                self.widget.after_cancel(self._after)
            except Exception:
                pass
            self._after = None

    def _show(self):
        if self._tip or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 12
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        except Exception:
            return
        self._tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        tk.Label(tw, text=self.text, bg="#05090d", fg="#c9d6da",
                 font=(FONT_UI, 9), justify="left", padx=8, pady=5,
                 wraplength=360, bd=1, relief="solid").pack()

    def _hide(self, _e=None):
        self._cancel()
        if self._tip:
            try:
                self._tip.destroy()
            except Exception:
                pass
            self._tip = None


def _ip_sort_key(ip):
    """Sort IPs numerically, so .9 precedes .10 instead of following it."""
    try:
        return tuple(int(p) for p in str(ip).split("."))
    except Exception:
        return (999, 999, 999, 999)


class SentinelApp:
    def __init__(self, root):
        self.root = root
        root.title("SentinelFusion")
        root.geometry("1320x820")

        self._me_coords = None
        self.wigle_var = tk.StringVar()   # shared by the WiFi and Settings tabs

        # Load saved settings and push them into the detectors *before* the
        # engine starts, so the very first packet is judged by the user's
        # thresholds and the feed thread uses the saved refresh interval.
        settings.load()
        self.wigle_var.set(settings.get("wigle_token", ""))
        cve_lookup.set_api_key(settings.get("nvd_api_key", ""))
        self._register_infrastructure()
        self._apply_settings()
        watchlist.load()
        allowlist.load()
        asset_registry.load()
        self._watch_alerted = set()   # (ip, kind, value) already alerted this session

        # Desktop-notification state.
        self._toasts = []             # currently-open toast windows
        self._notified_keys = set()   # event keys already toasted
        self._notify_ready = False    # first poll seeds the backlog without toasting

        # Start the engine (background threads).
        self.sniffer = threat_detection.start_async_monitor(
            iface=settings.get("capture_iface") or None)
        geo_lookup.start_resolver(threat_detection.external_endpoints, interval=5)
        process_lookup.start()
        threat_intel.start(refresh_hours=settings.get("intel_refresh_hours", 6))
        threat_detection.start_analytics()
        events.log_event("INFO", "system", "app", "SentinelFusion monitoring started")

        self._build_ui()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Locate "me" in the background, then place the marker on the GUI thread.
        threading.Thread(target=self._locate_me, daemon=True).start()

        # Refresh loops (Tk timers, on the main thread).
        self.root.after(1000, self._refresh_metrics)
        self.root.after(2500, self._refresh_map)
        self.root.after(4000, self._check_watchlist)
        self.root.after(2500, self._poll_notifications)

        # LAN survey: mark our own IP, trust the gateway as the DHCP server,
        # then run a baseline inventory sweep.
        try:
            lan_monitor.set_self(network_discovery._primary_ip())
            dhcp_monitor.set_expected(network_discovery.default_gateway())
        except Exception:
            pass
        self.root.after(4000, self._startup_net_scan)

    # ---------- UI construction ----------

    def _build_ui(self):
        self._build_hud()

        nb = ttk.Notebook(self.root)
        self.nb = nb
        nb.pack(fill="both", expand=True)

        self.metrics_tab = ttk.Frame(nb)
        self.apps_tab = ttk.Frame(nb)
        self.active_tab = ttk.Frame(nb)
        self.connections_tab = ttk.Frame(nb)
        self.wifi_tab = ttk.Frame(nb)
        self.network_tab = ttk.Frame(nb)
        self.inspection_tab = ttk.Frame(nb)
        self.alerts_tab = ttk.Frame(nb)
        self.incidents_tab = ttk.Frame(nb)
        self.cases_tab = ttk.Frame(nb)
        self.dns_tab = ttk.Frame(nb)
        self.http_tab = ttk.Frame(nb)
        self.flows_tab = ttk.Frame(nb)
        self.logs_tab = ttk.Frame(nb)
        self.watchlist_tab = ttk.Frame(nb)
        self.settings_tab = ttk.Frame(nb)
        nb.add(self.metrics_tab, text="  Metrics  ")
        nb.add(self.apps_tab, text="  Applications  ")
        nb.add(self.active_tab, text="  Active  ")
        nb.add(self.connections_tab, text="  Connections  ")
        nb.add(self.wifi_tab, text="  WiFi  ")
        nb.add(self.network_tab, text="  Network  ")
        nb.add(self.inspection_tab, text="  Inspection  ")
        nb.add(self.alerts_tab, text="  Alerts  ")
        nb.add(self.incidents_tab, text="  Incidents  ")
        nb.add(self.cases_tab, text="  Cases  ")
        nb.add(self.dns_tab, text="  DNS  ")
        nb.add(self.http_tab, text="  HTTP  ")
        nb.add(self.flows_tab, text="  Flows  ")
        nb.add(self.logs_tab, text="  Logs  ")
        nb.add(self.watchlist_tab, text="  Watchlist  ")
        nb.add(self.settings_tab, text="  Settings  ")

        self._build_metrics_tab()
        self._build_apps_tab()
        self._build_active_tab()
        self._build_connections_tab()
        self._build_wifi_tab()
        self._build_network_tab()
        self._build_inspection_tab()
        self._build_alerts_tab()
        self._build_incidents_tab()
        self._build_cases_tab()
        self._build_dns_tab()
        self._build_http_tab()
        self._build_flows_tab()
        self._build_logs_tab()
        self._build_watchlist_tab()
        self._build_settings_tab()

    # ---------- top HUD (always-visible status strip) ----------

    def _build_hud(self):
        bar = tk.Frame(self.root, bg=THEME_HEAD)
        bar.pack(fill="x", side="top")

        # Wordmark block: product name + plain descriptor.
        title = tk.Frame(bar, bg=THEME_HEAD)
        title.pack(side="left", padx=(14, 18), pady=7)
        tk.Label(title, text="SentinelFusion", bg=THEME_HEAD, fg=THEME_HEADFG,
                 font=(FONT_HEAD, 14)).pack(anchor="w")
        tk.Label(title, text="Network security monitor", bg=THEME_HEAD, fg=THEME_MUTED,
                 font=(FONT_UI, 8)).pack(anchor="w")

        self._hud_cells = {}
        hud_help = {
            "status": "Live capture state. MONITORING = sniffer running and seeing "
                      "packets; IDLE = running but quiet; STOPPED = not capturing.",
            "endpoints": "Distinct external IPs your machine has talked to.",
            "connections": "Active network connections right now.",
            "flagged": "IPs currently flagged as suspicious or on a threat feed.",
            "alerts": "Unacknowledged ALERT-level events. Acknowledge them on the Alerts tab.",
            "warnings": "Unacknowledged WARNING-level events.",
            "rate": "Packets per second across all traffic.",
            "threat": "Overall posture: NORMAL, GUARDED (warnings), or ELEVATED (alerts/flagged).",
        }
        for key, caption in (("status", "Status"), ("endpoints", "Endpoints"),
                             ("connections", "Conns"), ("flagged", "Flagged"),
                             ("alerts", "Alerts"), ("warnings", "Warnings"),
                             ("rate", "Pkt/s"), ("threat", "Threat")):
            cell = tk.Frame(bar, bg=THEME_HEAD)
            cell.pack(side="left", padx=12, pady=6)
            cap = tk.Label(cell, text=caption, bg=THEME_HEAD, fg=THEME_MUTED,
                           font=(FONT_UI, 8))
            cap.pack(anchor="w")
            val = tk.Label(cell, text="-", bg=THEME_HEAD, fg=THEME_FG,
                           font=(FONT_DATA, 13))
            val.pack(anchor="w")
            self._hud_cells[key] = val
            _Tooltip(cell, hud_help.get(key, ""))
            _Tooltip(cap, hud_help.get(key, ""))
            _Tooltip(val, hud_help.get(key, ""))

        # Help button - explains the whole interface at a glance.
        help_btn = tk.Label(bar, text="  ?  ", bg=THEME_BTN, fg=THEME_ACCENT,
                            font=(FONT_HEAD, 11), cursor="hand2",
                            highlightthickness=1, highlightbackground=THEME_BTN_BORDER)
        help_btn.pack(side="right", padx=14, pady=8)
        help_btn.bind("<Button-1>", lambda _e: self._show_help())
        _Tooltip(help_btn, "What am I looking at? A guide to every tab.")

        # Thin accent rule under the banner.
        tk.Frame(self.root, bg=THEME_BORDER, height=1).pack(fill="x", side="top")

        self._hud_last_pkts = None
        self._hud_last_t = None
        self.root.after(1000, self._refresh_hud)

    # Plain-language guide to every tab, shown by the ? button.
    TAB_GUIDE = [
        ("Metrics", "The dashboard: live throughput graph, traffic map, and top talkers."),
        ("Applications", "Which programs on your PC are using the network, and how much."),
        ("Active", "Live connections as they open and close, with the process behind each."),
        ("Connections", "A fuller connection table with addresses, ports and state."),
        ("WiFi", "Nearby wireless networks and OSINT lookups on them."),
        ("Network", "Survey of devices on your LAN - IP, MAC, vendor, hostname, open ports."),
        ("Inspection", "Capture packets and read one apart byte-by-byte. Import a .pcap here."),
        ("Alerts", "Everything the detectors flagged. Click one to see why; acknowledge to clear it."),
        ("Incidents", "Related alerts about one actor, grouped and scored - a whole attack chain as a single HIGH incident."),
        ("DNS", "Every domain looked up and the IPs it resolved to. Intent before the connection."),
        ("HTTP", "Cleartext web requests and a software inventory built from User-Agent strings."),
        ("Flows", "Each conversation as one record: who, how long, and bytes each way."),
        ("Logs", "The raw event stream, unfiltered."),
        ("Watchlist", "IPs and domains you're keeping an eye on."),
        ("Settings", "Capture interface, threat feeds, GeoIP, notifications and more."),
    ]

    def _show_help(self):
        win = tk.Toplevel(self.root)
        win.title("SentinelFusion - guide")
        win.configure(bg=THEME_BG)
        win.geometry("640x640")
        tk.Label(win, text="WHAT AM I LOOKING AT?", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 14), anchor="w", padx=14, pady=10).pack(fill="x")
        tk.Frame(win, bg=THEME_ACCENT, height=2).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_UI, 10), wrap="word",
                                         padx=14, pady=12, bd=0)
        body.pack(fill="both", expand=True)
        body.tag_configure("h", font=(FONT_HEAD, 11), foreground=THEME_ACCENT,
                           spacing1=8, spacing3=2)
        body.tag_configure("b", font=(FONT_UI, 10), foreground=THEME_FG,
                           spacing3=6, lmargin1=14, lmargin2=14)
        body.insert("end", "The top bar is always-on: capture status, counts, and an overall "
                    "threat level. Hover any number for what it means.\n\n")
        body.insert("end", "THE TABS\n", "h")
        for name, desc in self.TAB_GUIDE:
            body.insert("end", f"{name}\n", "h")
            body.insert("end", f"{desc}\n", "b")
        body.insert("end", "\nCOLOUR CODES\n", "h")
        body.insert("end", "Red = alert or flagged / hostile.  Amber = warning or caution.  "
                    "Cyan = normal / informational.\n", "b")
        body.config(state="disabled")
        tk.Button(win, text="Got it", command=win.destroy, bg=THEME_PANEL,
                  fg=THEME_FG, bd=0, padx=16, pady=4).pack(pady=10)

    def _refresh_hud(self):
        try:
            import time as _t
            ext = threat_detection.external_endpoints()
            flagged = self._flagged_ips()
            flows = threat_detection.flows
            n_alert = events.unacked_count("ALERT")
            n_warn = events.unacked_count("WARNING")

            # packets/sec across everything (diff total process counts)
            total = sum(threat_detection._safe_copy(threat_detection.process_counts).values())
            now = _t.time()
            pps = 0.0
            if self._hud_last_pkts is not None and self._hud_last_t and now > self._hud_last_t:
                pps = max(0.0, (total - self._hud_last_pkts) / (now - self._hud_last_t))
            self._hud_last_pkts, self._hud_last_t = total, now

            # Real monitoring status: is the sniffer alive and seeing packets?
            cap = threat_detection.capture_status()
            running = self._capture_running()
            age = (now - cap["last_ts"]) if cap["last_ts"] else 1e9
            if not running:
                status, scol = "Stopped", THEME_RED
            elif age <= 5:
                status, scol = "Monitoring", THEME_GREEN
            else:
                status, scol = "Idle", THEME_AMBER
            self._hud_cells["status"].config(text=status, fg=scol)
            self._hud_cells["endpoints"].config(text=str(len(ext)), fg=THEME_FG)
            self._hud_cells["connections"].config(text=str(len(flows)), fg=THEME_FG)
            self._hud_cells["flagged"].config(
                text=str(len(flagged)), fg=THEME_RED if flagged else THEME_FG)
            self._hud_cells["alerts"].config(
                text=str(n_alert), fg=THEME_RED if n_alert else THEME_FG)
            self._hud_cells["warnings"].config(
                text=str(n_warn), fg=THEME_AMBER if n_warn else THEME_FG)
            self._hud_cells["rate"].config(text=_human_count(pps), fg=THEME_FG)

            if flagged or n_alert:
                level, color = "Elevated", THEME_RED
            elif n_warn:
                level, color = "Guarded", THEME_AMBER
            else:
                level, color = "Normal", THEME_GREEN
            self._hud_cells["threat"].config(text=level, fg=color)
        except Exception as e:
            print("HUD refresh error:", e)
        self.root.after(1000, self._refresh_hud)

    # ---------- right-click cross-navigation ----------

    def _bind_context(self, tree, ip_getter):
        def handler(event):
            item = tree.identify_row(event.y)
            if not item:
                return
            tree.selection_set(item)
            ip = ip_getter(item)
            if ip:
                self._popup_context_menu(event, ip)
        tree.bind("<Button-3>", handler)

    def _popup_context_menu(self, event, ip, alert_meta=None):
        """Shared right-click menu.

        When `alert_meta` is supplied (from the Alerts tab) the detector-feedback
        options are prepended. Both live in one menu because a Tk widget keeps
        only the last <Button-3> binding - two separate menus silently cancel.
        """
        menu = tk.Menu(self.root, tearoff=0, bg=THEME_PANEL, fg=THEME_FG,
                       activebackground=THEME_SEL, activeforeground=THEME_ACCENT,
                       bd=0)
        if alert_meta:
            sev, cat, src, msg, _key = alert_meta
            menu.add_command(
                label=f"Mark accurate  (true positive - {cat})",
                command=lambda: self._record_feedback(
                    feedback_loop.TRUE_POSITIVE, cat, src, sev, msg))
            menu.add_command(
                label=f"Mark false alarm  (false positive - {cat})",
                command=lambda: self._record_feedback(
                    feedback_loop.FALSE_POSITIVE, cat, src, sev, msg))
            if ip and cat not in allowlist.NEVER_SUPPRESS:
                menu.add_command(
                    label=f"Allow {ip} for '{cat}' alerts  (stop repeating)",
                    command=lambda: self._allow_destination(ip, cat))
            menu.add_separator()
        if ip:
            menu.add_command(label=f"Inspect {ip}  (capture)", command=lambda: self._inspect_ip(ip))
            menu.add_command(label="Endpoint detail", command=lambda: self._open_endpoint(ip))
            menu.add_command(label="Enrich IP  (full profile)", command=lambda: self._enrich_ip(ip))
            menu.add_command(label="DNS chain  (why this connection?)",
                             command=lambda: self._show_dns_chain(ip))
            menu.add_command(label="Export PCAP  (open in Wireshark)",
                             command=lambda: self._export_ip_pcap(ip))
            menu.add_command(label="Build evidence bundle  (forensics)",
                             command=lambda: self._build_evidence(ip))
            menu.add_separator()
            menu.add_command(label="Copy IP", command=lambda: self._copy_text(ip))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _show_resolution_graph(self):
        """Forward view: which lookups led to traffic, and which went nowhere.

        The DNS log answers "what was resolved"; the per-IP chain answers "why
        does this connection exist". This is the third question - across every
        recent lookup, which ones actually produced a live flow. A name resolved
        but never contacted is unremarkable on its own; a run of them from one
        process is what domain-generation malware looks like while it hunts for
        a live controller.
        """
        win = tk.Toplevel(self.root)
        win.title("DNS resolution graph")
        win.configure(bg=THEME_BG)
        win.geometry("820x560")
        tk.Label(win, text="RESOLUTION GRAPH   lookup -> address -> live?",
                 bg=THEME_HEAD, fg=THEME_ACCENT, font=(FONT_HEAD, 13),
                 anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        summary = tk.Label(win, text="", bg=THEME_BG, fg=THEME_MUTED,
                           font=(FONT_UI, 9), anchor="w", padx=14, pady=6)
        summary.pack(fill="x")
        cols = ("name", "type", "ips", "live", "client")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c, txt, w in (("name", "NAME", 280), ("type", "TYPE", 60),
                          ("ips", "RESOLVED TO", 250), ("live", "LIVE FLOW", 80),
                          ("client", "ASKED BY", 130)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.tag_configure("live", foreground=THEME_GREEN)
        tree.tag_configure("dead", foreground=THEME_MUTED)
        tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        def refresh():
            tree.delete(*tree.get_children())
            try:
                import dns_chain, dns_log as _dns
                rows = dns_chain.resolution_graph(dns_log=_dns,
                                                  flow_tracker=flow_tracker)
            except Exception as exc:
                summary.config(text=f"could not build graph: {exc}")
                return
            live_n = 0
            for r in rows:
                if r["live"]:
                    live_n += 1
                tree.insert("", "end", values=(
                    r["name"] or "-", r["qtype"] or "-",
                    ", ".join(r["ips"])[:44] or "(no answer)",
                    "yes" if r["live"] else "-",
                    r["client"] or "-"), tags=("live" if r["live"] else "dead",))
            summary.config(text=f"{len(rows)} recent lookup(s), {live_n} with a "
                                f"live flow. Resolved-but-never-contacted names "
                                "in bulk are worth a look.")

        ttk.Button(win, text="Refresh", command=refresh).pack(pady=(0, 10))
        refresh()

    def _show_dns_chain(self, ip):
        """Show why a connection to this IP exists: the DNS lookup that led here."""
        try:
            import dns_chain, dns_log as _dns
            chain = dns_chain.chains_for_ip(ip, dns_log=_dns, flow_tracker=flow_tracker)
            lines = dns_chain.chain_summary(chain)
        except Exception as exc:
            lines = [f"could not build chain: {exc}"]
        win = tk.Toplevel(self.root)
        win.title(f"DNS chain - {ip}")
        win.configure(bg=THEME_BG)
        win.geometry("560x360")
        tk.Label(win, text=f"RESOLUTION CHAIN   {ip}", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 12), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        body.insert("1.0", "\n".join(lines))
        body.config(state="disabled")

    def _export_ip_pcap(self, ip):
        """Dump this connection's retained packets to a .pcap for Wireshark."""
        held = threat_detection.retained_packet_count(ip)
        if held == 0:
            messagebox.showinfo("Export PCAP",
                                f"No packets retained for {ip} yet. Let some traffic "
                                "flow, then try again.")
            return
        default = f"sentinelfusion_{ip.replace('.', '_').replace(':', '_')}.pcap"
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap", initialfile=default,
            filetypes=[("PCAP capture", "*.pcap"), ("All files", "*.*")])
        if not path:
            return
        n = threat_detection.export_flow_pcap(ip, path)
        if n:
            messagebox.showinfo("Export PCAP",
                                f"Wrote {n} packet(s) involving {ip} to:\n{path}")
        else:
            messagebox.showwarning("Export PCAP", "Nothing was written (no packets or write error).")

    def _build_evidence(self, ip):
        """Assemble a forensic evidence bundle for an actor and save it."""
        out_dir = filedialog.askdirectory(title="Choose a folder for the evidence bundle")
        if not out_dir:
            return
        import os as _os
        bundle_dir = _os.path.join(out_dir, f"evidence_{ip.replace('.', '_')}_{int(time.time())}")

        def work():
            try:
                import db_manager, dns_log as _dns, http_log as _http
                import geo_lookup as _geo, threat_intel as _ti
                tl = forensics.timeline(ip, db=db_manager, dns_log=_dns,
                                        flow_tracker=flow_tracker, http_log=_http,
                                        asset_registry=asset_registry)
                prof = enrichment.profile(ip, geo_lookup=_geo, threat_intel=_ti,
                                          threat_detection=threat_detection, dns_log=_dns,
                                          flow_tracker=flow_tracker, correlation=correlation)
                iocs = forensics.extract_iocs(ip, dns_log=_dns, http_log=_http,
                                              threat_detection=threat_detection,
                                              enrichment_profile=prof)
                # include a PCAP if we have retained packets
                pcap_path = None
                if threat_detection.retained_packet_count(ip):
                    pcap_path = _os.path.join(bundle_dir, "capture.pcap")
                    _os.makedirs(bundle_dir, exist_ok=True)
                    threat_detection.export_flow_pcap(ip, pcap_path)
                manifest = forensics.build_bundle(
                    ip, bundle_dir, timeline_events=tl, iocs=iocs,
                    enrichment_lines=enrichment.summarize(prof), pcap_path=pcap_path)
                events.log_event("INFO", "soar", "forensics",
                                 f"Evidence bundle built for {ip} "
                                 f"({len(manifest['artifacts'])} artifacts)")
                self.root.after(0, lambda: messagebox.showinfo(
                    "Evidence bundle",
                    f"Bundle written to:\n{bundle_dir}\n\n"
                    f"{len(manifest['artifacts'])} artifact(s), each SHA-256 hashed "
                    "in manifest.json."))
            except Exception as exc:
                self.root.after(0, lambda e=exc: messagebox.showerror(
                    "Evidence bundle", f"Could not build bundle: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _enrich_ip(self, ip):
        """Assemble and show everything known about an IP in one panel."""
        win = tk.Toplevel(self.root)
        win.title(f"IP profile - {ip}")
        win.configure(bg=THEME_BG)
        win.geometry("620x600")
        tk.Label(win, text=f"IP PROFILE   {ip}", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        rule = tk.Frame(win, bg=THEME_ACCENT, height=2)
        rule.pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=("Consolas", 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        body.insert("1.0", "Gathering...")
        body.config(state="disabled")

        def work():
            try:
                import geo_lookup as _geo
                import threat_intel as _ti
                import dns_log as _dns
                import http_log as _http
                import rtt_tracker as _rtt
                import dns_chain as _dc
                prof = enrichment.profile(
                    ip, geo_lookup=_geo, threat_intel=_ti,
                    threat_detection=threat_detection, dns_log=_dns,
                    flow_tracker=flow_tracker, http_log=_http, correlation=correlation,
                    rtt_tracker=_rtt, dns_chain=_dc)
                text = "\n".join(enrichment.summarize(prof))
                level = prof.get("risk", ("", ""))[0]
            except Exception as exc:
                text, level = f"Could not build profile: {exc}", ""

            def show():
                colors = {"HOSTILE": THEME_RED, "CRITICAL": THEME_RED, "HIGH": THEME_RED,
                          "WATCH": THEME_AMBER, "NORMAL": THEME_ACCENT}
                rule.config(bg=colors.get(level, THEME_ACCENT))
                body.config(state="normal")
                body.delete("1.0", "end")
                body.insert("1.0", text)
                # highlight section headers and the verdict line
                body.tag_configure("hdr", foreground=THEME_ACCENT, font=(FONT_HEAD, 10))
                for kw in ("LOCATION / NETWORK", "REPUTATION", "DNS ", "TRAFFIC", "HTTP ",
                           "INCIDENT"):
                    idx = "1.0"
                    while True:
                        pos = body.search(kw, idx, stopindex="end")
                        if not pos:
                            break
                        body.tag_add("hdr", pos, f"{pos} lineend")
                        idx = f"{pos}+1line"
                body.config(state="disabled")
            self.root.after(0, show)

        threading.Thread(target=work, daemon=True).start()
        btns = tk.Frame(win, bg=THEME_BG)
        btns.pack(fill="x", pady=(0, 8))
        tk.Button(btns, text="Copy IP", command=lambda: self._copy_text(ip),
                  bg=THEME_PANEL, fg=THEME_FG, bd=0).pack(side="left", padx=10)
        tk.Button(btns, text="Add to watchlist",
                  command=lambda: self._watch_add_ip(ip), bg=THEME_PANEL,
                  fg=THEME_FG, bd=0).pack(side="left")
        tk.Button(btns, text="Fingerprint TLS (JARM)",
                  command=lambda: self._jarm_ip(ip, body), bg=THEME_PANEL,
                  fg=THEME_FG, bd=0).pack(side="left", padx=6)
        tk.Button(btns, text="Close", command=win.destroy, bg=THEME_PANEL,
                  fg=THEME_FG, bd=0).pack(side="right", padx=10)

    def _jarm_ip(self, ip, body_widget):
        """Actively JARM-fingerprint a host's TLS stack (on demand)."""
        def work():
            try:
                import jarm_fingerprint
                res = jarm_fingerprint.fingerprint(ip, 443, timeout=4.0)
                line = jarm_fingerprint.describe(res)
            except Exception as exc:
                line = f"JARM error: {exc}"

            def show():
                try:
                    body_widget.config(state="normal")
                    body_widget.insert("end", f"\n\nTLS SERVER FINGERPRINT\n   {line}\n")
                    body_widget.config(state="disabled")
                except Exception:
                    pass
            self.root.after(0, show)

        threading.Thread(target=work, daemon=True).start()

    def _watch_add_ip(self, ip):
        try:
            watchlist.add("ip", ip, note="added from IP profile")
        except Exception:
            pass

    def _inspect_ip(self, ip):
        try:
            self.target_var.set(ip)
        except Exception:
            pass
        try:
            self.nb.select(self.inspection_tab)
        except Exception:
            pass
        self._capture()

    def _copy_text(self, text):
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(text))
        except Exception:
            pass

    def _appep_ip(self, item):
        vals = self.app_ep_tree.item(item).get("values") or []
        ip = str(vals[1]) if len(vals) > 1 else ""
        return ip if self._looks_like_ip(ip) else None

    def _build_metrics_tab(self):
        self.banner = tk.Label(
            self.metrics_tab, text="Starting capture...",
            font=(FONT_HEAD, 12), anchor="w",
        )
        self.banner.pack(fill="x", padx=10, pady=(10, 0))

        self.counters = tk.Label(
            self.metrics_tab, text="", font=(FONT_UI, 10), anchor="w", fg=THEME_MUTED
        )
        self.counters.pack(fill="x", padx=10, pady=(0, 6))

        # Live throughput strip (bytes/s over the last ~2 minutes).
        self._tp_hist = deque(maxlen=120)   # (t, bytes_per_s, pkts_per_s)
        self._tp_last = None                # (t, total_bytes, total_pkts)
        self.tp_fig = Figure(figsize=(8, 1.5), dpi=100)
        self.ax_tp = self.tp_fig.add_subplot(1, 1, 1)
        self.tp_fig.subplots_adjust(left=0.08, right=0.98, top=0.82, bottom=0.28)
        self.tp_canvas = FigureCanvasTkAgg(self.tp_fig, master=self.metrics_tab)
        self.tp_canvas.get_tk_widget().pack(fill="x", padx=10, pady=(0, 6))
        self._draw_throughput()

        paned = ttk.PanedWindow(self.metrics_tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Left: embedded matplotlib charts (2x2).
        chart_frame = ttk.Frame(paned)
        paned.add(chart_frame, weight=1)

        self.fig = Figure(figsize=(6, 7), dpi=100)
        self.ax_src = self.fig.add_subplot(2, 2, 1)
        self.ax_geo = self.fig.add_subplot(2, 2, 2)
        self.ax_app = self.fig.add_subplot(2, 2, 3)
        self.ax_proto = self.fig.add_subplot(2, 2, 4)
        self.fig.subplots_adjust(
            hspace=0.55, wspace=0.45, left=0.2, right=0.97, top=0.92, bottom=0.08
        )
        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # Right: the cinematic ops map (live communication web).
        map_frame = ttk.Frame(paned)
        paned.add(map_frame, weight=1)
        self.ops_map = OpsMap(map_frame, on_select=self._on_endpoint_select)

    def _build_inspection_tab(self):
        self._last_packets = []
        self._last_findings = []

        # Control bar.
        bar = ttk.Frame(self.inspection_tab)
        bar.pack(fill="x", padx=10, pady=10)

        self.scan_btn = ttk.Button(bar, text="Scan network", command=self._scan_network)
        self.scan_btn.pack(side="left")

        ttk.Label(bar, text="   Target IP:").pack(side="left")
        self.target_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.target_var, width=16).pack(side="left", padx=(3, 8))

        ttk.Label(bar, text="Packets:").pack(side="left")
        self.count_var = tk.StringVar(value="50")
        ttk.Entry(bar, textvariable=self.count_var, width=5).pack(side="left", padx=(3, 8))

        self.capture_btn = ttk.Button(bar, text="Capture + inspect", command=self._capture)
        self.capture_btn.pack(side="left")

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.import_btn = ttk.Button(bar, text="Import .pcap", command=self._import_pcap)
        self.import_btn.pack(side="left")
        self.export_btn = ttk.Button(bar, text="Export .pcap", command=self._export_pcap)
        self.export_btn.pack(side="left", padx=(6, 0))
        self.review_btn = ttk.Button(bar, text="Capture review", command=self._show_review)
        self.review_btn.pack(side="left", padx=(6, 0))

        self.report_btn = ttk.Button(bar, text="Generate report", command=self._generate_report)
        self.report_btn.pack(side="right")

        self.insp_status = tk.Label(
            self.inspection_tab,
            text="Scan the network, or type a target IP, then Capture + inspect.",
            anchor="w", fg=THEME_MUTED,
        )
        self.insp_status.pack(fill="x", padx=10)

        paned = ttk.PanedWindow(self.inspection_tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        # Left: devices (top) + captured packets (bottom).
        left = ttk.PanedWindow(paned, orient="vertical")
        paned.add(left, weight=1)

        dev_frame = ttk.LabelFrame(left, text="Devices on the network")
        left.add(dev_frame, weight=1)
        self.dev_tree = ttk.Treeview(
            dev_frame, columns=("ip", "mac", "host"), show="headings", height=6
        )
        for col, txt, w in (("ip", "IP", 120), ("mac", "MAC", 150), ("host", "HOST / VENDOR", 170)):
            self.dev_tree.heading(col, text=txt)
            self.dev_tree.column(col, width=w)
        self.dev_tree.pack(fill="both", expand=True)
        self.dev_tree.bind("<<TreeviewSelect>>", self._on_device_select)

        pkt_frame = ttk.LabelFrame(left, text="Captured packets")
        left.add(pkt_frame, weight=1)
        self.pkt_tree = ttk.Treeview(
            pkt_frame, columns=("n", "summary", "dpi"), show="headings", height=8
        )
        self.pkt_tree.heading("n", text="#")
        self.pkt_tree.column("n", width=44, anchor="e")
        self.pkt_tree.heading("summary", text="SUMMARY")
        self.pkt_tree.column("summary", width=300)
        self.pkt_tree.heading("dpi", text="DPI")
        self.pkt_tree.column("dpi", width=180)
        self.pkt_tree.pack(fill="both", expand=True)
        self.pkt_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        prow = ttk.Frame(pkt_frame)
        prow.pack(fill="x", pady=(4, 2))
        ttk.Button(prow, text="Follow TCP stream",
                   command=self._follow_stream).pack(side="left")
        ttk.Label(prow, text="select a TCP packet, then reassemble its whole conversation").pack(side="left", padx=8)

        # Right: structured packet anatomy (top) + hex view (bottom).
        right = ttk.LabelFrame(paned, text="Packet detail")
        paned.add(right, weight=2)
        detail_paned = ttk.PanedWindow(right, orient="vertical")
        detail_paned.pack(fill="both", expand=True)

        anat_frame = ttk.Frame(detail_paned)
        detail_paned.add(anat_frame, weight=3)
        self.anatomy_tree = ttk.Treeview(anat_frame, columns=("value",), show="tree headings")
        self.anatomy_tree.heading("#0", text="FIELD")
        self.anatomy_tree.column("#0", width=200)
        self.anatomy_tree.heading("value", text="VALUE")
        self.anatomy_tree.column("value", width=380)
        avs = ttk.Scrollbar(anat_frame, orient="vertical", command=self.anatomy_tree.yview)
        self.anatomy_tree.configure(yscrollcommand=avs.set)
        self.anatomy_tree.pack(side="left", fill="both", expand=True)
        avs.pack(side="right", fill="y")
        self.anatomy_tree.tag_configure("section", font=(FONT_HEAD, 9),
                                        foreground=THEME_ACCENT)
        self.anatomy_tree.tag_configure("flag", foreground=THEME_RED)

        hex_frame = ttk.Frame(detail_paned)
        detail_paned.add(hex_frame, weight=2)
        self.dump_text = scrolledtext.ScrolledText(hex_frame, font=("Consolas", 9), wrap="none")
        self.dump_text.pack(fill="both", expand=True)
        self.dump_text.config(state="disabled")

    def _build_apps_tab(self):
        self._apps_selected = None
        paned = ttk.PanedWindow(self.apps_tab, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        left = ttk.LabelFrame(paned, text="Applications")
        paned.add(left, weight=0)
        self.app_list = tk.Listbox(left, width=26, font=("Consolas", 10),
                                   exportselection=False)
        self.app_list.pack(fill="both", expand=True)
        self.app_list.bind("<<ListboxSelect>>", self._on_app_select)
        ttk.Button(left, text="Map connections",
                   command=self._show_process_map_selected).pack(fill="x", pady=(4, 0))

        right = ttk.LabelFrame(paned, text="Endpoints for the selected application")
        paned.add(right, weight=1)
        cols = ("host", "ip", "pkts", "ports", "proto", "bytes")
        self.app_ep_tree = ttk.Treeview(right, columns=cols, show="headings")
        for c, txt, w in (("host", "HOST", 210), ("ip", "IP", 130), ("pkts", "PKTS", 70),
                          ("ports", "PORTS", 120), ("proto", "PROTO", 90),
                          ("bytes", "BYTES", 90)):
            self.app_ep_tree.heading(c, text=txt)
            self.app_ep_tree.column(c, width=w)
        self._bind_context(self.app_ep_tree, self._appep_ip)
        self.app_ep_tree.pack(fill="both", expand=True)

        self.root.after(3000, self._refresh_apps)

    def _refresh_apps(self):
        names = threat_detection.app_names()
        if list(self.app_list.get(0, "end")) != names:
            self.app_list.delete(0, "end")
            for n in names:
                self.app_list.insert("end", n)
            if self._apps_selected in names:
                self.app_list.selection_set(names.index(self._apps_selected))
        if self._apps_selected:
            self._populate_app_endpoints(self._apps_selected)
        self.root.after(3000, self._refresh_apps)

    def _show_process_map_selected(self):
        if not self._apps_selected:
            return
        self._show_process_map(self._apps_selected)

    # Role -> colour for the connection map.
    _ROLE_COLORS = {
        "Game server": "#5fd08a",
        "Voice chat": "#c98ae6",
        "Matchmaking / platform": "#5b9dd9",
        "Anti-cheat": "#e0993a",
        "Auth / login": "#e0c04a",
        "CDN / content / update": "#4fb0b4",
        "Telemetry / analytics": "#9aa7b3",
        "Web / API": "#7fb8e6",
        "Peer-to-peer": "#d98a8a",
        "Unknown": "#68808a",
    }

    def _show_process_map(self, app):
        """A visual linking a process to every endpoint it talks to, each
        classified by what it's for (game / voice / matchmaking / ...)."""
        win = tk.Toplevel(self.root)
        win.title(f"Connection map - {app}")
        win.configure(bg=THEME_BG)
        win.geometry("960x620")
        tk.Label(win, text=f"CONNECTION MAP   {app}", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")

        body = tk.Frame(win, bg=THEME_BG)
        body.pack(fill="both", expand=True)
        canvas = tk.Canvas(body, bg=THEME_BG, highlightthickness=0, width=560)
        canvas.pack(side="left", fill="both", expand=True)
        side = tk.Frame(body, bg=THEME_PANEL, width=360)
        side.pack(side="right", fill="y")
        side.pack_propagate(False)
        detail = scrolledtext.ScrolledText(side, bg=THEME_PANEL, fg=THEME_FG,
                                           font=(FONT_DATA, 9), wrap="word",
                                           padx=10, pady=8, bd=0)
        detail.pack(fill="both", expand=True)
        detail.insert("1.0", "Select a node to see why it was classified.\n")
        detail.config(state="disabled")

        status = tk.Label(win, text="gathering...", bg=THEME_PANEL, fg=THEME_MUTED,
                          font=(FONT_DATA, 9), anchor="w", padx=12, pady=6)
        status.pack(fill="x")

        node_hit = {}   # canvas item -> endpoint dict

        def show_detail(ep):
            detail.config(state="normal")
            detail.delete("1.0", "end")
            title = ep.get("host") or ep["ip"]
            detail.insert("end", f"{title}\n", "h")
            detail.insert("end", f"{ep['ip']}\n\n")
            detail.insert("end", f"Role: {ep.get('role', 'Unknown')} "
                                 f"({ep.get('confidence', 0)}%)\n\n", "h")
            detail.insert("end", "Why:\n")
            for r in ep.get("reasons", []):
                detail.insert("end", f"  - {r}\n")
            detail.insert("end", "\n")
            io = f"{_human_bytes(ep.get('out_bytes', 0))} out / " \
                 f"{_human_bytes(ep.get('in_bytes', 0))} in"
            detail.insert("end", f"Traffic: {io}\n")
            try:
                q = rtt_tracker.quality(ep["ip"])
                if q.get("rtt_ms") is not None or q.get("jitter_ms") is not None:
                    bits = []
                    if q.get("rtt_ms") is not None:
                        bits.append(f"RTT ~{q['rtt_ms']:.0f}ms")
                    if q.get("jitter_ms") is not None:
                        bits.append(f"jitter {q['jitter_ms']:.0f}ms")
                    detail.insert("end", f"Link: {q['verdict']} ({', '.join(bits)})\n")
            except Exception:
                pass
            if ep.get("ports"):
                ports = ", ".join(str(p) for p, _ in ep["ports"][:6])
                detail.insert("end", f"Ports: {ports}\n")
            if ep.get("isp") or ep.get("asn"):
                detail.insert("end", f"Network: {ep.get('isp') or ''} {ep.get('asn') or ''}\n")
            detail.tag_configure("h", foreground=THEME_ACCENT, font=(FONT_HEAD, 10))
            detail.config(state="disabled")

        def draw(endpoints):
            canvas.delete("all")
            node_hit.clear()
            w = canvas.winfo_width() or 560
            h = canvas.winfo_height() or 520
            cx, cy = w // 2, h // 2
            # central process node
            r = 46
            canvas.create_oval(cx - r, cy - r, cx + r, cy + r, outline=THEME_ACCENT,
                               width=2, fill=THEME_PANEL)
            canvas.create_text(cx, cy - 6, text=app[:16], fill=THEME_FG,
                               font=(FONT_HEAD, 10), width=80)
            canvas.create_text(cx, cy + 12, text=f"{len(endpoints)} links", fill=THEME_MUTED,
                               font=(FONT_DATA, 8))
            if not endpoints:
                status.config(text=f"{app}: no external connections observed yet.")
                return
            import math
            n = len(endpoints)
            radius = min(w, h) // 2 - 90
            for i, ep in enumerate(endpoints):
                ang = (2 * math.pi * i / n) - math.pi / 2
                ex, ey = cx + radius * math.cos(ang), cy + radius * math.sin(ang)
                color = self._ROLE_COLORS.get(ep.get("role"), THEME_MUTED)
                canvas.create_line(cx, cy, ex, ey, fill=THEME_BORDER, width=1)
                nr = 22
                oval = canvas.create_oval(ex - nr, ey - nr, ex + nr, ey + nr,
                                          outline=color, width=2, fill=THEME_PANEL,
                                          activewidth=3)
                label = (ep.get("host") or ep["ip"]).split(".")[0][:12]
                txt = canvas.create_text(ex, ey, text=label, fill=color,
                                         font=(FONT_DATA, 8))
                # role caption just outside the node
                lx = ex + (34 if math.cos(ang) >= 0 else -34)
                anchor = "w" if math.cos(ang) >= 0 else "e"
                rcap = canvas.create_text(lx, ey, text=ep.get("role", ""), fill=THEME_MUTED,
                                          font=(FONT_DATA, 8), anchor=anchor, width=120)
                for item in (oval, txt, rcap):
                    node_hit[item] = ep
            status.config(text=f"{app}: {n} endpoint(s).  Click a node for the evidence.")

        def on_click(event):
            item = canvas.find_closest(event.x, event.y)
            if item and item[0] in node_hit:
                ep = node_hit[item[0]]
                show_detail(ep)
                for it, e in node_hit.items():
                    if canvas.type(it) == "oval":
                        canvas.itemconfig(it, width=3 if e is ep else 2)
        canvas.bind("<Button-1>", on_click)

        def work():
            try:
                import geo_lookup as _geo
                import dns_log as _dns
                eps = threat_detection.process_map(
                    app, geo_lookup=_geo, dns_log=_dns, flow_tracker=flow_tracker,
                    flow_analytics=flow_analytics, service_roles=service_roles)
            except Exception as exc:
                eps = []
                msg = f"error: {exc}"
                self.root.after(0, lambda m=msg: status.config(text=m))
            self.root.after(0, lambda: draw(eps))
            # role summary + infrastructure rollup in the side panel
            try:
                lines = service_roles.summarize_process(app, eps)
                import geo_lookup as _geo2
                groups = infra_rollup.rollup(eps, geo_lookup=_geo2, novelty=novelty)
                roll = infra_rollup.summarize(groups)
                outs = infra_rollup.outliers(groups)
                extra = []
                if outs:
                    extra.append("")
                    extra.append("WORTH A LOOK:")
                    for g in outs[:4]:
                        why = "new org" if g.get("is_new") else "lone host (not big cloud)"
                        extra.append(f"  {g['org']} - {why}")

                def show_summary():
                    detail.config(state="normal")
                    detail.delete("1.0", "end")
                    detail.insert("1.0", "\n".join(lines) + "\n\n" +
                                  "\n".join(roll) + "\n" + "\n".join(extra) +
                                  "\n\nClick any node for details.")
                    detail.config(state="disabled")
                self.root.after(0, show_summary)
            except Exception:
                pass

        canvas.after(150, lambda: threading.Thread(target=work, daemon=True).start())
        tk.Button(win, text="Refresh",
                  command=lambda: threading.Thread(target=work, daemon=True).start(),
                  bg=THEME_BTN, fg=THEME_FG, bd=0).pack(pady=(0, 8))

    def _on_app_select(self, _evt):
        sel = self.app_list.curselection()
        if sel:
            self._apps_selected = self.app_list.get(sel[0])
            self._populate_app_endpoints(self._apps_selected)

    def _populate_app_endpoints(self, app):
        rows = threat_detection.endpoints_for_app(app)
        self.app_ep_tree.delete(*self.app_ep_tree.get_children())
        for r in rows:
            ports = ", ".join(str(p) for p, _ in r["ports"][:5])
            proto = ", ".join(p for p, _ in r["protos"][:3])
            self.app_ep_tree.insert("", "end", values=(
                r["host"] or "-", r["ip"], r["packets"], ports, proto,
                _human_bytes(r["bytes"])))

    def _build_active_tab(self):
        self._prev_proc = {}
        top = ttk.Frame(self.active_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(top, text="Applications actively sending / receiving right now").pack(side="left")
        self.active_count = ttk.Label(top, text="")
        self.active_count.pack(side="right")

        cols = ("app", "rate", "total")
        self.active_tree = ttk.Treeview(self.active_tab, columns=cols, show="headings")
        for c, txt, w in (("app", "APPLICATION", 260), ("rate", "PKTS/S", 100),
                          ("total", "TOTAL PACKETS", 130)):
            self.active_tree.heading(c, text=txt)
            self.active_tree.column(c, width=w)
        self.active_tree.pack(fill="both", expand=True, padx=10, pady=10)

        self.root.after(1000, self._refresh_active)

    def _refresh_active(self):
        cur = threat_detection._safe_copy(threat_detection.process_counts)
        rows = []
        for app, cnt in cur.items():
            if app in threat_detection.PSEUDO_APPS:
                continue
            rate = max(0, cnt - self._prev_proc.get(app, cnt))
            rows.append((app, rate, cnt))
        self._prev_proc = cur

        rows.sort(key=lambda t: (t[1], t[2]), reverse=True)
        self.active_tree.delete(*self.active_tree.get_children())
        active = [r for r in rows if r[1] > 0]
        display = active if active else sorted(rows, key=lambda t: t[2], reverse=True)[:12]
        for app, rate, cnt in display:
            self.active_tree.insert("", "end", values=(app, rate, cnt))
        self.active_count.config(text=f"{len(active)} active")
        self.root.after(1000, self._refresh_active)

    def _build_wifi_tab(self):
        # 802.11 WIDS (monitor mode) - the defensive wireless survey.
        wids = ttk.LabelFrame(self.wifi_tab, text="Wireless IDS - 802.11 monitor mode (deauth / rogue AP / evil twin)")
        wids.pack(fill="x", padx=10, pady=(10, 4))
        wr = ttk.Frame(wids)
        wr.pack(fill="x", padx=6, pady=6)
        ttk.Label(wr, text="Monitor iface:").pack(side="left")
        self.wids_iface = tk.StringVar(value="Wi-Fi")
        ttk.Entry(wr, textvariable=self.wids_iface, width=16).pack(side="left", padx=(4, 8))
        self.wids_btn = ttk.Button(wr, text="Start WIDS", command=self._toggle_wids)
        self.wids_btn.pack(side="left")
        ttk.Button(wr, text="Set current as baseline",
                   command=self._wids_baseline).pack(side="left", padx=6)
        self.wids_status = ttk.Label(
            wr, text="requires a monitor-mode-capable adapter (often a USB Wi-Fi adapter on Windows)")
        self.wids_status.pack(side="left", padx=8)
        self.wids_view = tk.Label(
            wids, justify="left", anchor="w", wraplength=940, font=("Consolas", 9),
            bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=6,
            text="Detection-only: listens to management frames in the air and flags deauth floods, "
                 "rogue access points (your SSID from an unexpected BSSID), and evil twins. It never "
                 "transmits. Start it, let it learn the APs around you, then 'Set current as baseline' "
                 "so later imposters stand out.")
        self.wids_view.pack(fill="x", padx=6, pady=(0, 6))
        self._wids_on = False

        # WiGLE token row
        trow = ttk.Frame(self.wifi_tab)
        trow.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(trow, text="WiGLE token:").pack(side="left")
        ttk.Entry(trow, textvariable=self.wigle_var, width=42, show="*").pack(side="left", padx=(4, 6))
        ttk.Button(trow, text="Set", command=self._set_wigle).pack(side="left")
        self.wifi_status = ttk.Label(trow, text="paste your WiGLE 'Encode for use' token, then Set (saved automatically)")
        self.wifi_status.pack(side="left", padx=10)

        # Area search
        area = ttk.LabelFrame(self.wifi_tab, text="Search WiFi networks in an area (WiGLE)")
        area.pack(fill="both", expand=True, padx=10, pady=6)
        ctl = ttk.Frame(area)
        ctl.pack(fill="x", padx=6, pady=6)
        ttk.Label(ctl, text="Lat:").pack(side="left")
        self.wifi_lat = tk.StringVar()
        ttk.Entry(ctl, textvariable=self.wifi_lat, width=10).pack(side="left", padx=(2, 6))
        ttk.Label(ctl, text="Lon:").pack(side="left")
        self.wifi_lon = tk.StringVar()
        ttk.Entry(ctl, textvariable=self.wifi_lon, width=10).pack(side="left", padx=(2, 6))
        ttk.Label(ctl, text="Radius km:").pack(side="left")
        self.wifi_radius = tk.StringVar(value="1")
        ttk.Entry(ctl, textvariable=self.wifi_radius, width=5).pack(side="left", padx=(2, 6))
        ttk.Label(ctl, text="SSID:").pack(side="left")
        self.wifi_ssid = tk.StringVar()
        ttk.Entry(ctl, textvariable=self.wifi_ssid, width=14).pack(side="left", padx=(2, 6))
        ttk.Button(ctl, text="Use my location", command=self._wifi_use_my_loc).pack(side="left", padx=(6, 4))
        self.wifi_search_btn = ttk.Button(ctl, text="Search", command=self._wifi_search)
        self.wifi_search_btn.pack(side="left")

        cols = ("ssid", "bssid", "enc", "lat", "lon")
        self.wifi_tree = ttk.Treeview(area, columns=cols, show="headings")
        for c, txt, w in (("ssid", "SSID", 210), ("bssid", "BSSID", 150),
                          ("enc", "ENCRYPTION", 110), ("lat", "LAT", 95), ("lon", "LON", 95)):
            self.wifi_tree.heading(c, text=txt)
            self.wifi_tree.column(c, width=w)
        self.wifi_tree.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # BSSID geolocation
        bf = ttk.LabelFrame(self.wifi_tab, text="Geolocate a BSSID (Mylnikov + WiGLE)")
        bf.pack(fill="x", padx=10, pady=(0, 10))
        brow = ttk.Frame(bf)
        brow.pack(fill="x", padx=6, pady=6)
        ttk.Label(brow, text="BSSID:").pack(side="left")
        self.bssid_var = tk.StringVar()
        ttk.Entry(brow, textvariable=self.bssid_var, width=22).pack(side="left", padx=(2, 6))
        self.bssid_btn = ttk.Button(brow, text="Locate", command=self._locate_bssid)
        self.bssid_btn.pack(side="left")
        self.bssid_result = ttk.Label(bf, text="", anchor="w", justify="left", font=("Consolas", 9))
        self.bssid_result.pack(fill="x", padx=8, pady=(0, 6))

    def _toggle_wids(self):
        """Start or stop the 802.11 WIDS capture (monitor mode required)."""
        if self._wids_on:
            wifi_wids.stop_capture()
            self._wids_on = False
            self.wids_btn.config(text="Start WIDS")
            self.wids_status.config(text="WIDS stopped.")
            return

        iface = self.wids_iface.get().strip() or "Wi-Fi"

        def emit(sev, cat, msg):
            try:
                events.log_event(sev, cat, "wifi", msg)
            except Exception:
                pass

        ok, message = wifi_wids.start_capture(iface, emit=emit)
        if ok:
            self._wids_on = True
            self.wids_btn.config(text="Stop WIDS")
            self.wids_status.config(text=message)
            self._refresh_wids_view()
        else:
            self.wids_status.config(text=message)

    def _refresh_wids_view(self):
        if not self._wids_on:
            return
        try:
            st = wifi_wids.stats()
            aps = wifi_wids.access_points()
            lines = [f"frames {st['frames']}  |  SSIDs {st['ssids']}  |  "
                     f"BSSIDs {st['bssids']}  |  trusted {st['known']}", ""]
            for ssid, bssids in list(aps.items())[:12]:
                tag = "  [multiple BSSIDs]" if len(bssids) > 1 else ""
                lines.append(f"{ssid or '<hidden>'}: {', '.join(bssids)}{tag}")
            self.wids_view.config(text="\n".join(lines))
        except Exception:
            pass
        self.root.after(2000, self._refresh_wids_view)

    def _wids_baseline(self):
        """Trust the SSID/BSSID pairs seen so far as the known-good baseline."""
        try:
            wifi_wids.lock_baseline()
            st = wifi_wids.stats()
            self.wids_status.config(
                text=f"baseline locked - {st['known']} known network(s). "
                     "New BSSIDs for these SSIDs will now flag as rogue.")
        except Exception as exc:
            self.wids_status.config(text=f"baseline error: {exc}")

    def _set_wigle(self):
        token = self.wigle_var.get().strip()
        wifi_osint.set_wigle_token(token)
        settings.set("wigle_token", token)
        settings.save()
        self.wifi_status.config(text="WiGLE token set and saved." if token else "token cleared")

    # ---------- settings ----------

    def _section(self, parent, text, pad=(10, 8)):
        """A consistent section header: muted uppercase label + hairline underline.

        Gives every tab the same title treatment instead of ad-hoc fonts/sizes.
        Returns the header frame in case the caller wants to add trailing widgets.
        """
        wrap = tk.Frame(parent, bg=THEME_BG)
        wrap.pack(fill="x", padx=pad[0], pady=(pad[1], 0))
        tk.Label(wrap, text=text.upper(), bg=THEME_BG, fg=THEME_MUTED,
                 font=(FONT_UI, 9), anchor="w").pack(side="left")
        tk.Frame(parent, bg=THEME_BORDER, height=1).pack(fill="x", padx=pad[0],
                                                         pady=(3, 6))
        return wrap

    def _scrollable(self, parent, pad=(16, 14)):
        # Return an inner frame inside a vertically-scrollable canvas, so tall
        # tabs (like Settings) never hide content below the window edge.
        canvas = tk.Canvas(parent, bg=THEME_BG, highlightthickness=0)
        vsb = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(canvas, padding=(pad[0], pad[1], pad[0], pad[1]))
        win = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))

        def _wheel(e):
            canvas.yview_scroll(int(-e.delta / 120), "units")
        canvas.bind("<Enter>", lambda e: canvas.bind_all("<MouseWheel>", _wheel))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))
        return inner

    def _show_hunt_playbooks(self):
        """Guided threat-hunting procedures the analyst can run step by step."""
        win = tk.Toplevel(self.root)
        win.title("Threat-hunting playbooks")
        win.configure(bg=THEME_BG)
        win.geometry("760x560")
        tk.Label(win, text="THREAT-HUNTING PLAYBOOKS", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=10, pady=8)
        ttk.Label(bar, text="Hunt:").pack(side="left")
        names = {p["name"]: p["id"] for p in hunt_playbooks.playbooks()}
        sel = tk.StringVar(value=list(names)[0])
        ttk.Combobox(bar, textvariable=sel, values=list(names), width=44,
                     state="readonly").pack(side="left", padx=(4, 8))
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        def show(*_):
            pb = hunt_playbooks.get(names[sel.get()])
            body.config(state="normal")
            body.delete("1.0", "end")
            body.insert("1.0", "\n".join(hunt_playbooks.summarize(pb)))
            body.config(state="disabled")

        def run_all():
            pb = hunt_playbooks.get(names[sel.get()])
            registry = self._hunt_registry()
            body.config(state="normal")
            body.delete("1.0", "end")
            body.insert("end", pb["name"] + "\n\n")
            for i, step in enumerate(pb["steps"], 1):
                body.insert("end", f"{i}. {step['title']}\n   Look for: {step['look_for']}\n")
                res = hunt_playbooks.run_step(step, registry=registry)
                if res["ran"]:
                    r = res["result"]
                    n = len(r) if isinstance(r, list) else ("-" if r is None else 1)
                    body.insert("end", f"   -> {n} result(s)"
                                       + (f"  (error: {res['error']})" if res.get("error") else "")
                                       + "\n\n")
                else:
                    body.insert("end", "   -> manual step (investigate directly)\n\n")
            body.config(state="disabled")

        sel.trace_add("write", show)
        ttk.Button(bar, text="Run linked queries", command=run_all).pack(side="left")
        show()

    def _hunt_registry(self):
        """Map hunt-step query kinds to real data pulls (read-only)."""
        import db_manager
        def search_events(category=None):
            try:
                return db_manager.search_events(category=category, limit=500)
            except Exception:
                return []
        def flows_outbound_heavy():
            try:
                return [f for f in flow_tracker.flows(800, "bytes")
                        if f.get("out_bytes", 0) > 5 * (f.get("in_bytes", 0) or 1)]
            except Exception:
                return []
        def ml_rank():
            try:
                eps = self._ml_endpoint_records()
                return ml_anomaly.rank(eps)
            except Exception:
                return []
        def dns_chainless():
            try:
                import dns_chain, dns_log as _dns
                out = []
                for f in flow_tracker.flows(400, "bytes"):
                    ip = f.get("dst")
                    if ip and not dns_chain.chains_for_ip(ip, dns_log=_dns).get("had_dns"):
                        out.append(ip)
                return list(dict.fromkeys(out))
            except Exception:
                return []
        def novelty_new(kind="ip"):
            try:
                return novelty.recent_new(kind)
            except Exception:
                return []
        return {"search_events": search_events, "flows_outbound_heavy": flows_outbound_heavy,
                "ml_rank": ml_rank, "dns_chainless": dns_chainless, "novelty_new": novelty_new}

    def _ml_endpoint_records(self):
        """Shape live endpoint stats into records for the ML model."""
        recs = []
        try:
            for ip, r in list(threat_detection.endpoint_stats.items()):
                recs.append({
                    "ip": ip, "out_bytes": r.get("out_bytes", 0),
                    "in_bytes": r.get("in_bytes", 0),
                    "packets": r.get("packets", 0), "ports": r.get("ports", {}),
                    "duration": max(0.0, r.get("last", 0) - r.get("first", 0)),
                })
        except Exception:
            pass
        return recs

    def _show_ml_anomalies(self):
        """Train the anomaly model on the current baseline and rank outliers."""
        win = tk.Toplevel(self.root)
        win.title("ML anomaly detection")
        win.configure(bg=THEME_BG)
        win.geometry("720x520")
        tk.Label(win, text="ML ANOMALY DETECTION", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True, padx=10, pady=10)

        def run():
            body.config(state="normal")
            body.delete("1.0", "end")
            eps = self._ml_endpoint_records()
            n = ml_anomaly.train(eps)
            if not n:
                body.insert("1.0", "Not enough endpoints to train yet (need ~8+), or "
                                   "scikit-learn isn't installed. Let more traffic flow "
                                   "and try again.")
                body.config(state="disabled")
                return
            ranked = ml_anomaly.rank(eps, top=25)
            # Emit the clear outliers so ML findings reach Alerts and correlation
            # instead of dying in this window. Deliberately conservative: only
            # flagged anomalies, only once per endpoint per session, and at
            # INFO - the model produces leads, not verdicts, and a detector that
            # fires on ~5% of endpoints every run would drown the alert stream.
            for r in ranked:
                if not r.get("anomaly") or not r.get("ip"):
                    continue
                if r["ip"] in self._ml_reported:
                    continue
                self._ml_reported.add(r["ip"])
                reasons = "; ".join(r.get("reasons") or []) or "no single feature dominant"
                events.log_event(
                    "INFO", "endpoint", r["ip"],
                    f"{r['ip']} is a statistical outlier vs this network's "
                    f"baseline (score {r['score']}): {reasons}. A lead to "
                    "investigate, not a verdict.")
            body.insert("end", f"Trained on {n} endpoints. Most anomalous first "
                               "(higher score = more unusual vs your baseline):\n\n")
            for r in ranked:
                flag = "  << ANOMALY" if r["anomaly"] else ""
                body.insert("end", f"{r['score']:.3f}  {r['ip']}{flag}\n")
                if r["reasons"]:
                    body.insert("end", f"        {'; '.join(r['reasons'])}\n")
            body.insert("end", "\nNote: outliers are leads to investigate, not verdicts. "
                               "A backup server or big download can score high.")
            body.config(state="disabled")

        ttk.Button(win, text="Train & rank", command=run).pack(pady=(0, 8))
        run()

    def _show_feedback(self):
        """Show detection accuracy from analyst verdicts, and apply the tuning
        it recommends without retyping thresholds by hand."""
        import db_manager
        win = tk.Toplevel(self.root)
        win.title("Detection feedback")
        win.configure(bg=THEME_BG)
        win.geometry("820x600")
        tk.Label(win, text="DETECTION FEEDBACK", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         height=10, padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True, padx=10, pady=(10, 6))

        tk.Label(win, text="Recommendations - select one and apply the nudge:",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 9),
                 anchor="w", padx=14).pack(fill="x")
        cols = ("dir", "category", "issue", "suggestion")
        tree = ttk.Treeview(win, columns=cols, show="headings", height=7)
        for c, txt, w in (("dir", "", 34), ("category", "CATEGORY", 90),
                          ("issue", "WHAT THE DATA SHOWS", 300),
                          ("suggestion", "RECOMMENDED", 330)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.tag_configure("raise", foreground=THEME_AMBER)
        tree.tag_configure("lower", foreground=THEME_ACCENT)
        tree.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        recs_by_item = {}

        def refresh():
            body.config(state="normal")
            body.delete("1.0", "end")
            body.insert("1.0", "\n".join(feedback_loop.summary(db=db_manager)))
            off = detection_rules.disabled_categories()
            if off:
                body.insert("end", "\n\nCurrently disabled (generating nothing): "
                                   + ", ".join(off))
            body.config(state="disabled")
            tree.delete(*tree.get_children())
            recs_by_item.clear()
            for r in feedback_loop.recommendations(db=db_manager,
                                                   detection_rules=detection_rules):
                arrow = {"raise": "\u2191", "lower": "\u2193"}.get(r["direction"], "=")
                item = tree.insert("", "end", values=(
                    arrow, r["category"], r["issue"], r["suggestion"]),
                    tags=(r["direction"] or "",))
                recs_by_item[item] = r

        def apply_selected():
            sel = tree.selection()
            if not sel:
                return
            rec = recs_by_item.get(sel[0])
            if not rec or not rec.get("direction"):
                messagebox.showinfo("Detection feedback",
                                    "That entry is an affirmation, not a change - "
                                    "the rule is already well tuned.")
                return
            ok, old, new = feedback_loop.apply_recommendation(
                rec, detection_rules=detection_rules)
            if not ok:
                messagebox.showwarning(
                    "Detection feedback",
                    "Could not apply: that category has no tunable threshold.")
                return
            events.log_event("INFO", "system", "tuning",
                             f"{rec['category']} threshold {old} -> {new} "
                             f"({rec['direction']}, from analyst feedback)")
            messagebox.showinfo(
                "Detection feedback",
                f"{rec['category']}: threshold {old} -> {new}.\n\n"
                "Applied to the running engine immediately. Export your config "
                "if you want it to survive a restart.")
            refresh()

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bar, text="Apply selected nudge",
                   command=apply_selected).pack(side="left")
        ttk.Button(bar, text="Refresh", command=refresh).pack(side="left", padx=(6, 0))
        tk.Label(bar, text="Mark alerts accurate/false (right-click an alert) to build this up.",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 8)).pack(side="right")
        refresh()

    def _record_feedback(self, verdict, category="", actor="", severity="", message=""):
        """Record an analyst verdict on a detection (from the alert right-click)."""
        import db_manager
        feedback_loop.record(verdict, db=db_manager, category=category, actor=actor,
                             severity=severity, message=message)
        try:
            self.set_status(f"Feedback recorded: {verdict.replace('_', ' ')} for {category}")
        except Exception:
            pass

    def _show_log_sources(self):
        """Configure external log ingestion (syslog / file / Windows Event Log)."""
        win = tk.Toplevel(self.root)
        win.title("Log sources")
        win.configure(bg=THEME_BG)
        win.geometry("640x460")
        tk.Label(win, text="LOG SOURCES", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        info = tk.Label(win, text="Ingest external logs so they correlate alongside "
                                  "packet detections. Security-relevant lines (auth "
                                  "failures, firewall denies, lockouts) become events.",
                        bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 9),
                        wraplength=600, justify="left", anchor="w")
        info.pack(fill="x", padx=14, pady=8)

        status = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                           font=(FONT_DATA, 10), wrap="word", height=8,
                                           padx=12, pady=10, bd=0)
        status.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        def cb(rec):
            log_ingest.forward(rec, events=events)

        def refresh():
            status.config(state="normal")
            status.delete("1.0", "end")
            active = log_sources.running()
            status.insert("1.0", "Active sources: " + (", ".join(active) if active else "none") + "\n")
            status.config(state="disabled")

        row = ttk.Frame(win)
        row.pack(fill="x", padx=10, pady=(0, 4))
        ttk.Button(row, text="Start syslog server (UDP 5514)",
                   command=lambda: (log_sources.start_syslog_server(cb), refresh())).pack(side="left")
        ttk.Button(row, text="Tail a log file...",
                   command=lambda: self._tail_log_file(cb, refresh)).pack(side="left", padx=(6, 0))
        row2 = ttk.Frame(win)
        row2.pack(fill="x", padx=10, pady=(0, 8))
        ttk.Button(row2, text="Start Windows Event Log",
                   command=lambda: (log_sources.start_windows_eventlog(cb), refresh())).pack(side="left")
        ttk.Button(row2, text="Stop all",
                   command=lambda: (log_sources.stop(), refresh())).pack(side="left", padx=(6, 0))
        refresh()

    def _tail_log_file(self, cb, refresh):
        path = filedialog.askopenfilename(title="Choose a log file to tail")
        if path:
            log_sources.start_file_tail(path, cb)
            refresh()

    def _show_integrations(self):
        """Configure outbound webhooks to Slack/Teams/SOAR/SIEM."""
        win = tk.Toplevel(self.root)
        win.title("Integrations")
        win.configure(bg=THEME_BG)
        win.geometry("680x500")
        tk.Label(win, text="OUTBOUND INTEGRATIONS", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        tk.Label(win, text="Send high-severity incidents out to Slack, Teams, or a "
                           "SOAR/SIEM endpoint. Outbound and read-only - SentinelFusion "
                           "never receives commands back or performs containment itself.",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 9), wraplength=640,
                 justify="left", anchor="w").pack(fill="x", padx=14, pady=8)

        form = ttk.Frame(win)
        form.pack(fill="x", padx=12, pady=4)
        ttk.Label(form, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Label(form, text="Webhook URL").grid(row=0, column=1, sticky="w")
        ttk.Label(form, text="Kind").grid(row=0, column=2, sticky="w")
        ttk.Label(form, text="Min severity").grid(row=0, column=3, sticky="w")
        name_v = tk.StringVar(); url_v = tk.StringVar()
        kind_v = tk.StringVar(value="slack"); sev_v = tk.StringVar(value="HIGH")
        ttk.Entry(form, textvariable=name_v, width=12).grid(row=1, column=0, padx=2)
        ttk.Entry(form, textvariable=url_v, width=32).grid(row=1, column=1, padx=2)
        ttk.Combobox(form, textvariable=kind_v, width=8, state="readonly",
                     values=("slack", "teams", "generic", "siem")).grid(row=1, column=2, padx=2)
        ttk.Combobox(form, textvariable=sev_v, width=9, state="readonly",
                     values=("MEDIUM", "HIGH", "CRITICAL")).grid(row=1, column=3, padx=2)

        listing = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                            font=(FONT_DATA, 10), wrap="word", height=8,
                                            padx=12, pady=10, bd=0)
        listing.pack(fill="both", expand=True, padx=10, pady=8)

        def refresh():
            listing.config(state="normal")
            listing.delete("1.0", "end")
            tg = integrations.targets()
            if not tg:
                listing.insert("1.0", "No integrations configured.")
            for nm, t in tg.items():
                state = "on" if t["enabled"] else "off"
                listing.insert("end", f"{nm}  [{t['kind']}]  >= {t['min_severity']}  "
                                      f"({state})\n   {t['url'][:60]}\n")
            listing.config(state="disabled")

        def add():
            if name_v.get() and url_v.get():
                integrations.add_target(name_v.get(), url_v.get(), kind_v.get(), sev_v.get())
                name_v.set(""); url_v.set(""); refresh()

        def test():
            tg = list(integrations.targets())
            if tg:
                res = integrations.test_target(tg[-1])
                messagebox.showinfo("Integration test",
                                    f"Test to '{tg[-1]}': "
                                    + ("delivered" if res["ok"] else f"failed - {res['error']}"))

        brow = ttk.Frame(win)
        brow.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(brow, text="Add", command=add).pack(side="left")
        ttk.Button(brow, text="Test last", command=test).pack(side="left", padx=(6, 0))
        ttk.Button(brow, text="Clear all",
                   command=lambda: ([integrations.remove_target(n) for n in list(integrations.targets())], refresh())).pack(side="left", padx=(6, 0))
        refresh()

    def _show_vuln_settings(self):
        """Configure the NVD data source: API key and result cache."""
        win = tk.Toplevel(self.root)
        win.title("Vulnerability data (NVD)")
        win.configure(bg=THEME_BG)
        win.geometry("620x400")
        tk.Label(win, text="VULNERABILITY DATA SOURCE", bg=THEME_HEAD,
                 fg=THEME_ACCENT, font=(FONT_HEAD, 13), anchor="w",
                 padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        tk.Label(win, text="Service versions found on your devices are checked against "
                           "NIST's National Vulnerability Database. NVD limits "
                           "unauthenticated use to about 5 requests per 30 seconds; a "
                           "free API key raises that to roughly 50, which makes "
                           "scanning several hosts practical.",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 9), wraplength=580,
                 justify="left", anchor="w").pack(fill="x", padx=14, pady=8)

        form = ttk.Frame(win)
        form.pack(fill="x", padx=14, pady=4)
        ttk.Label(form, text="NVD API key (optional):").pack(side="left")
        key_var = tk.StringVar(value=settings.get("nvd_api_key", "") or "")
        entry = ttk.Entry(form, textvariable=key_var, width=42, show="*")
        entry.pack(side="left", padx=(6, 6))

        info = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         height=8, padx=12, pady=10, bd=0)
        info.pack(fill="both", expand=True, padx=10, pady=8)

        def refresh():
            st = cve_lookup.cache_stats()
            info.config(state="normal")
            info.delete("1.0", "end")
            info.insert("1.0",
                        f"API key: {'set' if cve_lookup.has_api_key() else 'not set'}\n"
                        f"Request spacing: "
                        f"{'~0.8s' if cve_lookup.has_api_key() else '~6.5s'} between lookups\n\n"
                        f"Cached lookups: {st['entries']} ({st['fresh']} still fresh)\n"
                        f"Cache lifetime: {cve_lookup.CACHE_TTL // 3600}h\n\n"
                        "Results are cached so repeat scans of the same devices "
                        "cost nothing. Clear the cache to force fresh lookups after "
                        "patching.\n\n"
                        "Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
            info.config(state="disabled")

        def save_key():
            cve_lookup.set_api_key(key_var.get())
            try:
                settings.update({"nvd_api_key": key_var.get()})
                settings.save()
            except Exception:
                pass
            refresh()

        row = ttk.Frame(win)
        row.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(row, text="Save key", command=save_key).pack(side="left")
        ttk.Button(row, text="Clear cache",
                   command=lambda: (cve_lookup.clear_cache(), refresh())).pack(side="left", padx=(6, 0))
        refresh()

    def _show_health(self):
        win = tk.Toplevel(self.root)
        win.title("Health / self-check")
        win.configure(bg=THEME_BG)
        win.geometry("560x420")
        tk.Label(win, text="SENSOR HEALTH", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)

        def refresh():
            try:
                import dns_log as _dns, http_log as _http
                mods = {
                    "threat_intel": (threat_intel, "status"),
                    "geo_lookup": (geo_lookup, "locate_self"),
                    "dns_log": (_dns, "count"),
                    "flow_tracker": (flow_tracker, "count"),
                    "correlation": (correlation, "stats"),
                }
                rep = health_monitor.report(
                    threat_detection=threat_detection, flow_tracker=flow_tracker,
                    dns_log=_dns, http_log=_http, events=events, modules=mods)
                lines = health_monitor.summary(rep)
            except Exception as exc:
                lines = [f"error: {exc}"]
            body.config(state="normal")
            body.delete("1.0", "end")
            body.insert("1.0", "\n".join(lines))
            body.config(state="disabled")
            win.after(2000, refresh)

        refresh()

    def _show_detection_rules(self):
        win = tk.Toplevel(self.root)
        win.title("Detection rules")
        win.configure(bg=THEME_BG)
        win.geometry("820x560")
        tk.Label(win, text="DETECTION RULES", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        cols = ("rule", "cat", "attck", "value", "state")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c, txt, w in (("rule", "RULE", 220), ("cat", "CATEGORY", 90),
                          ("attck", "ATT&CK", 150), ("value", "THRESHOLD", 120),
                          ("state", "STATE", 80)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        row_map = {}

        def load():
            tree.delete(*tree.get_children())
            row_map.clear()
            for r in detection_rules.rules():
                techs = ", ".join(t["id"] for t in r.get("techniques", []))
                val = r["value"] if r["value"] is not None else "-"
                item = tree.insert("", "end", values=(
                    r["name"], r["category"], techs or "-", val,
                    "on" if r["enabled"] else "OFF"))
                row_map[item] = r

        load()
        ctl = ttk.Frame(win)
        ctl.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Label(ctl, text="Set threshold:").pack(side="left")
        val_var = tk.StringVar()
        ttk.Entry(ctl, textvariable=val_var, width=14).pack(side="left", padx=(4, 6))

        def apply_threshold():
            sel = tree.selection()
            if not sel:
                return
            r = row_map.get(sel[0])
            if not r or not r.get("tunable"):
                messagebox.showinfo("Detection rules", "That rule has no numeric threshold.")
                return
            try:
                detection_rules.set_threshold(r["id"], float(val_var.get()))
                load()
            except Exception as exc:
                messagebox.showerror("Detection rules", str(exc))

        def toggle():
            sel = tree.selection()
            if not sel:
                return
            r = row_map.get(sel[0])
            if r:
                detection_rules.set_enabled(r["category"], not r["enabled"])
                load()

        ttk.Button(ctl, text="Apply", command=apply_threshold).pack(side="left")
        ttk.Button(ctl, text="Enable / disable selected",
                   command=toggle).pack(side="left", padx=(10, 0))
        tk.Label(win, text="Disabling a rule suppresses that category at the source. "
                           "Thresholds take effect on the next packet.",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 8)).pack(pady=(0, 8))

    def _show_attack_coverage(self):
        import mitre_attack
        win = tk.Toplevel(self.root)
        win.title("ATT&CK coverage")
        win.configure(bg=THEME_BG)
        win.geometry("620x520")
        tk.Label(win, text="MITRE ATT&CK COVERAGE", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        lines = ["Techniques SentinelFusion's sensors can observe, by tactic:", ""]
        for row in mitre_attack.coverage():
            lines.append(row["tactic"].upper())
            for t in row["techniques"]:
                lines.append(f"   {t['id']:11} {t['name']}")
            lines.append("")
        body.insert("1.0", "\n".join(lines))
        body.config(state="disabled")

    def _export_config(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile="sentinelfusion_config.json",
            filetypes=[("Config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            config_io.export_to_file(path, settings=settings,
                                     detection_rules=detection_rules,
                                     allowlist=allowlist,
                                     integrations=integrations)
            messagebox.showinfo("Export config", f"Configuration written to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export config", str(exc))

    def _import_config(self):
        path = filedialog.askopenfilename(
            filetypes=[("Config", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            result = config_io.import_from_file(path, settings=settings,
                                                detection_rules=detection_rules,
                                                allowlist=allowlist,
                                                integrations=integrations)
            messagebox.showinfo("Import config", "Applied:\n" + "\n".join(result))
        except Exception as exc:
            messagebox.showerror("Import config", str(exc))

    def _build_settings_tab(self):
        wrap = self._scrollable(self.settings_tab)

        ttk.Label(wrap, text="Settings", font=(FONT_HEAD, 13)).pack(anchor="w")
        ttk.Label(wrap, text="Saved to disk and applied live - no restart needed. "
                             "Detection thresholds take effect on the next packet.").pack(anchor="w", pady=(0, 12))

        # Operations console: health, detection tuning, portable config.
        ops = ttk.LabelFrame(wrap, text="Operations")
        ops.pack(fill="x", pady=6)
        orow = ttk.Frame(ops)
        orow.pack(fill="x", padx=8, pady=(8, 2))
        ttk.Button(orow, text="Health / self-check",
                   command=self._show_health).pack(side="left")
        ttk.Button(orow, text="Detection rules",
                   command=self._show_detection_rules).pack(side="left", padx=(6, 0))
        ttk.Button(orow, text="ATT&CK coverage",
                   command=self._show_attack_coverage).pack(side="left", padx=(6, 0))
        ttk.Button(orow, text="Export config",
                   command=self._export_config).pack(side="left", padx=(16, 0))
        ttk.Button(orow, text="Import config",
                   command=self._import_config).pack(side="left", padx=(6, 0))

        # Analyst tools: proactive hunting, ML outliers, tuning feedback.
        arow = ttk.Frame(ops)
        arow.pack(fill="x", padx=8, pady=2)
        ttk.Button(arow, text="Threat-hunting playbooks",
                   command=self._show_hunt_playbooks).pack(side="left")
        ttk.Button(arow, text="ML anomalies",
                   command=self._show_ml_anomalies).pack(side="left", padx=(6, 0))
        ttk.Button(arow, text="Detection feedback",
                   command=self._show_feedback).pack(side="left", padx=(6, 0))

        # External reach: log ingestion + outbound integrations.
        lrow = ttk.Frame(ops)
        lrow.pack(fill="x", padx=8, pady=(2, 8))
        ttk.Button(lrow, text="Log sources",
                   command=self._show_log_sources).pack(side="left")
        ttk.Button(lrow, text="Integrations (webhooks)",
                   command=self._show_integrations).pack(side="left", padx=(6, 0))
        ttk.Button(lrow, text="Vulnerability data (NVD)",
                   command=self._show_vuln_settings).pack(side="left", padx=(6, 0))
        ttk.Button(arow, text="Allowlist",
                   command=self._show_allowlist).pack(side="left", padx=(6, 0))
        ttk.Button(arow, text="Asset inventory",
                   command=self._show_inventory).pack(side="left", padx=(6, 0))

        # Capture interface picker (changing it restarts the sniffer).
        ifr = ttk.LabelFrame(wrap, text="Capture interface")
        ifr.pack(fill="x", pady=6)
        irow = ttk.Frame(ifr)
        irow.pack(fill="x", padx=8, pady=8)
        self._iface_map = {"Automatic (scapy default)": ""}
        displays = ["Automatic (scapy default)"]
        try:
            for it in threat_detection.list_interfaces():
                label = it["name"]
                if it.get("ip"):
                    label += f"  ({it['ip']})"
                if label in self._iface_map:            # avoid display collisions
                    label += f"  [{it['id'][-8:]}]"
                self._iface_map[label] = it["id"]
                displays.append(label)
        except Exception:
            pass
        cur = settings.get("capture_iface", "")
        cur_disp = next((d for d, i in self._iface_map.items() if i == cur),
                        "Automatic (scapy default)")
        self._iface_var = tk.StringVar(value=cur_disp)
        ttk.Combobox(irow, textvariable=self._iface_var, values=displays,
                     state="readonly", width=46).pack(side="left")
        ttk.Button(irow, text="Apply & restart capture",
                   command=self._apply_iface).pack(side="right")
        self.iface_status = ttk.Label(
            ifr, text="Pick the adapter to sniff on, then apply. "
                      "'Automatic' lets scapy choose the primary interface.")
        self.iface_status.pack(fill="x", padx=8, pady=(0, 8))

        # WiGLE token (shares its variable with the WiFi tab, so they stay in sync).
        tok = ttk.LabelFrame(wrap, text="WiGLE API")
        tok.pack(fill="x", pady=6)
        trow = ttk.Frame(tok)
        trow.pack(fill="x", padx=8, pady=8)
        ttk.Label(trow, text="Token (\"Encode for use\"):").pack(side="left")
        ttk.Entry(trow, textvariable=self.wigle_var, width=46, show="*").pack(side="left", padx=(6, 0))

        # Detection thresholds.
        det = ttk.LabelFrame(wrap, text="Detection thresholds")
        det.pack(fill="x", pady=6)
        grid = ttk.Frame(det)
        grid.pack(fill="x", padx=8, pady=8)
        self._set_vars = {}
        fields = [
            ("port_scan_threshold", "Port scan - distinct ports probed on one host"),
            ("ping_sweep_hosts", "Ping sweep - distinct hosts pinged by one source"),
            ("syn_flood_count", "SYN flood - half-open SYNs to one target:port"),
            ("exfil_mb", "Exfiltration - outbound MB to a single endpoint"),
            ("beacon_min_intervals", "Beaconing - evenly-timed callouts required"),
            ("intel_refresh_hours", "Threat-intel feed refresh (hours)"),
        ]
        snap = settings.snapshot()
        for r, (key, desc) in enumerate(fields):
            ttk.Label(grid, text=desc).grid(row=r, column=0, sticky="w", padx=(0, 12), pady=3)
            var = tk.StringVar(value=str(snap.get(key, "")))
            self._set_vars[key] = var
            ttk.Entry(grid, textvariable=var, width=10).grid(row=r, column=1, sticky="w", pady=3)
        grid.columnconfigure(0, weight=1)

        # Offline GeoIP / ASN databases (MaxMind GeoLite2).
        geo = ttk.LabelFrame(wrap, text="Offline GeoIP + ASN (MaxMind GeoLite2)")
        geo.pack(fill="x", pady=6)
        grow = ttk.Frame(geo)
        grow.pack(fill="x", padx=8, pady=8)
        ttk.Label(grow, text="Folder with .mmdb files:").pack(side="left")
        self._geoip_dir_var = tk.StringVar(value=str(snap.get("geoip_dir", "")))
        ttk.Entry(grow, textvariable=self._geoip_dir_var, width=40).pack(side="left", padx=(6, 6))
        ttk.Button(grow, text="Browse", command=self._browse_geoip_dir).pack(side="left")
        ttk.Button(grow, text="Reload databases", command=self._reload_geoip).pack(side="left", padx=(6, 0))
        self.geoip_status = tk.Label(geo, text="", fg=THEME_MUTED, font=("Consolas", 8),
                                     anchor="w", justify="left", padx=8, pady=2)
        self.geoip_status.pack(fill="x", pady=(0, 8))
        self._update_geoip_status()

        # JA3 threat-fingerprint blocklist.
        ja = ttk.LabelFrame(wrap, text="Malicious TLS fingerprints (JA3 blocklist)")
        ja.pack(fill="x", pady=6)
        jrow = ttk.Frame(ja)
        jrow.pack(fill="x", padx=8, pady=8)
        ttk.Label(jrow, text="Blocklist file:").pack(side="left")
        self._ja3_file_var = tk.StringVar(value=str(snap.get("ja3_file", "")))
        ttk.Entry(jrow, textvariable=self._ja3_file_var, width=38).pack(side="left", padx=(6, 6))
        ttk.Button(jrow, text="Browse", command=self._browse_ja3).pack(side="left")
        ttk.Button(jrow, text="Reload", command=self._reload_ja3).pack(side="left", padx=(6, 0))
        self.ja3_status = tk.Label(ja, text="", fg=THEME_MUTED, font=("Consolas", 8),
                                   anchor="w", justify="left", padx=8, pady=2)
        self.ja3_status.pack(fill="x", pady=(0, 8))
        self._update_ja3_status()

        # Threat-intel feed status.
        ti = ttk.LabelFrame(wrap, text="Threat-intelligence feeds")
        ti.pack(fill="x", pady=6)
        tirow = ttk.Frame(ti)
        tirow.pack(fill="x", padx=8, pady=8)
        self.intel_status = ttk.Label(tirow, text="checking feeds ...")
        self.intel_status.pack(side="left")
        ttk.Button(tirow, text="Refresh feeds now", command=self._refresh_intel).pack(side="right")
        self._update_intel_status()

        # Desktop notifications.
        notf = ttk.LabelFrame(wrap, text="Desktop notifications")
        notf.pack(fill="x", pady=6)
        self._notify_enabled_var = tk.BooleanVar(value=bool(settings.get("notify_enabled", 1)))
        self._notify_warn_var = tk.BooleanVar(value=bool(settings.get("notify_warnings", 0)))
        ttk.Checkbutton(notf, text="Pop a toast in the corner when a serious alert fires",
                        variable=self._notify_enabled_var,
                        command=self._apply_notify).pack(anchor="w", padx=8, pady=(8, 0))
        ttk.Checkbutton(notf, text="Include warnings too (not just alerts)",
                        variable=self._notify_warn_var,
                        command=self._apply_notify).pack(anchor="w", padx=8, pady=(0, 8))

        # Privacy / Tor routing for outbound OSINT lookups.
        prx = ttk.LabelFrame(wrap, text="Privacy - route OSINT lookups through a proxy chain")
        prx.pack(fill="x", pady=6)
        self._proxy_enabled_var = tk.BooleanVar(value=bool(int(snap.get("proxy_enabled", 0))))
        ttk.Checkbutton(prx, text="Route threat-intel, IP reputation and WiGLE through the proxy chain "
                                  "(your own location lookup stays direct)",
                        variable=self._proxy_enabled_var).pack(anchor="w", padx=8, pady=(8, 2))
        prow = ttk.Frame(prx)
        prow.pack(fill="x", padx=8, pady=(0, 4))
        ttk.Label(prow, text="Chain:").pack(side="left")
        self._proxy_url_var = tk.StringVar(value=str(snap.get("proxy_url", "")))
        ttk.Entry(prow, textvariable=self._proxy_url_var, width=44).pack(side="left", padx=(6, 8))
        ttk.Button(prow, text="Detect Tor", command=self._detect_tor).pack(side="left")
        ttk.Button(prow, text="Test exit IP", command=self._test_exit_ip).pack(side="left", padx=(6, 0))
        ttk.Button(prow, text="Show routing", command=self._show_proxy_routing).pack(side="left", padx=(6, 0))
        self.proxy_status = tk.Label(prx, text="One hop or several, comma-separated:  "
                                              "socks5://127.0.0.1:9050, socks5://10.0.0.2:1080  "
                                              "(SOCKS needs:  pip install pysocks)",
                                     fg=THEME_MUTED, font=("Consolas", 8), anchor="w",
                                     justify="left", padx=8, pady=2)
        self.proxy_status.pack(fill="x", pady=(0, 8))

        btns = ttk.Frame(wrap)
        btns.pack(fill="x", pady=(10, 4))
        ttk.Button(btns, text="Save & apply", command=self._save_settings).pack(side="left")
        ttk.Button(btns, text="Reset to defaults", command=self._reset_settings).pack(side="left", padx=8)

        self.settings_status = tk.Label(wrap, text=f"config file: {settings.path()}",
                                        fg=THEME_MUTED, font=("Consolas", 8), anchor="w", justify="left")
        self.settings_status.pack(anchor="w", pady=(8, 0))

    def _update_geoip_status(self):
        st = geoip_local.status()
        if not st["lib"]:
            txt = ("geoip2 library not installed - using online lookups.  "
                   "Install with:  pip install geoip2")
        elif not st["available"]:
            txt = ("geoip2 ready, but no .mmdb databases found.  Drop "
                   "GeoLite2-City.mmdb / GeoLite2-ASN.mmdb beside the app or set the folder above.")
        else:
            city = "City \u2713" if st["city"] else "City \u2717"
            asn = "ASN \u2713" if st["asn"] else "ASN \u2717"
            txt = f"offline databases active:  {city}   {asn}   (online lookups now bypassed)"
        self.geoip_status.config(text=txt)

    def _browse_geoip_dir(self):
        d = filedialog.askdirectory(title="Select folder containing GeoLite2 .mmdb files")
        if d:
            self._geoip_dir_var.set(d)
            self._reload_geoip()

    def _reload_geoip(self):
        path = self._geoip_dir_var.get().strip()
        settings.set("geoip_dir", path)
        settings.save()
        geoip_local.configure(path)
        self._update_geoip_status()

    def _apply_notify(self):
        settings.set("notify_enabled", 1 if self._notify_enabled_var.get() else 0)
        settings.set("notify_warnings", 1 if self._notify_warn_var.get() else 0)
        settings.save()

    def _apply_iface(self):
        iface_id = self._iface_map.get(self._iface_var.get(), "")
        settings.set("capture_iface", iface_id)
        settings.save()
        self._restart_capture(iface_id)

    def _restart_capture(self, iface_id):
        self.iface_status.config(text="restarting capture ...")
        try:
            if getattr(self, "sniffer", None):
                self.sniffer.stop()
        except Exception:
            pass
        try:
            self.sniffer = threat_detection.start_async_monitor(iface=iface_id or None)
            where = self._iface_var.get() if iface_id else "default interface"
            self.iface_status.config(text=f"capturing on: {where}")
        except Exception as e:
            self.iface_status.config(
                text=f"could not start capture on that interface ({e}); "
                     "try 'Automatic' or run as Administrator.")

    def _update_intel_status(self):
        try:
            counts = threat_intel.indicator_count()
            n = sum(counts) if isinstance(counts, (tuple, list)) else int(counts)
        except Exception:
            n = 0
        if n:
            self.intel_status.config(
                text=f"{n:,} known-bad indicators loaded (abuse.ch, blocklist.de, Spamhaus, Tor).")
        else:
            self.intel_status.config(
                text="no indicators yet - feeds still loading, or blocked (check your connection).")

    def _refresh_intel(self):
        self.intel_status.config(text="refreshing feeds ...")

        def work():
            try:
                threat_intel.refresh(force=True)
            except Exception:
                pass
            self.root.after(0, self._update_intel_status)

        threading.Thread(target=work, daemon=True).start()

    def _update_ja3_status(self):
        st = ja3_intel.status()
        if st["count"]:
            txt = f"{st['count']} JA3 fingerprints loaded from {os.path.basename(st['source'])}."
        else:
            txt = ("no JA3 blocklist loaded - drop ja3_fingerprints.txt / .csv beside the app, "
                   "or set a file above (abuse.ch SSLBL's JA3 export works).")
        self.ja3_status.config(text=txt)

    def _browse_ja3(self):
        f = filedialog.askopenfilename(
            title="Select a JA3 blocklist file",
            filetypes=[("JA3 lists", "*.txt *.csv"), ("All files", "*.*")])
        if f:
            self._ja3_file_var.set(f)
            self._reload_ja3()

    def _reload_ja3(self):
        path = self._ja3_file_var.get().strip()
        settings.set("ja3_file", path)
        settings.save()
        ja3_intel.configure(path)
        self._update_ja3_status()

    def _apply_proxy_from_form(self):
        chain = self._proxy_chain_hops()
        net_proxy.configure(bool(self._proxy_enabled_var.get()), chain or None)

    def _proxy_chain_hops(self):
        """Split the proxy field into an ordered list of hop strings.

        Accepts commas, newlines or ' -> ' between hops, so a chain can be typed
        as 'socks5://127.0.0.1:9050, socks5://10.0.0.2:1080'.
        """
        raw = self._proxy_url_var.get().strip()
        if not raw:
            return []
        raw = raw.replace("->", ",").replace("\n", ",")
        return [h.strip() for h in raw.split(",") if h.strip()]

    def _detect_tor(self):
        hops = net_proxy.hop_status()
        socks = net_proxy.socks_supported()
        if not hops:
            self.proxy_status.config(text="No hops configured. Enter one or more, comma-separated.")
            return
        up = sum(1 for h in hops if h["up"])
        parts = [f"{h['name']} {'UP' if h['up'] else 'DOWN'}" for h in hops]
        chain_desc = "  ->  ".join(parts)
        extra = ""
        if not socks and any(h["scheme"].startswith("socks") for h in hops):
            extra = "   (SOCKS hop needs: pip install pysocks)"
        self.proxy_status.config(
            text=f"{len(hops)} hop(s), {up} reachable:  {chain_desc}{extra}")

    def _test_exit_ip(self):
        self._apply_proxy_from_form()
        self.proxy_status.config(text="testing exit IP ...")

        def work():
            ip = net_proxy.check_exit_ip()
            via = "via proxy" if net_proxy.active() else "direct (proxy off or unusable)"
            txt = f"exit IP seen by services: {ip}   ({via})" if ip \
                else "could not reach the IP-check service (proxy misconfigured or offline?)"
            self.root.after(0, lambda: self.proxy_status.config(text=txt))

        threading.Thread(target=work, daemon=True).start()

    def _show_proxy_routing(self):
        """A visual of how OSINT traffic is routed through the proxy chain."""
        self._apply_proxy_from_form()
        win = tk.Toplevel(self.root)
        win.title("Proxy routing")
        win.configure(bg=THEME_BG)
        win.geometry("820x460")
        tk.Label(win, text="OSINT TRAFFIC ROUTING", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_ACCENT, height=2).pack(fill="x")
        canvas = tk.Canvas(win, bg=THEME_BG, highlightthickness=0, height=300)
        canvas.pack(fill="both", expand=True, padx=10, pady=10)
        status = tk.Label(win, text="checking hops...", bg=THEME_PANEL, fg=THEME_FG,
                          font=("Consolas", 9), anchor="w", justify="left", padx=12, pady=8)
        status.pack(fill="x", padx=10, pady=(0, 10))

        def draw(hop_states, exit_ip=None):
            canvas.delete("all")
            w = canvas.winfo_width() or 800
            enabled = net_proxy.enabled() and hop_states
            # Build the node list: You -> hops -> OSINT services
            nodes = [("You", THEME_ACCENT, True)]
            if enabled:
                for h in hop_states:
                    col = THEME_GLOW if h["up"] else THEME_RED
                    nodes.append((h["name"], col, h["up"]))
            else:
                nodes.append(("(direct - no proxy)", THEME_AMBER, True))
            nodes.append(("OSINT / intel\nservices", THEME_GOLD, True))

            n = len(nodes)
            gap = (w - 120) / max(1, n - 1)
            y = 120
            coords = []
            for i, (label, color, up) in enumerate(nodes):
                x = 60 + i * gap
                coords.append((x, y, color, up))
            # links
            for i in range(len(coords) - 1):
                x1, y1, _, up1 = coords[i]
                x2, y2, c2, up2 = coords[i + 1]
                link = THEME_GLOW if (up1 and up2 and enabled) else THEME_BORDER
                canvas.create_line(x1 + 26, y1, x2 - 26, y2, fill=link, width=2,
                                   arrow="last", arrowshape=(10, 12, 5))
                if enabled and i < len(coords) - 2:
                    canvas.create_text((x1 + x2) / 2, y1 - 16, text="encrypted",
                                       fill=THEME_MUTED, font=("Consolas", 7))
            # nodes
            for i, (x, y, color, up) in enumerate(coords):
                label = nodes[i][0]
                r = 26
                canvas.create_oval(x - r, y - r, x + r, y + r, outline=color, width=2,
                                   fill=THEME_PANEL)
                if i == 0:
                    canvas.create_text(x, y, text="PC", fill=color, font=(FONT_HEAD, 11))
                elif i == len(coords) - 1:
                    canvas.create_text(x, y, text="WWW", fill=color, font=(FONT_HEAD, 9))
                else:
                    canvas.create_text(x, y, text=f"{i}", fill=color, font=(FONT_HEAD, 13))
                canvas.create_text(x, y + r + 18, text=label, fill=THEME_FG,
                                   font=("Consolas", 8), width=110, justify="center")
                if enabled and 0 < i < len(coords) - 1:
                    dot = "\u25cf UP" if up else "\u2715 DOWN"
                    canvas.create_text(x, y + r + 40, text=dot,
                                       fill=THEME_GLOW if up else THEME_RED,
                                       font=("Consolas", 8))
            # caption
            if not net_proxy.enabled():
                msg = "Routing is OFF - OSINT lookups go directly from your machine."
            elif not net_proxy.active():
                msg = ("Chain set but not usable (a SOCKS hop needs PySocks, or a hop is "
                       "unreachable). Traffic would fall back - check the hops.")
            else:
                hops = len(hop_states)
                where = f"{hops} hop{'s' if hops != 1 else ''}"
                msg = f"OSINT lookups exit through {where}."
                if exit_ip:
                    msg += f"  Services see: {exit_ip}"
            status.config(text=msg)

        def probe():
            states = net_proxy.hop_status()
            self.root.after(0, lambda: draw(states))
            ip = net_proxy.check_exit_ip() if net_proxy.active() else None
            self.root.after(0, lambda: draw(states, ip))

        canvas.after(120, lambda: threading.Thread(target=probe, daemon=True).start())
        tk.Button(win, text="Re-check", command=lambda: threading.Thread(
            target=probe, daemon=True).start(), bg=THEME_PANEL, fg=THEME_FG, bd=0).pack(pady=(0, 8))

    def _settings_fields_from_form(self):
        out = {}
        for key, var in self._set_vars.items():
            raw = var.get().strip()
            try:
                out[key] = int(raw)
            except ValueError:
                pass  # leave invalid entries to keep their current stored value
        return out

    def _refresh_settings_fields(self):
        snap = settings.snapshot()
        for key, var in self._set_vars.items():
            var.set(str(snap.get(key, "")))

    def _save_settings(self):
        settings.set("wigle_token", self.wigle_var.get().strip())
        settings.set("geoip_dir", self._geoip_dir_var.get().strip())
        settings.set("ja3_file", self._ja3_file_var.get().strip())
        settings.set("proxy_enabled", 1 if self._proxy_enabled_var.get() else 0)
        settings.set("proxy_url", self._proxy_url_var.get().strip())
        settings.update(self._settings_fields_from_form())
        ok = settings.save()
        self._apply_settings()
        self._refresh_settings_fields()   # show any clamping that occurred
        self._update_geoip_status()
        self._update_ja3_status()
        self.settings_status.config(
            text=("saved + applied   " if ok else "applied (could not write file)   ")
                 + f"config file: {settings.path()}")

    def _reset_settings(self):
        settings.reset()
        self.wigle_var.set(settings.get("wigle_token", ""))
        self._geoip_dir_var.set(settings.get("geoip_dir", ""))
        self._ja3_file_var.set(settings.get("ja3_file", ""))
        self._proxy_enabled_var.set(bool(int(settings.get("proxy_enabled", 0))))
        self._proxy_url_var.set(settings.get("proxy_url", ""))
        self._refresh_settings_fields()
        self._apply_settings()
        self._update_geoip_status()
        self._update_ja3_status()
        self.settings_status.config(text=f"reset to defaults   config file: {settings.path()}")

    def _allow_destination(self, ip, category):
        """Allowlist one destination for one detection category, from an alert."""
        hostname = ""
        try:
            hostname = threat_detection.host_for(ip) or ""
        except Exception:
            pass
        note = f"allowed from alert{(' - ' + hostname) if hostname else ''}"
        allowlist.add("ip", ip, categories=[category], note=note)
        events.log_event("INFO", "system", "allowlist",
                         f"{ip} allowlisted for '{category}' alerts")
        try:
            self.set_status(f"{ip} will no longer raise '{category}' alerts")
        except Exception:
            pass

    def _show_allowlist(self):
        """Manage known-good destinations."""
        win = tk.Toplevel(self.root)
        win.title("Allowlist")
        win.configure(bg=THEME_BG)
        win.geometry("780x540")
        tk.Label(win, text="ALLOWLIST  -  known-good destinations", bg=THEME_HEAD,
                 fg=THEME_ACCENT, font=(FONT_HEAD, 13), anchor="w",
                 padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        tk.Label(win, text="Stops a destination you've already judged benign from "
                           "raising the same finding forever. Suppression is scoped to "
                           "the categories you name - allowing a backup host for 'exfil' "
                           "won't hide beaconing to it. Threat-intel hits, cleartext "
                           "credentials, CVEs and certificate problems are never "
                           "suppressed, whatever you add here.",
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 9), wraplength=740,
                 justify="left", anchor="w").pack(fill="x", padx=14, pady=8)

        cols = ("kind", "value", "cats", "hits", "note")
        tree = ttk.Treeview(win, columns=cols, show="headings", height=10)
        for c, txt, w in (("kind", "KIND", 70), ("value", "VALUE", 190),
                          ("cats", "CATEGORIES", 160), ("hits", "SUPPRESSED", 90),
                          ("note", "NOTE", 220)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        form = ttk.Frame(win)
        form.pack(fill="x", padx=10, pady=(0, 4))
        kind_v = tk.StringVar(value="ip")
        val_v = tk.StringVar()
        cat_v = tk.StringVar()
        ttk.Combobox(form, textvariable=kind_v, width=8, state="readonly",
                     values=allowlist.KINDS).pack(side="left")
        ttk.Entry(form, textvariable=val_v, width=24).pack(side="left", padx=4)
        ttk.Label(form, text="categories (blank = all):").pack(side="left", padx=(6, 2))
        ttk.Entry(form, textvariable=cat_v, width=22).pack(side="left")

        def refresh():
            tree.delete(*tree.get_children())
            for r in allowlist.rules():
                cats = ", ".join(r.get("categories") or []) or "all"
                tree.insert("", "end", values=(r["kind"], r["value"], cats,
                                               r.get("hits", 0), r.get("note", "")))

        def add_entry():
            ok, msg = allowlist.validate(kind_v.get(), val_v.get())
            if not ok:
                messagebox.showwarning("Allowlist", msg)
                return
            cats = [c.strip() for c in cat_v.get().split(",") if c.strip()]
            allowlist.add(kind_v.get(), val_v.get(), categories=cats)
            val_v.set(""); cat_v.set("")
            refresh()

        def remove_entry():
            sel = tree.selection()
            if not sel:
                return
            idx = tree.index(sel[0])
            allowlist.remove(idx)
            refresh()

        row = ttk.Frame(win)
        row.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(row, text="Add", command=add_entry).pack(side="left")
        ttk.Button(row, text="Remove selected", command=remove_entry).pack(side="left", padx=(6, 0))
        ttk.Button(row, text="Refresh", command=refresh).pack(side="left", padx=(6, 0))
        tk.Label(row, text="Never suppressed: " + ", ".join(sorted(allowlist.NEVER_SUPPRESS)),
                 bg=THEME_BG, fg=THEME_MUTED, font=(FONT_UI, 8)).pack(side="right")
        refresh()

    def _show_inventory(self):
        """The asset inventory: what every host on the network actually is."""
        win = tk.Toplevel(self.root)
        win.title("Asset inventory")
        win.configure(bg=THEME_BG)
        win.geometry("900x560")
        tk.Label(win, text="ASSET INVENTORY", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        summary = tk.Label(win, text="", bg=THEME_BG, fg=THEME_MUTED,
                           font=(FONT_UI, 9), anchor="w", padx=14, pady=6)
        summary.pack(fill="x")

        cols = ("ip", "identity", "os_src", "services", "cves", "certs")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c, txt, w in (("ip", "IP", 120), ("identity", "IDENTIFIED AS", 250),
                          ("os_src", "EVIDENCE", 110), ("services", "SERVICES", 80),
                          ("cves", "CVEs", 70), ("certs", "TLS ISSUES", 90)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.tag_configure("risk", foreground=THEME_AMBER)
        tree.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        detail = scrolledtext.ScrolledText(win, height=10, bg=THEME_PANEL,
                                           fg=THEME_FG, font=(FONT_DATA, 10),
                                           wrap="word", padx=12, pady=10, bd=0)
        detail.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        rows = {}

        def refresh():
            tree.delete(*tree.get_children())
            rows.clear()
            for rec in sorted(asset_registry.assets(),
                              key=lambda r: _ip_sort_key(r["ip"])):
                risk = asset_registry.risk_summary(rec["ip"]) or {}
                tag = "risk" if (risk.get("cves") or risk.get("cert_issues")) else ""
                item = tree.insert("", "end", values=(
                    rec["ip"],
                    asset_registry.describe(rec["ip"]) or "-",
                    rec["os"].get("source") or "-",
                    len(rec.get("services") or {}),
                    risk.get("cves", 0) or "-",
                    risk.get("cert_issues", 0) or "-"), tags=(tag,))
                rows[item] = rec["ip"]
            st = asset_registry.stats()
            summary.config(text=f"{st['assets']} asset(s), {st['identified']} "
                                f"identified, {st['with_vulnerabilities']} with "
                                "vulnerability data")

        def on_select(_e):
            sel = tree.selection()
            if not sel:
                return
            ip = rows.get(sel[0])
            detail.config(state="normal")
            detail.delete("1.0", "end")
            detail.insert("1.0", "\n".join(asset_registry.summarize(ip)))
            detail.config(state="disabled")

        tree.bind("<<TreeviewSelect>>", on_select)
        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bar, text="Refresh", command=refresh).pack(side="left")
        ttk.Button(bar, text="Enrich selected",
                   command=lambda: self._enrich_ip(rows.get(
                       tree.selection()[0])) if tree.selection() else None
                   ).pack(side="left", padx=(6, 0))
        refresh()

    def _register_infrastructure(self):
        """Exempt the default gateway from sweep/flood detection.

        A router ARPs every address on the subnet and relays every host's
        traffic, so it trips both detectors permanently. Excluding it by
        identity is right; raising the thresholds until it goes quiet would
        also hide a real sweep or flood.
        """
        try:
            import network_discovery
            gw = network_discovery.default_gateway()
            if gw:
                anomaly_detectors.set_infrastructure([gw])
                print(f"gateway {gw} exempted from sweep/flood detection")
        except Exception as exc:
            print("could not identify gateway:", exc)

    def _apply_settings(self):
        # Push current settings into the live detector modules. Safe to call
        # before the UI exists (it only touches module-level constants).
        s = settings.snapshot()
        try:
            if s.get("wigle_token"):
                wifi_osint.set_wigle_token(s["wigle_token"])
            anomaly_detectors.PING_SWEEP_HOSTS = int(s["ping_sweep_hosts"])
            anomaly_detectors.SYN_FLOOD_COUNT = int(s["syn_flood_count"])
            scan_detector.PORT_SCAN_THRESHOLD = int(s["port_scan_threshold"])
            threat_detection.EXFIL_BYTES = int(s["exfil_mb"]) * 1024 * 1024
            threat_detection.BEACON_MIN = int(s["beacon_min_intervals"])
            threat_intel.REFRESH_HOURS = int(s["intel_refresh_hours"])
            geoip_local.configure(s.get("geoip_dir", ""))
            ja3_intel.configure(s.get("ja3_file", ""))
            _pc = s.get("proxy_url", "") or ""
            _pc = _pc.replace("->", ",").replace("\n", ",")
            net_proxy.configure(bool(int(s.get("proxy_enabled", 0))),
                                [h.strip() for h in _pc.split(",") if h.strip()] or None)
        except Exception as e:
            print("apply settings error:", e)

    def _wifi_use_my_loc(self):
        self.wifi_status.config(text="locating you...")

        def work():
            info = geo_lookup.locate_self()
            if info and info.get("lat") is not None:
                self.root.after(0, lambda: self._fill_my_loc(info))
            else:
                self.root.after(0, lambda: self.wifi_status.config(text="could not get your location"))

        threading.Thread(target=work, daemon=True).start()

    def _fill_my_loc(self, info):
        self.wifi_lat.set(f"{info['lat']:.4f}")
        self.wifi_lon.set(f"{info['lon']:.4f}")
        self.wifi_status.config(text=f"location set ({info.get('city', '?')})")

    def _wifi_search(self):
        try:
            lat = float(self.wifi_lat.get())
            lon = float(self.wifi_lon.get())
            rad = float(self.wifi_radius.get() or 1)
        except ValueError:
            self.wifi_status.config(text="enter numeric lat / lon / radius")
            return
        ssid = self.wifi_ssid.get().strip() or None
        self.wifi_search_btn.config(state="disabled")
        self.wifi_status.config(text="searching WiGLE...")

        def work():
            res = wifi_osint.wigle_search_area(lat, lon, rad, ssid)
            self.root.after(0, lambda: self._show_wifi(res))

        threading.Thread(target=work, daemon=True).start()

    def _show_wifi(self, res):
        self.wifi_search_btn.config(state="normal")
        self.wifi_tree.delete(*self.wifi_tree.get_children())
        if res.get("error"):
            self.wifi_status.config(text=res["error"])
            return
        nets = res.get("networks", [])
        for n in nets:
            lat = f"{n['lat']:.5f}" if n.get("lat") is not None else "-"
            lon = f"{n['lon']:.5f}" if n.get("lon") is not None else "-"
            self.wifi_tree.insert("", "end", values=(
                n["ssid"], n["bssid"] or "-", n["encryption"] or "-", lat, lon))
        self.wifi_status.config(text=f"{len(nets)} networks shown (total ~{res.get('total', '?')})")

    def _locate_bssid(self):
        b = self.bssid_var.get().strip()
        if not b:
            self.bssid_result.config(text="enter a BSSID (e.g. 00:11:22:33:44:55)")
            return
        self.bssid_btn.config(state="disabled")
        self.bssid_result.config(text="locating...")

        def work():
            res = wifi_osint.geolocate_bssid(b)
            self.root.after(0, lambda: self._show_bssid(res))

        threading.Thread(target=work, daemon=True).start()

    def _show_bssid(self, res):
        self.bssid_btn.config(state="normal")
        if res.get("error"):
            self.bssid_result.config(text=res["error"])
            return
        lines = []
        m = res.get("mylnikov")
        if isinstance(m, dict) and "lat" in m:
            lines.append(f"Mylnikov:  {m['lat']}, {m['lon']}  (+/- {m.get('range', '?')} m)")
        elif isinstance(m, dict) and "error" in m:
            lines.append(f"Mylnikov:  error - {m['error']}")
        else:
            lines.append("Mylnikov:  no match")
        w = res.get("wigle")
        if isinstance(w, dict) and "lat" in w:
            lines.append(f"WiGLE:     {w['lat']}, {w['lon']}  ssid={w.get('ssid')}")
        elif isinstance(w, dict) and "error" in w:
            lines.append(f"WiGLE:     error - {w['error']}")
        elif w is None:
            lines.append("WiGLE:     no match (or no token set)")
        self.bssid_result.config(text="\n".join(lines))

    def _build_connections_tab(self):
        top = ttk.Frame(self.connections_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(top, text="Live connections (double-click a row for endpoint detail)").pack(side="left")
        self.conn_filter = tk.StringVar(value="ALL")
        ttk.Combobox(top, textvariable=self.conn_filter, width=8, state="readonly",
                     values=("ALL", "TCP", "UDP")).pack(side="left", padx=(8, 0))
        self.conn_count = ttk.Label(top, text="")
        self.conn_count.pack(side="right")

        cols = ("app", "proto", "local", "remote", "state", "bytes", "age")
        self.conn_tree = ttk.Treeview(self.connections_tab, columns=cols, show="headings")
        for c, txt, w in (("app", "APPLICATION", 150), ("proto", "PROTO", 55),
                          ("local", "LOCAL", 150), ("remote", "REMOTE", 240),
                          ("state", "STATE", 105), ("bytes", "BYTES (out/in)", 150),
                          ("age", "AGE", 60)):
            self.conn_tree.heading(c, text=txt)
            self.conn_tree.column(c, width=w)
        self.conn_tree.tag_configure("flagged", foreground=THEME_RED)
        self.conn_tree.bind("<Double-1>", self._on_conn_click)
        self._bind_context(self.conn_tree, lambda item: self._conn_rows.get(item))
        self.conn_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._conn_rows = {}
        self.root.after(1500, self._refresh_connections)

    def _refresh_connections(self):
        flt = self.conn_filter.get()
        flagged = self._flagged_ips()
        self.conn_tree.delete(*self.conn_tree.get_children())
        self._conn_rows = {}
        now = time.time()
        shown = 0
        for f in threat_detection.active_flows():
            if flt != "ALL" and f["proto"] != flt:
                continue
            local = f.get("local")
            remote = f.get("remote")
            local_s = f"{local[0]}:{local[1]}" if local else f"{f['ep1'][0]}:{f['ep1'][1]}"
            if remote:
                rip = remote[0]
                host = threat_detection.host_for(rip)
                remote_s = f"{host or rip}:{remote[1]}"
            else:
                rip = f["ep2"][0]
                remote_s = f"{f['ep2'][0]}:{f['ep2'][1]}"
            age = int(now - f["first"])
            bytes_s = f"{_human_bytes(f.get('out_bytes', 0))} / {_human_bytes(f.get('in_bytes', 0))}"
            tags = ("flagged",) if rip in flagged else ()
            item = self.conn_tree.insert("", "end", values=(
                f.get("app", "") or "-", f["proto"], local_s, remote_s,
                f.get("state", ""), bytes_s, f"{age}s"), tags=tags)
            self._conn_rows[item] = rip
            shown += 1
        self.conn_count.config(text=f"{shown} connections")
        self.root.after(1500, self._refresh_connections)

    def _on_conn_click(self, _evt):
        sel = self.conn_tree.selection()
        if sel:
            ip = self._conn_rows.get(sel[0])
            if ip:
                self._open_endpoint(ip)

    def _build_alerts_tab(self):
        top = ttk.Frame(self.alerts_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.alerts_summary = ttk.Label(top, text="no alerts yet", font=(FONT_HEAD, 10))
        self.alerts_summary.pack(side="left")
        ttk.Button(top, text="Acknowledge selected", command=self._ack_selected).pack(side="right")
        ttk.Button(top, text="Acknowledge all shown", command=self._ack_all).pack(side="right", padx=6)
        self._hide_acked = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Hide acknowledged", variable=self._hide_acked,
                        command=self._force_alert_refresh).pack(side="right", padx=8)
        ttk.Button(top, text="Export JSON",
                   command=lambda: self._export_alerts("json")).pack(side="right", padx=(16, 4))
        ttk.Button(top, text="Export CSV",
                   command=lambda: self._export_alerts("csv")).pack(side="right", padx=4)

        cols = ("time", "sev", "cat", "source", "message")
        self.alerts_tree = ttk.Treeview(self.alerts_tab, columns=cols, show="headings")
        for c, txt, w in (("time", "TIME", 160), ("sev", "SEV", 80),
                          ("cat", "CATEGORY", 90), ("source", "SOURCE", 150),
                          ("message", "MESSAGE", 550)):
            self.alerts_tree.heading(c, text=txt)
            self.alerts_tree.column(c, width=w)
        self.alerts_tree.tag_configure("ALERT", foreground=THEME_RED)
        self.alerts_tree.tag_configure("WARNING", foreground=THEME_AMBER)
        self.alerts_tree.tag_configure("acked", foreground=THEME_MUTED)
        self.alerts_tree.bind("<Double-1>", self._on_alert_click)
        self.alerts_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        # One binding only: Tk keeps just the last <Button-3> handler, so the
        # feedback options and the IP actions share a single menu.
        self.alerts_tree.bind("<Button-3>", self._alert_context_menu)

        # Explanation panel: plain-English meaning of the selected alert.
        exp = ttk.Frame(self.alerts_tab)
        exp.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.alert_explain = tk.Label(
            exp, text="Select an alert to see what it means. Acknowledge rows you've triaged - "
                      "acknowledged alerts dim, drop out of the HUD count, and unflag their endpoint on the map.",
            justify="left", anchor="w", wraplength=920,
            font=("Consolas", 9), bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=8)
        self.alert_explain.pack(fill="x")

        self.alerts_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._alert_rows = {}
        self._alert_meta = {}
        self._alert_sig = None
        self.root.after(1500, self._refresh_alerts)

    def _refresh_alerts(self):
        self._render_alerts()
        self.root.after(1500, self._refresh_alerts)

    def _force_alert_refresh(self):
        self._alert_sig = None
        self._render_alerts()

    def _render_alerts(self):
        rows = [e for e in events.recent(limit=500)
                if e["severity"] in ("ALERT", "WARNING")]
        hide = self._hide_acked.get()
        n_acked = sum(1 for e in rows if events.is_acked(events.event_key(e)))
        # Rebuild only when the list, the ack state, or the filter changed - so a
        # selected explanation and scroll position otherwise survive refreshes.
        sig = (len(rows), (rows[-1]["stamp"] + rows[-1]["message"]) if rows else "",
               n_acked, hide)
        if sig == self._alert_sig:
            return
        self._alert_sig = sig
        self.alerts_tree.delete(*self.alerts_tree.get_children())
        self._alert_rows = {}
        self._alert_meta = {}
        by_cat = {}
        n_alert = n_warn = 0
        for e in rows:
            key = events.event_key(e)
            acked = events.is_acked(key)
            if e["severity"] == "ALERT":
                n_alert += 1
            else:
                n_warn += 1
            by_cat[e["category"]] = by_cat.get(e["category"], 0) + 1
            if hide and acked:
                continue
            tags = ("acked",) if acked else (e["severity"],)
            item = self.alerts_tree.insert("", "end", values=(
                ("\u2713 " if acked else "") + e["stamp"], e["severity"],
                e["category"], e["source"], e["message"]), tags=tags)
            self._alert_rows[item] = e["source"]
            self._alert_meta[item] = (e["severity"], e["category"], e["source"], e["message"], key)
        try:
            self.alerts_tree.yview_moveto(1.0)
        except Exception:
            pass
        if rows:
            cats = ", ".join(f"{k}:{v}" for k, v in
                             sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True))
            unacked = n_alert + n_warn - n_acked
            self.alerts_summary.config(
                text=f"{unacked} unacknowledged  ({n_alert} alerts / {n_warn} warnings)   [{cats}]")
        else:
            self.alerts_summary.config(text="no alerts yet")

    def _ack_selected(self):
        changed = False
        for item in self.alerts_tree.selection():
            meta = self._alert_meta.get(item)
            if meta:
                events.acknowledge(meta[4])
                changed = True
        if changed:
            self._force_alert_refresh()

    def _ack_all(self):
        changed = False
        for e in events.recent(limit=500):
            if e["severity"] in ("ALERT", "WARNING"):
                k = events.event_key(e)
                if not events.is_acked(k):
                    events.acknowledge(k)
                    changed = True
        if changed:
            self._force_alert_refresh()

    def _export_alerts(self, fmt):
        alerts = [e for e in events.recent(limit=2000)
                  if e["severity"] in ("ALERT", "WARNING")]
        if not alerts:
            self.alert_explain.config(text="No alerts to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=f"sentinel_alerts.{fmt}",
            filetypes=[(fmt.upper(), f"*.{fmt}"), ("All files", "*.*")])
        if not path:
            return
        try:
            isack = lambda e: events.is_acked(events.event_key(e))  # noqa: E731
            if fmt == "csv":
                alert_export.to_csv(alerts, path, isack)
            else:
                alert_export.to_json(alerts, path, isack)
            self.alert_explain.config(text=f"Exported {len(alerts)} alerts to  {path}")
        except Exception as e:
            self.alert_explain.config(text=f"Export failed: {e}")

    def _on_alert_select(self, _evt):
        sel = self.alerts_tree.selection()
        if not sel:
            return
        meta = self._alert_meta.get(sel[0])
        if not meta:
            return
        sev, cat, src, msg, _key = meta
        ex = events.explain(cat) or "No description available for this category."
        text = f"[{sev}]  {cat.upper()}  -  {msg}\n{ex}"
        if self._looks_like_ip(src):
            text += f"\nEndpoint {src}  -  double-click the row to open its full dossier."
        self.alert_explain.config(text=text)

    def _on_alert_click(self, _evt):
        sel = self.alerts_tree.selection()
        if sel:
            src = self._alert_rows.get(sel[0], "")
            if self._looks_like_ip(src):
                self._open_endpoint(src)

    def _alert_context_menu(self, event):
        """Right-click an alert: rate the detection, and act on its source IP.

        The feedback options appear for every alert - including ones whose source
        isn't an address - because any detection can be judged accurate or false.
        """
        row = self.alerts_tree.identify_row(event.y)
        if not row:
            return
        self.alerts_tree.selection_set(row)
        meta = self._alert_meta.get(row)
        ip = self._alert_rows.get(row, "")
        if not self._looks_like_ip(ip):
            ip = ""
        if not meta and not ip:
            return
        self._popup_context_menu(event, ip, alert_meta=meta)

    def _looks_like_ip(self, s):
        try:
            ipaddress.ip_address(str(s))
            return True
        except ValueError:
            return False

    def _open_endpoint(self, ip):
        info = geo_lookup.get(ip) or {}
        coords = geo_lookup.coords(ip)
        self._on_endpoint_select({"ip": ip, "info": info, "coords": coords, "count": 0})

    # ---------- DNS query log ----------

    def _build_dns_tab(self):
        top = ttk.Frame(self.dns_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.dns_summary = ttk.Label(top, text="no DNS traffic seen yet",
                                     font=(FONT_HEAD, 10))
        self.dns_summary.pack(side="left")
        ttk.Button(top, text="Resolution graph",
                   command=self._show_resolution_graph).pack(side="right")

        ttk.Label(top, text="filter:").pack(side="left", padx=(18, 4))
        self.dns_filter = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.dns_filter, width=26)
        ent.pack(side="left")
        self.dns_filter.trace_add("write", lambda *_: self._force_dns_refresh())
        self._dns_nx_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Failed lookups only", variable=self._dns_nx_only,
                        command=self._force_dns_refresh).pack(side="left", padx=10)
        self.dns_pause = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Pause", variable=self.dns_pause).pack(side="left")
        ttk.Button(top, text="Clear", command=self._clear_dns).pack(side="right")

        cols = ("time", "client", "query", "type", "result", "ttl")
        self.dns_tree = ttk.Treeview(self.dns_tab, columns=cols, show="headings")
        for c, txt, w in (("time", "TIME", 92), ("client", "CLIENT", 122),
                          ("query", "QUERY", 330), ("type", "TYPE", 62),
                          ("result", "RESOLVED TO", 330), ("ttl", "TTL", 62)):
            self.dns_tree.heading(c, text=txt)
            self.dns_tree.column(c, width=w)
        self.dns_tree.tag_configure("nx", foreground=THEME_AMBER)
        self.dns_tree.tag_configure("pending", foreground=THEME_MUTED)
        self.dns_tree.tag_configure("bad", foreground=THEME_RED)
        self.dns_tree.bind("<<TreeviewSelect>>", self._on_dns_select)
        self._dns_rows = {}
        self._bind_context(
            self.dns_tree,
            lambda item: (self._dns_rows.get(item, {}).get("ips") or [None])[0])

        det = ttk.Frame(self.dns_tab)
        det.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.dns_detail = tk.Label(
            det, text="Every DNS lookup on this machine, and what came back. Select a row for "
                      "detail; right-click to inspect a resolved IP. Names learned here label "
                      "endpoints elsewhere in the app.",
            justify="left", anchor="w", wraplength=940, font=("Consolas", 9),
            bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=8)
        self.dns_detail.pack(fill="x")

        self.dns_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._dns_sig = None
        self.root.after(2000, self._refresh_dns)

    def _refresh_dns(self):
        if not self.dns_pause.get():
            self._render_dns()
        self.root.after(2000, self._refresh_dns)

    def _force_dns_refresh(self):
        self._dns_sig = None
        self._render_dns()

    def _render_dns(self):
        import time as _t
        try:
            rows = dns_log.recent(limit=400, contains=self.dns_filter.get().strip() or None)
            stats = dns_log.stats()
        except Exception as exc:
            print("dns refresh error:", exc)
            return
        if self._dns_nx_only.get():
            rows = [r for r in rows if r["rcode"] and r["rcode"] != "OK"]
        sig = (len(rows), rows[-1]["ts"] if rows else 0,
               tuple(r["rcode"] for r in rows[-5:]), stats["total"])
        if sig == self._dns_sig:
            return
        self._dns_sig = sig
        self.dns_tree.delete(*self.dns_tree.get_children())
        self._dns_rows = {}
        flagged = self._flagged_ips()
        for r in rows:
            if not r["answered"]:
                result, tag = "(no reply yet)", "pending"
            elif r["ips"]:
                result = ", ".join(r["ips"][:3])
                if len(r["ips"]) > 3:
                    result += f"  +{len(r['ips']) - 3}"
                tag = "bad" if any(i in flagged for i in r["ips"]) else ""
            elif r["cnames"]:
                result, tag = f"CNAME {r['cnames'][0]}", ""
            else:
                result = r["rcode"] or "-"
                tag = "nx" if r["rcode"] and r["rcode"] != "OK" else ""
            item = self.dns_tree.insert("", "end", values=(
                _t.strftime("%H:%M:%S", _t.localtime(r["ts"])), r["client"],
                r["name"], r["type"], result, r["ttl"] or "-"),
                tags=(tag,) if tag else ())
            self._dns_rows[item] = r
        try:
            self.dns_tree.yview_moveto(1.0)
        except Exception:
            pass
        if stats["total"]:
            msg = (f"{stats['total']} lookups   -   {stats['domains']} unique domains   -   "
                   f"{stats['mapped_ips']} IPs named")
            if stats["nxdomain"]:
                msg += f"   -   {stats['nxdomain']} NXDOMAIN"
            if stats["unanswered"]:
                msg += f"   -   {stats['unanswered']} unanswered"
            self.dns_summary.config(text=msg)
        else:
            self.dns_summary.config(text="no DNS traffic seen yet")

    def _clear_dns(self):
        try:
            dns_log.clear()
        except Exception:
            pass
        self._force_dns_refresh()

    def _on_dns_select(self, _evt):
        sel = self.dns_tree.selection()
        if not sel:
            return
        r = self._dns_rows.get(sel[0])
        if not r:
            return
        lines = [f"{r['client']}  asked  {r['name']}   ({r['type']})",
                 f"Server:  {r['server']}      Status:  {r['rcode'] or 'awaiting reply'}"]
        if r["cnames"]:
            lines.append("CNAME chain:  " + "  ->  ".join(r["cnames"]))
        if r["ips"]:
            lines.append("")
            lines.append("Resolved to:")
            flagged = self._flagged_ips()
            for ip in r["ips"]:
                info = geo_lookup.get(ip) or {}
                bits = [ip]
                where = info.get("country") or ""
                if where:
                    bits.append(f"[{where}]")
                if info.get("isp"):
                    bits.append(info["isp"])
                if ip in flagged:
                    bits.append("  <-- FLAGGED")
                lines.append("   " + "  ".join(bits))
        if r["ttl"]:
            lines.append(f"TTL:  {r['ttl']}s")
        if r["rcode"] == "NXDOMAIN":
            lines.append("")
            lines.append("NXDOMAIN - this name does not exist. A burst of these is how "
                         "domain-generation-algorithm malware looks while it hunts for its server.")
        lines.append("")
        lines.append("Right-click to inspect the first resolved IP.")
        self.dns_detail.config(text="\n".join(lines))

    # ---------- HTTP transaction log ----------

    def _build_http_tab(self):
        top = ttk.Frame(self.http_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.http_summary = ttk.Label(top, text="no cleartext HTTP seen yet",
                                      font=(FONT_HEAD, 10))
        self.http_summary.pack(side="left")
        ttk.Label(top, text="filter:").pack(side="left", padx=(18, 4))
        self.http_filter = tk.StringVar()
        ttk.Entry(top, textvariable=self.http_filter, width=24).pack(side="left")
        self.http_filter.trace_add("write", lambda *_: self._force_http_refresh())
        self._http_flagged_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Flagged only", variable=self._http_flagged_only,
                        command=self._force_http_refresh).pack(side="left", padx=10)
        ttk.Button(top, text="Software inventory", command=self._show_user_agents).pack(side="right")
        ttk.Button(top, text="Clear", command=self._clear_http).pack(side="right", padx=6)

        cols = ("time", "client", "method", "url", "status", "type")
        self.http_tree = ttk.Treeview(self.http_tab, columns=cols, show="headings")
        for c, txt, w in (("time", "TIME", 90), ("client", "CLIENT", 118),
                          ("method", "METHOD", 68), ("url", "URL", 420),
                          ("status", "STATUS", 62), ("type", "CONTENT-TYPE", 150)):
            self.http_tree.heading(c, text=txt)
            self.http_tree.column(c, width=w)
        self.http_tree.tag_configure("flag", foreground=THEME_AMBER)
        self.http_tree.tag_configure("err", foreground=THEME_RED)
        self.http_tree.bind("<<TreeviewSelect>>", self._on_http_select)
        self._http_rows = {}
        self._bind_context(
            self.http_tree,
            lambda item: (self._http_rows.get(item, {}).get("server_ip")))

        det = ttk.Frame(self.http_tab)
        det.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.http_detail = tk.Label(
            det, text="Every cleartext HTTP request and response. Select a row for headers and "
                      "findings; 'Software inventory' lists the clients seen by their User-Agent.",
            justify="left", anchor="w", wraplength=940, font=("Consolas", 9),
            bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=8)
        self.http_detail.pack(fill="x")

        self.http_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._http_sig = None
        self.root.after(2000, self._refresh_http)

    def _refresh_http(self):
        self._render_http()
        self.root.after(2000, self._refresh_http)

    def _force_http_refresh(self):
        self._http_sig = None
        self._render_http()

    def _render_http(self):
        import time as _t
        try:
            rows = http_log.recent(limit=400, contains=self.http_filter.get().strip() or None,
                                   only_flagged=self._http_flagged_only.get())
            stats = http_log.stats()
        except Exception as exc:
            print("http refresh error:", exc)
            return
        sig = (len(rows), rows[-1]["ts"] if rows else 0, stats["total"], stats["flagged"])
        if sig == self._http_sig:
            return
        self._http_sig = sig
        self.http_tree.delete(*self.http_tree.get_children())
        self._http_rows = {}
        for r in rows:
            status = r.get("status") or "-"
            ctype = (r.get("resp_type") or r.get("req_type") or "").split(";")[0]
            tag = "flag" if r.get("flags") else ("err" if isinstance(status, int) and status >= 400 else "")
            item = self.http_tree.insert("", "end", values=(
                _t.strftime("%H:%M:%S", _t.localtime(r["ts"])), r.get("client", ""),
                r.get("method", ""), r.get("url", "") or r.get("host", ""),
                status, ctype), tags=(tag,) if tag else ())
            self._http_rows[item] = r
        try:
            self.http_tree.yview_moveto(1.0)
        except Exception:
            pass
        if stats["total"]:
            msg = (f"{stats['requests']} requests   -   {stats['user_agents']} clients"
                   f" ({stats['tool_agents']} tooling)")
            if stats["errors"]:
                msg += f"   -   {stats['errors']} errors"
            if stats["flagged"]:
                msg += f"   -   {stats['flagged']} flagged"
            self.http_summary.config(text=msg)
        else:
            self.http_summary.config(text="no cleartext HTTP seen yet")

    def _clear_http(self):
        try:
            http_log.clear()
        except Exception:
            pass
        self._force_http_refresh()

    def _on_http_select(self, _evt):
        sel = self.http_tree.selection()
        if not sel:
            return
        r = self._http_rows.get(sel[0])
        if not r:
            return
        lines = [f"{r.get('method', '')}  {r.get('url', '') or r.get('host', '')}"]
        lines.append(f"Client:  {r.get('client', '')}   ->   {r.get('server_ip', '')}:{r.get('port', '')}")
        if r.get("status"):
            lines.append(f"Response:  {r['status']} {r.get('reason', '')}"
                         + (f"   ({r.get('resp_type', '')})" if r.get("resp_type") else ""))
        if r.get("server"):
            lines.append(f"Server:  {r['server']}")
        if r.get("user_agent"):
            lines.append(f"User-Agent:  {r['user_agent']}")
        if r.get("referer"):
            lines.append(f"Referer:  {r['referer']}")
        if r.get("location"):
            lines.append(f"Redirects to:  {r['location']}")
        if r.get("cookie"):
            lines.append("Carries a cookie.")
        if r.get("flags"):
            lines.append("")
            for sev, message in r["flags"]:
                lines.append(f"   [{sev}]  {message}")
        lines.append("")
        lines.append("Right-click to inspect the server IP.")
        self.http_detail.config(text="\n".join(lines))

    def _show_user_agents(self):
        try:
            agents = http_log.user_agents()
            servers = http_log.servers()
        except Exception:
            agents, servers = [], []
        win = tk.Toplevel(self.root)
        win.title("Software inventory")
        win.configure(bg=THEME_BG)
        win.geometry("760x560")
        tk.Label(win, text="SOFTWARE INVENTORY  (from HTTP User-Agent / Server headers)",
                 bg=THEME_HEAD, fg=THEME_ACCENT, font=(FONT_HEAD, 12), anchor="w",
                 padx=12, pady=8).pack(fill="x")
        tk.Frame(win, bg=THEME_ACCENT, height=2).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG, font=("Consolas", 10),
                                         wrap="word", padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        out = []
        if agents:
            out.append("CLIENTS (User-Agent):\n")
            for a in agents:
                tag = "  [TOOL]" if a["tool"] else ""
                out.append(f"  {a['count']:>4}x  {a['agent']}{tag}")
                out.append(f"        seen talking to {a['hosts']} host(s)")
        else:
            out.append("No User-Agents captured yet.")
        if servers:
            out.append("\n\nSERVERS (Server header):\n")
            for s in servers:
                out.append(f"  {s['count']:>4}x  {s['server']}   ({s['hosts']} host(s))")
        body.insert("1.0", "\n".join(out))
        body.tag_configure("tool", foreground=THEME_AMBER)
        idx = "1.0"
        while True:
            pos = body.search("[TOOL]", idx, stopindex="end")
            if not pos:
                break
            body.tag_add("tool", f"{pos} linestart", f"{pos} lineend")
            idx = f"{pos}+1line"
        body.config(state="disabled")
        tk.Button(win, text="Close", command=win.destroy, bg=THEME_PANEL, fg=THEME_FG,
                  bd=0).pack(pady=(0, 10))

    # ---------- session / flow records ----------

    def _build_flows_tab(self):
        top = ttk.Frame(self.flows_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.flows_summary = ttk.Label(top, text="no flows yet",
                                       font=(FONT_HEAD, 10))
        self.flows_summary.pack(side="left")
        ttk.Label(top, text="sort:").pack(side="left", padx=(18, 4))
        self.flows_sort = tk.StringVar(value="bytes")
        sort_box = ttk.Combobox(top, textvariable=self.flows_sort, width=10, state="readonly",
                                values=("bytes", "duration", "last", "packets", "out"))
        sort_box.pack(side="left")
        sort_box.bind("<<ComboboxSelected>>", lambda _e: self._force_flows_refresh())
        self._flows_active_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Active only", variable=self._flows_active_only,
                        command=self._force_flows_refresh).pack(side="left", padx=10)
        ttk.Button(top, text="Clear", command=self._clear_flows).pack(side="right")

        cols = ("proto", "conv", "state", "dur", "out", "in", "pkts")
        self.flows_tree = ttk.Treeview(self.flows_tab, columns=cols, show="headings")
        for c, txt, w in (("proto", "PROTOCOL", 96), ("conv", "CONVERSATION", 400),
                          ("state", "STATE", 96), ("dur", "DURATION", 84),
                          ("out", "OUT", 92), ("in", "IN", 92), ("pkts", "PKTS", 70)):
            self.flows_tree.heading(c, text=txt)
            self.flows_tree.column(c, width=w)
        self.flows_tree.tag_configure("exfil", foreground=THEME_AMBER)
        self.flows_tree.tag_configure("closed", foreground=THEME_MUTED)
        self.flows_tree.tag_configure("reset", foreground=THEME_RED)
        self.flows_tree.bind("<<TreeviewSelect>>", self._on_flow_select)
        self._flow_rows = {}
        self._bind_context(
            self.flows_tree,
            lambda item: (self._flow_rows.get(item, {}).get("dst")))

        det = ttk.Frame(self.flows_tab)
        det.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.flows_detail = tk.Label(
            det, text="Each row is one conversation - who talked to whom, for how long, how much "
                      "each way, and its TCP state. A big out/in imbalance is what a data upload "
                      "looks like. Right-click to inspect the remote IP.",
            justify="left", anchor="w", wraplength=940, font=("Consolas", 9),
            bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=8)
        self.flows_detail.pack(fill="x")

        self.flows_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._flows_sig = None
        self.root.after(2000, self._refresh_flows)
        self.root.after(30000, self._expire_flows)

    def _expire_flows(self):
        try:
            flow_tracker.expire()
        except Exception:
            pass
        self.root.after(30000, self._expire_flows)

    def _refresh_flows(self):
        self._render_flows()
        self.root.after(2500, self._refresh_flows)

    def _force_flows_refresh(self):
        self._flows_sig = None
        self._render_flows()

    def _human_bytes(self, n):
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        if n < 1024 * 1024 * 1024:
            return f"{n / 1024 / 1024:.1f} MB"
        return f"{n / 1024 / 1024 / 1024:.1f} GB"

    def _render_flows(self):
        try:
            rows = flow_tracker.flows(limit=500, sort=self.flows_sort.get(),
                                      active_only=self._flows_active_only.get())
            stats = flow_tracker.stats()
        except Exception as exc:
            print("flows refresh error:", exc)
            return
        sig = (len(rows), tuple((r["bytes"], r["state"]) for r in rows[:12]),
               stats["total"], self.flows_sort.get())
        if sig == self._flows_sig:
            return
        self._flows_sig = sig
        self.flows_tree.delete(*self.flows_tree.get_children())
        self._flow_rows = {}
        for r in rows:
            remote = r["host"] or r["dst"]
            conv = f"{r['src']}:{r['sport']}  ->  {remote}:{r['dport']}"
            dur = f"{r['duration']:.0f}s" if r["duration"] < 90 else f"{r['duration'] / 60:.1f}m"
            tag = ""
            # Flag an upload-shaped flow: lots out, comparatively little in.
            if r["out_bytes"] > 50000 and r["ratio"] > 20:
                tag = "exfil"
            elif r["state"] == "reset":
                tag = "reset"
            elif r["state"] == "closed":
                tag = "closed"
            item = self.flows_tree.insert("", "end", values=(
                r["protocol"] or r["proto"], conv, r["state"], dur,
                self._human_bytes(r["out_bytes"]), self._human_bytes(r["in_bytes"]),
                r["packets"]), tags=(tag,) if tag else ())
            self._flow_rows[item] = r
        out_h = self._human_bytes(stats["out_bytes"])
        in_h = self._human_bytes(stats["in_bytes"])
        if stats["total"]:
            self.flows_summary.config(
                text=f"{stats['total']} flows ({stats['active']} active)   -   "
                     f"out {out_h} / in {in_h}")
        else:
            self.flows_summary.config(text="no flows yet")

    def _clear_flows(self):
        try:
            flow_tracker.clear()
        except Exception:
            pass
        self._force_flows_refresh()

    def _on_flow_select(self, _evt):
        sel = self.flows_tree.selection()
        if not sel:
            return
        r = self._flow_rows.get(sel[0])
        if not r:
            return
        import time as _t
        remote = r["host"] or r["dst"]
        lines = [f"{r['proto']}"
                 + (f" / {r['protocol']}" if r["protocol"] else "")
                 + f"    {r['src']}:{r['sport']}  <->  {remote}:{r['dport']}"]
        if r["host"] and r["host"] != r["dst"]:
            lines.append(f"Remote:  {r['dst']}  ({r['host']})")
        lines.append("")
        lines.append(f"Out:  {self._human_bytes(r['out_bytes'])}  in {r['out_pkts']} packets")
        lines.append(f"In:   {self._human_bytes(r['in_bytes'])}  in {r['in_pkts']} packets")
        if r["in_bytes"]:
            lines.append(f"Ratio (out/in):  {r['ratio']:.1f}")
            if r["out_bytes"] > 50000 and r["ratio"] > 20:
                lines.append("   -> heavily outbound: the shape of a data upload. "
                             "Worth knowing what this is and where it's going.")
        lines.append("")
        lines.append(f"State:     {r['state']}")
        lines.append(f"Duration:  {r['duration']:.1f}s"
                     + (f"   (idle {r['idle']:.0f}s)" if r["idle"] > 1 else ""))
        lines.append(f"Started:   {_t.strftime('%H:%M:%S', _t.localtime(r['start']))}")
        lines.append("")
        lines.append("Right-click to inspect the remote IP.")
        self.flows_detail.config(text="\n".join(lines))

    # ---------- correlated incidents ----------

    def _build_incidents_tab(self):
        top = ttk.Frame(self.incidents_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.incidents_summary = ttk.Label(
            top, text="no incidents yet", font=(FONT_HEAD, 10))
        self.incidents_summary.pack(side="left")
        ttk.Button(top, text="Acknowledge", command=self._ack_incident).pack(side="right")
        ttk.Button(top, text="Rebuild from history",
                   command=self._rebuild_incidents).pack(side="right", padx=6)

        cols = ("level", "actor", "score", "pattern", "attck", "signals", "seen")
        self.incidents_tree = ttk.Treeview(self.incidents_tab, columns=cols, show="headings")
        for c, txt, w in (("level", "LEVEL", 96), ("actor", "ACTOR", 150),
                          ("score", "SCORE", 68), ("pattern", "PATTERN", 240),
                          ("attck", "ATT&CK", 170),
                          ("signals", "SIGNALS", 170), ("seen", "LAST", 84)):
            self.incidents_tree.heading(c, text=txt)
            self.incidents_tree.column(c, width=w)
        self.incidents_tree.tag_configure("CRITICAL", foreground=THEME_RED,
                                          font=(FONT_HEAD, 10))
        self.incidents_tree.tag_configure("HIGH", foreground=THEME_RED)
        self.incidents_tree.tag_configure("MEDIUM", foreground=THEME_AMBER)
        self.incidents_tree.tag_configure("LOW", foreground=THEME_FG)
        self.incidents_tree.bind("<<TreeviewSelect>>", self._on_incident_select)
        self._incident_rows = {}
        self._bind_context(
            self.incidents_tree,
            lambda item: self._incident_rows.get(item, {}).get("actor"))

        det = ttk.Frame(self.incidents_tab)
        det.pack(side="bottom", fill="both", padx=10, pady=(0, 10))
        self.incident_detail = scrolledtext.ScrolledText(
            det, height=11, bg=THEME_PANEL, fg=THEME_FG, font=("Consolas", 9),
            wrap="word", padx=10, pady=8, bd=0)
        self.incident_detail.pack(fill="both", expand=True)
        self.incident_detail.insert(
            "1.0", "Incidents group related alerts about one actor into a single scored "
            "event, so a real attack chain (recon -> access -> C2 -> exfil) shows up as one "
            "HIGH incident instead of a dozen scattered lines. Select one to see the signals "
            "that built its score.")
        self.incident_detail.config(state="disabled")

        self.incidents_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._incidents_sig = None
        self._playbooks_fired = set()
        self._ml_reported = set()
        self._soar_enabled = True
        self.root.after(3000, self._refresh_incidents)

    def _build_cases_tab(self):
        bar = ttk.Frame(self.cases_tab)
        bar.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Label(bar, text="Filter:").pack(side="left")
        self._case_filter = tk.StringVar(value="all")
        ttk.Combobox(bar, textvariable=self._case_filter, width=14, state="readonly",
                     values=("all", "new", "investigating", "contained", "closed")
                     ).pack(side="left", padx=(4, 8))
        ttk.Button(bar, text="Refresh", command=self._refresh_cases).pack(side="left")
        ttk.Button(bar, text="Run log", command=self._show_run_log).pack(side="left", padx=(6, 0))
        self._soar_toggle = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-run playbooks", variable=self._soar_toggle,
                        command=self._toggle_soar).pack(side="right")
        self.cases_summary = ttk.Label(bar, text="")
        self.cases_summary.pack(side="right", padx=(0, 12))

        body = ttk.Frame(self.cases_tab)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        cols = ("id", "sev", "status", "actor", "title", "assignee", "updated")
        self.cases_tree = ttk.Treeview(body, columns=cols, show="headings", height=12)
        for c, txt, w in (("id", "#", 44), ("sev", "SEV", 78), ("status", "STATUS", 104),
                          ("actor", "ACTOR", 130), ("title", "TITLE", 240),
                          ("assignee", "ASSIGNEE", 90), ("updated", "UPDATED", 130)):
            self.cases_tree.heading(c, text=txt)
            self.cases_tree.column(c, width=w)
        self.cases_tree.tag_configure("CRITICAL", foreground=THEME_RED)
        self.cases_tree.tag_configure("HIGH", foreground=THEME_RED)
        self.cases_tree.tag_configure("MEDIUM", foreground=THEME_AMBER)
        self.cases_tree.tag_configure("closed", foreground=THEME_MUTED)
        self.cases_tree.bind("<<TreeviewSelect>>", self._on_case_select)
        self.cases_tree.pack(fill="both", expand=True)
        self._case_rows = {}

        ctrl = ttk.Frame(self.cases_tab)
        ctrl.pack(fill="x", padx=10)
        ttk.Label(ctrl, text="Set status:").pack(side="left")
        for st in case_manager.STATUSES:
            ttk.Button(ctrl, text=st.capitalize(),
                       command=lambda s=st: self._case_set_status(s)).pack(side="left", padx=2)
        ttk.Button(ctrl, text="Add note", command=self._case_add_note).pack(side="left", padx=(10, 0))
        ttk.Button(ctrl, text="Assign", command=self._case_assign).pack(side="left", padx=(6, 0))
        ttk.Button(ctrl, text="Enrich actor", command=self._case_enrich).pack(side="left", padx=(6, 0))
        ttk.Button(ctrl, text="Generate report", command=self._case_report).pack(side="left", padx=(6, 0))
        ttk.Button(ctrl, text="SOC metrics", command=self._show_soc_metrics).pack(side="left", padx=(6, 0))

        self.case_detail = scrolledtext.ScrolledText(
            self.cases_tab, height=14, bg=THEME_PANEL, fg=THEME_FG,
            font=(FONT_DATA, 10), wrap="word", padx=12, pady=10, bd=0)
        self.case_detail.pack(fill="both", expand=True, padx=10, pady=10)
        self.case_detail.insert("1.0", "Select a case to work it. Cases open automatically "
                                        "from incidents when auto-run playbooks is on.")
        self.case_detail.config(state="disabled")
        self._selected_case = None
        self.root.after(3500, self._refresh_cases)

    def _refresh_cases(self):
        import db_manager
        try:
            flt = self._case_filter.get()
            status = None if flt == "all" else flt
            rows = db_manager.get_cases(status=status)
            st = case_manager.stats(db=db_manager)
        except Exception as exc:
            print("cases refresh error:", exc)
            self.root.after(4000, self._refresh_cases)
            return
        self.cases_tree.delete(*self.cases_tree.get_children())
        self._case_rows = {}
        for c in rows:
            tags = (c.get("severity", ""),)
            if c.get("status") == "closed":
                tags = ("closed",)
            item = self.cases_tree.insert("", "end", values=(
                c["id"], c.get("severity", ""), c.get("status", ""),
                c.get("actor", ""), (c.get("title", "") or "")[:40],
                c.get("assignee", "") or "-", c.get("updated_at", "")), tags=tags)
            self._case_rows[item] = c["id"]
        bs = st["by_status"]
        self.cases_summary.config(
            text=f"{st['open']} open  ({bs['new']} new / {bs['investigating']} inv / "
                 f"{bs['contained']} contained)   {st['total']} total")
        self.root.after(4000, self._refresh_cases)

    def _on_case_select(self, _evt):
        sel = self.cases_tree.selection()
        if not sel:
            return
        cid = self._case_rows.get(sel[0])
        self._selected_case = cid
        self._render_case_detail(cid)

    def _render_case_detail(self, cid):
        import db_manager
        case = db_manager.get_case(cid)
        self.case_detail.config(state="normal")
        self.case_detail.delete("1.0", "end")
        if case:
            self.case_detail.insert("1.0", "\n".join(case_manager.summarize(case)))
        self.case_detail.config(state="disabled")

    def _case_set_status(self, status):
        import db_manager
        if not self._selected_case:
            return
        case_manager.set_status(self._selected_case, status, db=db_manager)
        events.log_event("INFO", "soar", "case",
                         f"Case #{self._selected_case} -> {status}")
        self._render_case_detail(self._selected_case)
        self._refresh_cases_now()

    def _case_add_note(self):
        import db_manager
        if not self._selected_case:
            return
        from tkinter import simpledialog
        text = simpledialog.askstring("Add note", "Case note:")
        if text:
            case_manager.add_note(self._selected_case, text, db=db_manager)
            self._render_case_detail(self._selected_case)

    def _case_assign(self):
        """Set the analyst who owns a case - the SOC metrics read this."""
        import db_manager
        if not self._selected_case:
            return
        from tkinter import simpledialog
        case = db_manager.get_case(self._selected_case)
        who = simpledialog.askstring(
            "Assign case", "Assign to:",
            initialvalue=(case or {}).get("assignee", "") or "")
        if who is None:
            return
        case_manager.assign(self._selected_case, who.strip(), db=db_manager)
        case_manager.add_note(self._selected_case,
                              f"Assigned to {who.strip() or 'nobody'}.",
                              db=db_manager)
        self._render_case_detail(self._selected_case)
        self._refresh_cases_now()

    def _case_enrich(self):
        import db_manager
        if not self._selected_case:
            return
        case = db_manager.get_case(self._selected_case)
        if case and case.get("actor"):
            self._enrich_ip(case["actor"])

    def _case_report(self):
        """Generate a professional PDF report for the selected case."""
        import db_manager
        if not self._selected_case:
            messagebox.showinfo("Report", "Select a case first.")
            return
        case = db_manager.get_case(self._selected_case)
        if not case:
            return
        default = f"case_{case['id']}_report.pdf"
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", initialfile=default,
            filetypes=[("PDF report", "*.pdf"), ("All files", "*.*")])
        if not path:
            return

        def work():
            try:
                import mitre_attack
                # Reconstruct techniques from the linked incident's categories.
                techs = []
                inc_id = case.get("incident_id")
                incident = None
                if inc_id:
                    for i in correlation.incidents(min_score=0, include_acked=True):
                        if str(i["id"]) == str(inc_id):
                            incident = i
                            break
                if incident:
                    techs = mitre_attack.techniques_for_incident(incident)
                notes = case_manager.notes(case)
                actions = case_manager.actions(case)
                metrics = soc_metrics.summary(db=db_manager)
                # Asset context: what this host is, if we have ever identified it.
                asset_lines = None
                try:
                    if asset_registry.get(case["actor"]):
                        asset_lines = asset_registry.summarize(case["actor"])
                except Exception:
                    pass
                enrich_lines = None
                try:
                    import geo_lookup as _geo, threat_intel as _ti, dns_log as _dns
                    prof = enrichment.profile(
                        case["actor"], geo_lookup=_geo, threat_intel=_ti,
                        threat_detection=threat_detection, dns_log=_dns,
                        flow_tracker=flow_tracker, correlation=correlation)
                    enrich_lines = enrichment.summarize(prof)
                except Exception:
                    pass
                out = report_generator.generate_case_report(
                    case, path=path, techniques=techs, metrics=metrics,
                    notes=notes, actions=actions, enrichment_lines=enrich_lines,
                    asset_lines=asset_lines)
                events.log_event("INFO", "soar", "report",
                                 f"Case #{case['id']} report generated")
                self.root.after(0, lambda: messagebox.showinfo(
                    "Report", f"Case report written to:\n{out}"))
            except Exception as exc:
                self.root.after(0, lambda e=exc: messagebox.showerror(
                    "Report", f"Could not generate report: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def _show_soc_metrics(self):
        import db_manager
        win = tk.Toplevel(self.root)
        win.title("SOC metrics")
        win.configure(bg=THEME_BG)
        win.geometry("560x420")
        tk.Label(win, text="SOC METRICS", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)

        def refresh():
            try:
                lines = soc_metrics.summary(db=db_manager)
                trend = soc_metrics.detection_trend(db=db_manager)
                lines.append("")
                lines.append("Detections per day (7d):")
                mx = max((d["count"] for d in trend["series"]), default=0) or 1
                for d in trend["series"]:
                    bar = "#" * int(20 * d["count"] / mx)
                    lines.append(f"  {d['day']}  {bar} {d['count']}")
            except Exception as exc:
                lines = [f"error: {exc}"]
            body.config(state="normal")
            body.delete("1.0", "end")
            body.insert("1.0", "\n".join(lines))
            body.config(state="disabled")

        refresh()
        tk.Button(win, text="Refresh", command=refresh, bg=THEME_BTN, fg=THEME_FG,
                  bd=0).pack(pady=(0, 8))

    def _refresh_cases_now(self):
        # Force an immediate list refresh without waiting for the timer.
        try:
            self.cases_tree.after(50, self._refresh_cases)
        except Exception:
            pass

    def _toggle_soar(self):
        self._soar_enabled = bool(self._soar_toggle.get())

    def _show_run_log(self):
        import db_manager
        win = tk.Toplevel(self.root)
        win.title("Playbook run log")
        win.configure(bg=THEME_BG)
        win.geometry("760x520")
        tk.Label(win, text="PLAYBOOK RUN LOG", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 9), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        import json
        try:
            runs = db_manager.get_playbook_runs(200)
        except Exception as exc:
            runs = []
            body.insert("end", f"error: {exc}\n")
        if not runs:
            body.insert("end", "No playbook runs yet. They fire automatically when an "
                               "incident of MEDIUM+ severity appears (with auto-run on).")
        for r in runs:
            body.insert("end", f"\n{r.get('ran_at', '')}  -  {r.get('playbook', '')}  "
                               f"(actor {r.get('actor', '')}, case {r.get('case_id') or '-'})\n")
            try:
                steps = json.loads(r.get("steps") or "[]")
            except Exception:
                steps = []
            for s in steps:
                mark = "OK " if s.get("ok") else "!! "
                body.insert("end", f"     {mark}{s.get('action')}: {s.get('result')}\n")
        body.config(state="disabled")

    def _playbook_registry(self):
        """Map playbook action names to real, investigative-only capabilities.

        Every handler gathers, records, or recommends - none execute containment.
        Each takes (incident, context) and returns a short result string.
        """
        import db_manager

        def enrich_actor(inc, ctx):
            ip = inc.get("actor", "")
            try:
                import geo_lookup as _geo, threat_intel as _ti, dns_log as _dns
                import http_log as _http, rtt_tracker as _rtt, dns_chain as _dc
                prof = enrichment.profile(
                    ip, geo_lookup=_geo, threat_intel=_ti,
                    threat_detection=threat_detection, dns_log=_dns,
                    flow_tracker=flow_tracker, http_log=_http, correlation=correlation,
                    rtt_tracker=_rtt, dns_chain=_dc)
                ctx["profile"] = prof
                risk = prof.get("risk", ("", ""))
                return f"enriched {ip}: {risk[0]}"
            except Exception as exc:
                return f"enrich failed: {exc}"

        def resolution_chain(inc, ctx):
            ip = inc.get("actor", "")
            try:
                import dns_chain, dns_log as _dns
                ch = dns_chain.chains_for_ip(ip, dns_log=_dns, flow_tracker=flow_tracker)
                if ch.get("had_dns"):
                    return f"resolved from {ch['names'][0]['name']}"
                return "no DNS lookup seen (hard-coded / IP-literal)"
            except Exception as exc:
                return f"chain failed: {exc}"

        def capture_evidence(inc, ctx):
            ip = inc.get("actor", "")
            try:
                held = threat_detection.retained_packet_count(ip)
                if not held:
                    return "no packets retained to capture"
                import os as _os
                path = _os.path.join(_os.getcwd(),
                                     f"evidence_{ip.replace('.', '_')}_{int(time.time())}.pcap")
                n = threat_detection.export_flow_pcap(ip, path)
                ctx["evidence"] = path
                return f"captured {n} packet(s) -> {_os.path.basename(path)}"
            except Exception as exc:
                return f"capture failed: {exc}"

        def add_watchlist(inc, ctx):
            ip = inc.get("actor", "")
            try:
                watchlist.add("ip", ip, note=f"auto-added by playbook ({inc.get('level')})")
                return f"added {ip} to watchlist"
            except Exception as exc:
                return f"watchlist failed: {exc}"

        def open_case(inc, ctx):
            try:
                case = case_manager.open_case(inc, db=db_manager)
                if case:
                    ctx["case_id"] = case["id"]
                    return f"opened case #{case['id']}"
                return "case not opened"
            except Exception as exc:
                return f"open_case failed: {exc}"

        def tag_stage(inc, ctx):
            stages = inc.get("stages", [])
            cid = ctx.get("case_id")
            note = f"Kill-chain stages: {' -> '.join(stages) if stages else 'none'}"
            if cid:
                try:
                    case_manager.add_note(cid, note, db=db_manager)
                except Exception:
                    pass
            return note

        def recommend_actions(inc, ctx):
            recs = case_manager.recommend_actions(inc)
            cid = ctx.get("case_id")
            if cid:
                try:
                    case_manager.set_actions(cid, recs, db=db_manager)
                except Exception:
                    pass
            return f"{len(recs)} recommended action(s) attached"

        def hunt_similar(inc, ctx):
            # Look for the same detector categories from other actors in history.
            try:
                cats = list((inc.get("categories") or {}).keys())
                if not cats:
                    return "no categories to hunt"
                hits = db_manager.search_events(category=cats[0], limit=500)
                others = {h.get("source") for h in hits if h.get("source") != inc.get("actor")}
                return f"{len(others)} other host(s) show '{cats[0]}' activity"
            except Exception as exc:
                return f"hunt failed: {exc}"

        def escalate_note(inc, ctx):
            cid = ctx.get("case_id")
            msg = (f"ESCALATION SUGGESTED: {inc.get('level')} incident from "
                   f"{inc.get('actor')} reached "
                   f"{(inc.get('stages') or ['?'])[-1]} stage.")
            if cid:
                try:
                    case_manager.add_note(cid, msg, db=db_manager)
                except Exception:
                    pass
            return msg

        return {
            "enrich_actor": enrich_actor,
            "resolution_chain": resolution_chain,
            "capture_evidence": capture_evidence,
            "add_watchlist": add_watchlist,
            "open_case": open_case,
            "tag_stage": tag_stage,
            "recommend_actions": recommend_actions,
            "hunt_similar": hunt_similar,
            "escalate_note": escalate_note,
        }

    def _auto_run_playbooks(self, incidents):
        """Fire playbooks once for incidents that newly crossed the threshold."""
        if not getattr(self, "_soar_enabled", True):
            return
        import db_manager
        registry = self._playbook_registry()
        for inc in incidents:
            key = (inc["id"], inc["score"])
            if key in self._playbooks_fired:
                continue
            # only auto-run for incidents worth attention
            if inc.get("level") not in ("MEDIUM", "HIGH", "CRITICAL"):
                continue
            self._playbooks_fired.add(key)
            try:
                records = playbook_engine.run_for_incident(
                    inc, registry=registry, db=db_manager)
                for rec in records:
                    events.log_event("INFO", "system", "soar",
                                     f"Playbook '{rec['playbook']}' ran for "
                                     f"{rec['actor']} ({len(rec['steps'])} steps)")
            except Exception as exc:
                print("playbook auto-run error:", exc)
            # Notify any configured external integrations (severity-gated).
            try:
                if integrations.targets():
                    import mitre_attack
                    techs = mitre_attack.techniques_for_incident(inc)
                    case = db_manager.case_for_incident(inc["id"])
                    integrations.notify_incident(
                        inc, techniques=techs,
                        case_id=case["id"] if case else None)
            except Exception as exc:
                print("integration notify error:", exc)

    def _refresh_incidents(self):
        self._render_incidents()
        self.root.after(3000, self._refresh_incidents)

    def _render_incidents(self):
        import time as _t
        try:
            incs = correlation.incidents(min_score=1.0)
            stats = correlation.stats()
        except Exception as exc:
            print("incidents refresh error:", exc)
            return
        sig = tuple((i["actor"], i["score"], i["event_count"]) for i in incs[:20])
        if sig == self._incidents_sig:
            return
        self._incidents_sig = sig
        self._auto_run_playbooks(incs)
        self.incidents_tree.delete(*self.incidents_tree.get_children())
        self._incident_rows = {}
        for i in incs:
            signals = ", ".join(f"{c}x{n}" if n > 1 else c
                                for c, n in sorted(i["categories"].items(),
                                                   key=lambda kv: -kv[1]))
            try:
                import mitre_attack as _mit
                attck = _mit.summary_line(i).replace("ATT&CK: ", "")
            except Exception:
                attck = "-"
            item = self.incidents_tree.insert("", "end", values=(
                i["level"], i["actor"], i["score"], i["pattern"] or "-",
                attck[:34],
                signals[:34], _t.strftime("%H:%M:%S", _t.localtime(i["last"]))),
                tags=(i["level"],))
            self._incident_rows[item] = i
        lv = stats["levels"]
        if stats["open"]:
            self.incidents_summary.config(
                text=f"{stats['open']} open incidents   -   "
                     f"{lv['CRITICAL']} critical / {lv['HIGH']} high / {lv['MEDIUM']} medium")
        else:
            self.incidents_summary.config(text="no incidents yet")

    def _on_incident_select(self, _evt):
        sel = self.incidents_tree.selection()
        if not sel:
            return
        i = self._incident_rows.get(sel[0])
        if not i:
            return
        import time as _t
        lines = [f"INCIDENT #{i['id']}   -   {i['actor']}",
                 f"Level:   {i['level']}   (score {i['score']})",
                 f"Pattern: {i['pattern'] or 'no recognised pattern'}",
                 f"Stages:  {' -> '.join(i['stages']) if i['stages'] else '-'}",
                 f"Window:  {_t.strftime('%H:%M:%S', _t.localtime(i['first']))}"
                 f" -> {_t.strftime('%H:%M:%S', _t.localtime(i['last']))}"
                 f"   ({i['duration']:.0f}s, {i['event_count']} events)",
                 ""]
        try:
            import mitre_attack
            techs = mitre_attack.techniques_for_incident(i)
            tactics = mitre_attack.tactics_for_incident(i)
            if tactics:
                # The tactic order is the attack's shape in ATT&CK's own terms -
                # more legible at a glance than the raw technique list below.
                lines.append("ATT&CK tactics:  " + " -> ".join(tactics))
            if techs:
                lines.append("ATT&CK techniques:")
                for t in techs:
                    lines.append(f"   {t['id']:11} {t['name']}  ({t['tactic']})")
                lines.append("")
        except Exception:
            pass
        lines.append(f"{i['distinct_signals']} distinct detector(s) fired:")
        lines.append("")
        for e in i["events"][-24:]:
            lines.append(f"   [{e['severity']:7}] {e['stamp']}  {e['category']:9}  {e['message'][:78]}")
        lines.append("")
        lines.append("Right-click the row to inspect this actor. 'Acknowledge' clears the incident.")
        self.incident_detail.config(state="normal")
        self.incident_detail.delete("1.0", "end")
        self.incident_detail.insert("1.0", "\n".join(lines))
        self.incident_detail.config(state="disabled")

    def _ack_incident(self):
        sel = self.incidents_tree.selection()
        if not sel:
            return
        i = self._incident_rows.get(sel[0])
        if i:
            try:
                correlation.acknowledge(i["actor"])
            except Exception:
                pass
            self._incidents_sig = None
            self._render_incidents()

    def _rebuild_incidents(self):
        """Re-derive incidents from stored event history (retro-hunt)."""
        try:
            import db_manager
            rows = db_manager.get_events(limit=5000)
            for r in rows:
                r.setdefault("ts", 0)
                try:
                    r["ts"] = time.mktime(time.strptime(r.get("ts", ""), "%Y-%m-%d %H:%M:%S"))
                except Exception:
                    r["ts"] = 0
                r["stamp"] = ""
            correlation.rebuild(rows)
        except Exception as exc:
            print("rebuild error:", exc)
        self._incidents_sig = None
        self._render_incidents()

    def _build_logs_tab(self):
        bar = ttk.Frame(self.logs_tab)
        bar.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(bar, text="Severity:").pack(side="left")
        self.log_sev = tk.StringVar(value="ALL")
        ttk.Combobox(
            bar, textvariable=self.log_sev, width=10, state="readonly",
            values=("ALL", "INFO", "WARNING", "ALERT"),
        ).pack(side="left", padx=(4, 10))
        self.log_pause = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Pause", variable=self.log_pause).pack(side="left")
        ttk.Button(bar, text="Retro-hunt (search history)",
                   command=self._open_retrohunt).pack(side="left", padx=(10, 0))
        self.log_count = ttk.Label(bar, text="")
        self.log_count.pack(side="right")

        cols = ("time", "sev", "cat", "source", "message")
        self.log_tree = ttk.Treeview(self.logs_tab, columns=cols, show="headings")
        for c, txt, w in (
            ("time", "TIME", 150), ("sev", "SEV", 80), ("cat", "CATEGORY", 90),
            ("source", "SOURCE", 140), ("message", "MESSAGE", 600),
        ):
            self.log_tree.heading(c, text=txt)
            self.log_tree.column(c, width=w)
        self.log_tree.tag_configure("ALERT", foreground=THEME_RED)
        self.log_tree.tag_configure("WARNING", foreground=THEME_AMBER)
        self.log_tree.tag_configure("INFO", foreground=THEME_MUTED)
        self._log_rows = {}
        self._bind_context(
            self.log_tree,
            lambda item: (self._log_rows.get(item)
                          if self._looks_like_ip(self._log_rows.get(item, "")) else None))
        self.log_tree.pack(fill="both", expand=True, padx=10, pady=10)

        self.root.after(1500, self._refresh_logs)

    def _open_retrohunt(self):
        """Search the full stored event history (retro-hunt)."""
        import db_manager
        win = tk.Toplevel(self.root)
        win.title("Retro-hunt - search stored history")
        win.configure(bg=THEME_BG)
        win.geometry("900x600")
        tk.Label(win, text="RETRO-HUNT", bg=THEME_HEAD, fg=THEME_ACCENT,
                 font=(FONT_HEAD, 13), anchor="w", padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_ACCENT, height=2).pack(fill="x")

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=10, pady=8)
        ttk.Label(bar, text="Text:").pack(side="left")
        q_text = tk.StringVar()
        ttk.Entry(bar, textvariable=q_text, width=22).pack(side="left", padx=(4, 10))
        ttk.Label(bar, text="Category:").pack(side="left")
        q_cat = tk.StringVar(value="ANY")
        cats = ["ANY"] + sorted(events.CATEGORY_INFO.keys()) if hasattr(events, "CATEGORY_INFO") else ["ANY"]
        ttk.Combobox(bar, textvariable=q_cat, width=10, state="readonly",
                     values=cats).pack(side="left", padx=(4, 10))
        ttk.Label(bar, text="Severity:").pack(side="left")
        q_sev = tk.StringVar(value="ANY")
        ttk.Combobox(bar, textvariable=q_sev, width=9, state="readonly",
                     values=("ANY", "INFO", "WARNING", "ALERT")).pack(side="left", padx=(4, 10))
        ttk.Label(bar, text="Source IP:").pack(side="left")
        q_src = tk.StringVar()
        ttk.Entry(bar, textvariable=q_src, width=14).pack(side="left", padx=(4, 10))

        summary = ttk.Label(win, text="")
        summary.pack(fill="x", padx=12)

        cols = ("time", "sev", "cat", "source", "message")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c, txt, w in (("time", "TIME", 150), ("sev", "SEV", 74), ("cat", "CATEGORY", 90),
                          ("source", "SOURCE", 140), ("message", "MESSAGE", 420)):
            tree.heading(c, text=txt)
            tree.column(c, width=w)
        tree.tag_configure("ALERT", foreground=THEME_RED)
        tree.tag_configure("WARNING", foreground=THEME_AMBER)
        tree.tag_configure("INFO", foreground=THEME_MUTED)
        rows_map = {}
        self._bind_context(tree, lambda item: rows_map.get(item))

        def run_search():
            cat = None if q_cat.get() == "ANY" else q_cat.get()
            sev = None if q_sev.get() == "ANY" else q_sev.get()
            try:
                results = db_manager.search_events(
                    text=q_text.get().strip() or None, category=cat, severity=sev,
                    source=q_src.get().strip() or None, limit=2000)
            except Exception as exc:
                summary.config(text=f"search error: {exc}")
                return
            tree.delete(*tree.get_children())
            rows_map.clear()
            for r in reversed(results):
                item = tree.insert("", "end", values=(
                    r.get("ts", ""), r.get("severity", ""), r.get("category", ""),
                    r.get("source", ""), r.get("message", "")),
                    tags=(r.get("severity", "INFO"),))
                rows_map[item] = r.get("source", "")
            st = db_manager.event_stats()
            summary.config(text=f"{len(results)} match(es)   -   "
                                f"{st['total']} events in history")

        ttk.Button(bar, text="Search", command=run_search).pack(side="left", padx=(6, 0))
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        run_search()

    def _refresh_logs(self):
        if not self.log_pause.get():
            rows = events.recent(limit=400, severity=self.log_sev.get())
            self.log_tree.delete(*self.log_tree.get_children())
            self._log_rows = {}
            for e in rows:
                item = self.log_tree.insert(
                    "", "end",
                    values=(e["stamp"], e["severity"], e["category"],
                            e["source"], e["message"]),
                    tags=(e["severity"],),
                )
                self._log_rows[item] = e["source"]
            self.log_count.config(text=f"{len(rows)} shown")
            try:
                self.log_tree.yview_moveto(1.0)
            except Exception:
                pass
        self.root.after(1500, self._refresh_logs)

    # ---------- watchlist ----------

    _WATCH_KINDS = (("IP / CIDR", "ip"),
                    ("Country (code or name)", "country"),
                    ("ASN (number)", "asn"))

    # ---------- network (LAN survey) ----------

    def _build_network_tab(self):
        top = ttk.Frame(self.network_tab)
        top.pack(fill="x", padx=10, pady=(10, 0))
        self.net_summary = ttk.Label(top, text="No devices discovered yet",
                                     font=(FONT_HEAD, 10))
        self.net_summary.pack(side="left")
        self.net_scan_btn = ttk.Button(top, text="Scan network now", command=self._lan_scan_now)
        self.net_scan_btn.pack(side="right")
        self.net_ports_btn = ttk.Button(top, text="Scan ports on selected",
                                        command=self._scan_host_ports)
        self.net_ports_btn.pack(side="right", padx=6)
        self.net_vuln_btn = ttk.Button(top, text="Check vulnerabilities",
                                       command=self._check_host_vulns)
        self.net_vuln_btn.pack(side="right")

        cols = ("ip", "mac", "vendor", "host", "kind", "os", "ports", "seen")
        self.net_tree = ttk.Treeview(self.network_tab, columns=cols, show="headings")
        for c, txt, w in (("ip", "IP", 116), ("mac", "MAC", 130), ("vendor", "VENDOR", 130),
                          ("host", "HOSTNAME", 175), ("kind", "TYPE", 120),
                          ("os", "IDENTIFIED AS", 190),
                          ("ports", "OPEN PORTS", 120), ("seen", "SEEN", 58)):
            self.net_tree.heading(c, text=txt)
            self.net_tree.column(c, width=w)
        self.net_tree.tag_configure("self", foreground=THEME_ACCENT)
        self.net_tree.tag_configure("risk", foreground=THEME_AMBER)
        self.net_tree.bind("<<TreeviewSelect>>", self._on_host_select)
        self._net_rows = {}
        self._bind_context(self.net_tree, lambda item: self._net_rows.get(item))

        det = ttk.Frame(self.network_tab)
        det.pack(side="bottom", fill="x", padx=10, pady=(0, 10))
        self.net_detail = tk.Label(
            det, text="Select a device for details, then 'Scan ports on selected' to map what it "
                      "exposes. Devices are found by ARP sweep and by the mDNS / SSDP / DHCP / "
                      "NetBIOS chatter they broadcast; names come from reverse DNS, NetBIOS, or "
                      "mDNS. Only scan networks you own or are authorised to test.",
            justify="left", anchor="w", wraplength=940, font=("Consolas", 9),
            bg=THEME_PANEL, fg=THEME_FG, padx=10, pady=8)
        self.net_detail.pack(fill="x")

        self.net_tree.pack(fill="both", expand=True, padx=10, pady=10)
        self._net_sig = None
        self.root.after(3000, self._refresh_network)

    def _refresh_network(self):
        self._render_network()
        self.root.after(3000, self._refresh_network)

    def _render_network(self):
        import time as _t
        try:
            hosts = lan_monitor.hosts()
        except Exception as exc:
            print("network refresh error:", exc)
            return
        sig = tuple((h["ip"], h["mac"], h["hostname"], h["kind"], len(h["services"]),
                     tuple(h["ports"]),
                     (threat_detection.get_host_os(h["ip"]) or {}).get("os", ""))
                    for h in hosts)
        if sig == self._net_sig:
            return
        self._net_sig = sig
        # Push link-layer identity into the asset record. Without this the
        # registry only ever learns about hosts that were port-scanned, so a
        # discovered-but-unscanned device has no record at all.
        for h in hosts:
            try:
                asset_registry.note_identity(
                    h["ip"], mac=h.get("mac"), vendor=h.get("vendor"),
                    hostname=h.get("hostname"), kind=h.get("kind"))
            except Exception:
                pass
        self.net_tree.delete(*self.net_tree.get_children())
        self._net_rows = {}
        now = _t.time()
        n_risk = 0
        for h in hosts:
            age = now - h["last"]
            seen = "now" if age < 60 else (f"{int(age // 60)}m" if age < 3600 else f"{int(age // 3600)}h")
            risky = port_scanner.risky(h["findings"]) if h["findings"] else []
            if risky:
                n_risk += 1
            if h["ports"]:
                ports = ", ".join(str(p) for p in h["ports"][:5])
                if len(h["ports"]) > 5:
                    ports += f" +{len(h['ports']) - 5}"
                if risky:
                    ports = "\u26a0 " + ports
            else:
                ports = "-"
            tags = ("self",) if h["is_self"] else (("risk",) if risky else ())
            os_fp = threat_detection.get_host_os(h["ip"])
            # Prefer what we positively identified (SMB build, product banner,
            # TLS certificate) over the passive TCP-fingerprint guess. The
            # passive answer is an inference; the asset record holds measurements.
            os_txt = asset_registry.describe(h["ip"]) or (
                os_fp["os"] if os_fp else "") or "-"
            item = self.net_tree.insert("", "end", values=(
                h["ip"], h["mac"] or "-", h["vendor"] or "-", h["hostname"] or "-",
                h["kind"] or "-", os_txt, ports, seen), tags=tags)
            self._net_rows[item] = h["ip"]
        msg = f"{len(hosts)} device(s) on the network"
        if n_risk:
            msg += f"   -   {n_risk} with services worth reviewing"
        try:
            if dhcp_monitor.rogue_count():
                msg += f"   -   {dhcp_monitor.rogue_count()} ROGUE DHCP SERVER(S)"
        except Exception:
            pass
        self.net_summary.config(text=msg)

    def _resolve_names(self):
        # Ask each unnamed host for its own name (reverse DNS -> NetBIOS -> mDNS).
        try:
            todo = [h["ip"] for h in lan_monitor.hosts() if not h["hostname"]]
        except Exception:
            return
        if not todo:
            return
        from concurrent.futures import ThreadPoolExecutor
        try:
            with ThreadPoolExecutor(max_workers=min(16, len(todo))) as pool:
                for ip, info in zip(todo, pool.map(
                        lambda i: host_resolve.resolve(i, timeout=1.0), todo)):
                    if info and info.get("hostname"):
                        lan_monitor.note_hostname(
                            ip, info["hostname"], info.get("source", ""),
                            info.get("workgroup", ""), info.get("mac", ""))
        except Exception as exc:
            print("name resolution error:", exc)
        self.root.after(0, lambda: setattr(self, "_net_sig", None))

    def _lan_scan_now(self):
        self.net_scan_btn.config(state="disabled")
        self.net_summary.config(text="scanning (ARP sweep) ...")

        def work():
            try:
                devices = network_discovery.scan_network()
                lan_monitor.ingest_scan(devices)
            except Exception as exc:
                print("scan error:", exc)
            self.root.after(0, lambda: self.net_summary.config(text="resolving names ..."))
            self._resolve_names()

            def done():
                self.net_scan_btn.config(state="normal")
                self._net_sig = None
                self._render_network()
            self.root.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def _startup_net_scan(self):
        # First inventory sweep, then set the baseline so later arrivals alert.
        def work():
            try:
                devices = network_discovery.scan_network()
                lan_monitor.ingest_scan(devices)
            except Exception as exc:
                print("startup scan error:", exc)
            self._resolve_names()
            lan_monitor.mark_baseline()
            self.root.after(0, lambda: setattr(self, "_net_sig", None))

        threading.Thread(target=work, daemon=True).start()

    def _check_host_vulns(self):
        """Identify service versions on a LAN device and check them against NVD.

        Asset vulnerability management: what on my own network needs patching.
        Runs off the UI thread because NVD lookups are deliberately rate-limited.
        """
        sel = self.net_tree.selection()
        if not sel:
            self.net_detail.config(text="Select a device first, then check vulnerabilities.")
            return
        ip = self._net_rows.get(sel[0])
        if not ip:
            return
        findings = []
        for h in lan_monitor.hosts():
            if h.get("ip") == ip:
                findings = h.get("findings") or []
                break
        if not findings:
            messagebox.showinfo(
                "Check vulnerabilities",
                f"No port-scan results for {ip} yet.\n\n"
                "Run 'Scan ports on selected' first - the version banners it "
                "collects are what make a vulnerability check possible.")
            return

        # Identify once, persist to the asset record, and reuse the rows below -
        # this used to run twice and discard the result both times.
        rows = service_fingerprint.identify_findings(findings, ip=ip)
        asset_registry.note_services(ip, rows)
        asset_registry.save()
        products = []
        for row in rows:
            products.extend(row["products"])
        versioned = service_fingerprint.versioned(products)

        win = tk.Toplevel(self.root)
        win.title(f"Vulnerabilities - {ip}")
        win.configure(bg=THEME_BG)
        win.geometry("860x600")
        tk.Label(win, text=f"VULNERABILITY ASSESSMENT   {ip}", bg=THEME_HEAD,
                 fg=THEME_ACCENT, font=(FONT_HEAD, 13), anchor="w",
                 padx=14, pady=9).pack(fill="x")
        tk.Frame(win, bg=THEME_BORDER, height=1).pack(fill="x")
        status = tk.Label(win, text="", bg=THEME_BG, fg=THEME_MUTED,
                          font=(FONT_UI, 9), anchor="w", padx=14, pady=6)
        status.pack(fill="x")
        body = scrolledtext.ScrolledText(win, bg=THEME_PANEL, fg=THEME_FG,
                                         font=(FONT_DATA, 10), wrap="word",
                                         padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Show what we identified immediately - that part needs no network.
        body.insert("end", "IDENTIFIED SERVICES\n")
        for row in rows:
            for p in row["products"]:
                mark = "*" if p["confidence"] == "high" else " "
                ver = p["version"] or "version not disclosed"
                body.insert("end", f" {mark} {row['port']}/tcp  {p['label']} {ver}\n")
        body.insert("end", "\n")
        if not versioned:
            body.insert("end",
                        "None of these services disclosed a version, so there is "
                        "nothing to check against the CVE database. That is a "
                        "normal result for SMB, RDP, printers and most IoT gear.\n")
            status.config(text="Nothing to look up.")
            return

        est = len(versioned) * (1 if cve_lookup.has_api_key() else 7)
        status.config(text=f"Looking up {len(versioned)} service version(s) against "
                           f"NVD - roughly {est}s (rate-limited by NIST).")

        def work():
            try:
                assessments = cve_lookup.assess_products(versioned)
                asset_registry.note_vulnerabilities(ip, assessments)
                asset_registry.save()
                lines = cve_lookup.summarize(assessments)
                roll = cve_lookup.risk_rollup(assessments)
                # Surface serious findings into the event stream so they show up
                # in Alerts/Logs alongside everything else.
                for a in assessments:
                    # Release-level OS matches are the release's whole history,
                    # not this host's exposure - alerting on them would bury the
                    # Alerts tab under a thousand already-patched findings.
                    if a.get("precision") == "release":
                        continue
                    for c in (a.get("cves") or []):
                        if (c.get("severity") in ("HIGH", "CRITICAL")
                                and not c.get("suspect")):
                            events.log_event(
                                "WARNING", "vuln", ip,
                                f"{ip} runs {a['product']} {a['version']} - "
                                f"{c['id']} ({c['severity']} {c['score']})")
            except Exception as exc:
                lines = [f"Lookup failed: {exc}"]
                roll = {}

            def done():
                body.insert("end", "KNOWN VULNERABILITIES\n")
                body.insert("end", "\n".join(lines))
                body.see("end")
                if roll.get("total_cves"):
                    status.config(
                        text=f"{roll['total_cves']} CVE(s) - worst "
                             f"{roll['worst_severity'].title()} "
                             f"({roll['worst_score']}). Patch guidance only; "
                             "verify against vendor advisories.")
                else:
                    status.config(text="No known CVEs matched the identified versions.")
            self.root.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def _scan_host_ports(self):
        sel = self.net_tree.selection()
        if not sel:
            self.net_detail.config(text="Select a device first, then scan its ports.")
            return
        ip = self._net_rows.get(sel[0])
        if not ip:
            return
        self.net_ports_btn.config(state="disabled")
        self.net_detail.config(text=f"Scanning {ip} for open services ...")

        def work():
            try:
                findings = port_scanner.scan_host(ip, timeout=0.5)
                lan_monitor.note_findings(ip, findings)
                # Everything the scan learned goes onto the asset record, so the
                # device inventory knows what a host *is*, not just that it exists.
                try:
                    rows = service_fingerprint.identify_findings(findings, ip=ip)
                    asset_registry.note_services(ip, rows)
                    for f in findings:
                        if f.get("cert_issues"):
                            asset_registry.note_cert_issues(ip, f["port"],
                                                            f["cert_issues"])
                    asset_registry.save()
                except Exception as exc:
                    print("asset record update failed:", exc)
                for f in port_scanner.risky(findings):
                    events.log_event(
                        "WARNING", "service", ip,
                        f"{ip} exposes {f['port']}/{f['service'] or 'unknown'} - {f['risk']}")
                for f in findings:
                    cert = f.get("cert")
                    for sev, label, detail in f.get("cert_issues", []):
                        subj = (cert.get("subject") or {}).get("CN") or "?"
                        events.log_event(
                            sev, "cert", ip,
                            f"{ip}:{f['port']} certificate ({subj}) - {label}: {detail}")
            except Exception as exc:
                print("port scan error:", exc)

            def done():
                self.net_ports_btn.config(state="normal")
                self._net_sig = None
                self._render_network()
                self._show_host_detail(ip)
            self.root.after(0, done)

        threading.Thread(target=work, daemon=True).start()

    def _on_host_select(self, _evt):
        sel = self.net_tree.selection()
        if sel:
            ip = self._net_rows.get(sel[0])
            if ip:
                self._show_host_detail(ip)

    def _show_host_detail(self, ip):
        h = lan_monitor.get(ip)
        if not h:
            return
        lines = [f"{h['ip']}" + ("   (this machine)" if h["is_self"] else "")]
        if h["mac"]:
            lines.append(f"MAC:  {h['mac']}" + (f"   -  {h['vendor']}" if h["vendor"] else ""))
        elif h["vendor"]:
            lines.append(f"Vendor:  {h['vendor']}")
        if h["hostname"]:
            src = f"   (via {h['name_source']})" if h.get("name_source") else ""
            lines.append(f"Hostname:  {h['hostname']}{src}")
        if h.get("workgroup"):
            lines.append(f"Workgroup:  {h['workgroup']}")
        if h["kind"]:
            lines.append(f"Type:  {h['kind']}")
        if h["services"]:
            pretty = [s.replace("._tcp.local", "").replace("._udp.local", "").lstrip("_")
                      for s in h["services"][:12]]
            lines.append("Services:  " + ", ".join(pretty))
        if h["findings"]:
            lines.append("")
            lines.append("OPEN PORTS:")
            for f in h["findings"]:
                row = f"   {f['port']:>5}/{f['service'] or 'unknown'}"
                if f["banner"]:
                    row += f"   \u2192 {f['banner']}"
                lines.append(row)
                cert = f.get("cert")
                if cert:
                    subj = (cert.get("subject") or {}).get("CN") or "?"
                    iss = (cert.get("issuer") or {}).get("CN") or "?"
                    key = cert.get("key_type", "")
                    key += f" {cert['curve']}" if cert.get("curve") else f" {cert.get('key_bits', 0)}-bit"
                    lines.append(f"          cert: {subj}   issued by {iss}")
                    lines.append(f"          {key},  {cert.get('sig_alg', '?')},  "
                                 f"expires {tls_certs._fmt(cert.get('not_after'))}"
                                 f"   [{cert.get('tls_version', '?')}]")
                    if cert.get("san"):
                        lines.append(f"          names: {', '.join(cert['san'][:5])}")
                    for sev, label, detail in f.get("cert_issues", []):
                        lines.append(f"          [!] {label}  -  {detail}")
            risky = port_scanner.risky(h["findings"])
            if risky:
                lines.append("")
                lines.append("WORTH REVIEWING:")
                for f in risky:
                    lines.append(f"   [!] {f['port']}/{f['service']}  -  {f['risk']}")
        elif h["ports"]:
            lines.append("Open ports:  " + ", ".join(str(p) for p in h["ports"]))
        via = []
        if h["active"]:
            via.append("ARP sweep")
        if h["passive"]:
            via.append("passive broadcast")
        lines.append("")
        lines.append("Discovered via:  " + (", ".join(via) or "unknown")
                     + "     |     Right-click to inspect this host or copy its IP.")
        self.net_detail.config(text="\n".join(lines))

    def _build_watchlist_tab(self):
        wrap = ttk.Frame(self.watchlist_tab)
        wrap.pack(fill="both", expand=True, padx=14, pady=12)

        ttk.Label(wrap, text="Watchlist", font=(FONT_HEAD, 13)).pack(anchor="w")
        ttk.Label(wrap, text="Raise an alert whenever traffic touches an IP/CIDR, country, or ASN "
                             "you list here. Matches appear in the Alerts tab and flag red on the map.").pack(anchor="w", pady=(0, 10))

        add = ttk.LabelFrame(wrap, text="Add a rule")
        add.pack(fill="x", pady=6)
        row = ttk.Frame(add)
        row.pack(fill="x", padx=8, pady=8)
        ttk.Label(row, text="Type:").pack(side="left")
        self._watch_kind = tk.StringVar(value=self._WATCH_KINDS[0][0])
        ttk.Combobox(row, textvariable=self._watch_kind, width=22, state="readonly",
                     values=[d for d, _ in self._WATCH_KINDS]).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Value:").pack(side="left")
        self._watch_value = tk.StringVar()
        ttk.Entry(row, textvariable=self._watch_value, width=22).pack(side="left", padx=(4, 10))
        ttk.Label(row, text="Note:").pack(side="left")
        self._watch_note = tk.StringVar()
        ttk.Entry(row, textvariable=self._watch_note, width=22).pack(side="left", padx=(4, 10))
        ttk.Button(row, text="Add", command=self._add_watch).pack(side="left")
        self.watch_status = ttk.Label(add, text="e.g.  Country = RU   |   ASN = 13335   |   IP = 45.9.0.0/16",
                                      foreground=THEME_MUTED)
        self.watch_status.pack(anchor="w", padx=8, pady=(0, 8))

        lst = ttk.LabelFrame(wrap, text="Current rules")
        lst.pack(fill="both", expand=True, pady=6)
        cols = ("type", "value", "note")
        self.watch_tree = ttk.Treeview(lst, columns=cols, show="headings")
        for c, txt, w in (("type", "TYPE", 120), ("value", "VALUE", 220), ("note", "NOTE", 360)):
            self.watch_tree.heading(c, text=txt)
            self.watch_tree.column(c, width=w)
        self.watch_tree.pack(fill="both", expand=True, padx=6, pady=(6, 4))
        self._watch_items = {}

        btns = ttk.Frame(lst)
        btns.pack(fill="x", padx=6, pady=(0, 6))
        ttk.Button(btns, text="Remove selected", command=self._remove_watch).pack(side="left")
        ttk.Button(btns, text="Clear all", command=self._clear_watch).pack(side="left", padx=8)

        self._refresh_watch_tree()

    def _refresh_watch_tree(self):
        self.watch_tree.delete(*self.watch_tree.get_children())
        self._watch_items = {}
        labels = {k: d for d, k in self._WATCH_KINDS}
        for i, r in enumerate(watchlist.rules()):
            item = self.watch_tree.insert("", "end", values=(
                labels.get(r["kind"], r["kind"]), r["value"], r.get("note", "")))
            self._watch_items[item] = i

    def _add_watch(self):
        kind = dict(self._WATCH_KINDS).get(self._watch_kind.get(), "ip")
        value = self._watch_value.get().strip()
        ok, msg = watchlist.validate(kind, value)
        if not ok:
            self.watch_status.config(text=msg, foreground=THEME_RED)
            return
        if watchlist.add(kind, value, self._watch_note.get().strip()):
            self._watch_value.set("")
            self._watch_note.set("")
            self.watch_status.config(text=f"added {kind} rule: {value}", foreground=THEME_MUTED)
            self._refresh_watch_tree()
        else:
            self.watch_status.config(text="that rule already exists", foreground=THEME_AMBER)

    def _remove_watch(self):
        sel = self.watch_tree.selection()
        if not sel:
            return
        idx = self._watch_items.get(sel[0])
        if idx is not None and watchlist.remove(idx):
            self._refresh_watch_tree()

    def _clear_watch(self):
        watchlist.clear()
        self._refresh_watch_tree()
        self.watch_status.config(text="all rules cleared", foreground=THEME_MUTED)

    def _check_watchlist(self):
        try:
            if watchlist.rules():
                ext = threat_detection.external_endpoints()
                for ip in ext:
                    r = watchlist.match(ip, geo_lookup.get(ip))
                    if not r:
                        continue
                    key = (ip, r["kind"], r["value"])
                    if key in self._watch_alerted:
                        continue
                    self._watch_alerted.add(key)
                    note = f" ({r['note']})" if r.get("note") else ""
                    events.log_event("ALERT", "watch", ip,
                                     f"Watchlist match: {ip} matches {r['kind']} '{r['value']}'{note}")
        except Exception as e:
            print("watchlist check error:", e)
        self.root.after(3000, self._check_watchlist)

    # ---------- desktop notifications ----------

    @staticmethod
    def _notifiable(alerts, seen, include_warnings):
        # New (unseen) events matching the severity filter, oldest-first.
        out = []
        for e in alerts:
            key = events.event_key(e)
            if key in seen:
                continue
            sev = e.get("severity")
            if sev == "ALERT" or (include_warnings and sev == "WARNING"):
                out.append((key, e))
        return out

    def _poll_notifications(self):
        try:
            alerts = [e for e in events.recent(limit=300)
                      if e["severity"] in ("ALERT", "WARNING")]
            include_w = bool(settings.get("notify_warnings", 0))
            new = self._notifiable(alerts, self._notified_keys, include_w)
            # Mark every candidate seen (so toggling the filter later doesn't
            # dump a backlog), then toast only once we're past the first poll.
            for e in alerts:
                self._notified_keys.add(events.event_key(e))
            if new and self._notify_ready and bool(settings.get("notify_enabled", 1)):
                self._show_notifications(new)
            self._notify_ready = True
        except Exception as exc:
            print("notification poll error:", exc)
        self.root.after(2000, self._poll_notifications)

    def _show_notifications(self, new):
        cap = 3
        for _key, e in new[:cap]:
            self._toast(e["severity"],
                        f"{e['category'].upper()}  -  {e['source']}", e["message"])
        extra = len(new) - cap
        if extra > 0:
            self._toast("ALERT", "More alerts",
                        f"+{extra} more new alert(s) - open the Alerts tab.")

    def _toast(self, severity, title, message):
        try:
            color = THEME_RED if severity == "ALERT" else THEME_AMBER
            win = tk.Toplevel(self.root)
            win.overrideredirect(True)
            try:
                win.attributes("-topmost", True)
            except Exception:
                pass
            w, h = 340, 96
            sw = self.root.winfo_screenwidth()
            x = sw - w - 24
            y = 24 + len(self._toasts) * (h + 12)
            win.geometry(f"{w}x{h}+{x}+{y}")
            outer = tk.Frame(win, bg=color)
            outer.pack(fill="both", expand=True)
            inner = tk.Frame(outer, bg=THEME_PANEL)
            inner.pack(fill="both", expand=True, padx=2, pady=2)
            tk.Label(inner, text=title, bg=THEME_PANEL, fg=color,
                     font=(FONT_HEAD, 10), anchor="w").pack(fill="x", padx=10, pady=(8, 0))
            tk.Label(inner, text=message, bg=THEME_PANEL, fg=THEME_FG, font=("Consolas", 9),
                     anchor="w", justify="left", wraplength=w - 24).pack(fill="x", padx=10, pady=(2, 8))
            self._toasts.append(win)

            def close(_evt=None, _w=win):
                try:
                    if _w in self._toasts:
                        self._toasts.remove(_w)
                    _w.destroy()
                except Exception:
                    pass
                self._restack_toasts()

            for widget in (win, outer, inner) + tuple(inner.winfo_children()):
                widget.bind("<Button-1>", close)
            win.after(6000, close)
        except Exception as exc:
            print("toast error:", exc)

    def _restack_toasts(self):
        w, h = 340, 96
        try:
            sw = self.root.winfo_screenwidth()
        except Exception:
            return
        for i, win in enumerate(list(self._toasts)):
            try:
                win.geometry(f"{w}x{h}+{sw - w - 24}+{24 + i * (h + 12)}")
            except Exception:
                pass

    # ---------- chart helper ----------

    def _barh(self, ax, items, colors, title):
        ax.clear()
        ax.set_title(title, fontsize=9)
        ax.tick_params(labelsize=7)
        if not items:
            ax.set_xlim(0, 1)
            return
        labels = [str(k) for k, _ in items]
        values = [v for _, v in items]
        ax.barh(labels, values, color=colors)
        top = max(values)
        ax.set_xlim(0, top * 1.18 + 1)
        for i, v in enumerate(values):
            ax.text(v + top * 0.01 + 0.1, i, str(v), va="center", fontsize=6)

    # ---------- refresh loops ----------

    def _refresh_metrics(self):
        try:
            src = threat_detection._safe_copy(threat_detection.source_counts)
            proc = threat_detection._safe_copy(threat_detection.process_counts)
            proto = threat_detection._safe_copy(threat_detection.times_found_dict)
            ext = threat_detection.external_endpoints()
        except Exception:
            src, proc, proto, ext = {}, {}, {}, {}

        top_src = sorted(src.items(), key=lambda kv: kv[1], reverse=True)[:8][::-1]
        scopes = [threat_detection.classify_ip(ip) for ip, _ in top_src]
        self._barh(
            self.ax_src, top_src,
            [SCOPE_COLORS.get(s, "#888780") for s in scopes],
            "Top sources",
        )

        by_country = geo_lookup.group_by_country(ext)
        top_c = sorted(by_country.items(), key=lambda kv: kv[1], reverse=True)[:8][::-1]
        self._barh(
            self.ax_geo, top_c,
            ["#888780" if l in ("Resolving...", "Unknown") else "#185FA5" for l, _ in top_c],
            "By country",
        )

        top_a = sorted(proc.items(), key=lambda kv: kv[1], reverse=True)[:8][::-1]
        self._barh(self.ax_app, top_a, "#7F77DD", "Top applications")

        top_p = sorted(proto.items())
        self._barh(self.ax_proto, top_p, "#378ADD", "Protocols")

        self.canvas.draw_idle()

        n = scan_detector.active_alert_count()
        if n:
            self.banner.config(
                text=f"[!]  {n} possible port scan(s) detected", fg=THEME_RED
            )
        else:
            self.banner.config(
                text="Monitoring - no port scans detected", fg=THEME_ACCENT
            )

        total = sum(src.values()) if src else 0
        self.counters.config(
            text=f"Packets: {total:,}     Sources: {len(src)}     "
                 f"External endpoints: {len(ext)}"
        )

        # Sample throughput (bytes/s and pkts/s) for the strip chart.
        try:
            cap = threat_detection.capture_status()
            now = time.time()
            tb, tp = cap.get("bytes", 0), cap.get("packets", 0)
            if self._tp_last is not None:
                dt = now - self._tp_last[0]
                if dt > 0:
                    bps = max(0.0, (tb - self._tp_last[1]) / dt)
                    pps = max(0.0, (tp - self._tp_last[2]) / dt)
                    self._tp_hist.append((now, bps, pps))
            self._tp_last = (now, tb, tp)
            self._draw_throughput()
        except Exception as e:
            print("throughput sample error:", e)

        self.root.after(1000, self._refresh_metrics)

    def _draw_throughput(self):
        ax = self.ax_tp
        ax.clear()
        ax.set_title("Throughput (last ~2 min)", fontsize=9)
        ax.tick_params(labelsize=7)
        ax.set_xlabel("seconds ago", fontsize=7)
        if len(self._tp_hist) < 2:
            ax.set_xlim(-60, 0)
            ax.set_ylim(0, 1)
            self.tp_canvas.draw_idle()
            return
        t_now = self._tp_hist[-1][0]
        xs = [t - t_now for (t, _, _) in self._tp_hist]   # <= 0
        bps = [b for (_, b, _) in self._tp_hist]
        ax.plot(xs, bps, color=THEME_ACCENT, linewidth=1.4)
        ax.fill_between(xs, bps, color=THEME_ACCENT, alpha=0.18)
        ax.set_xlim(min(xs[0], -60), 0)
        ymax = max(bps) if any(bps) else 1
        ax.set_ylim(0, ymax * 1.25 + 1)
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _p: _human_bytes(v) + "/s"))
        cur_b, cur_p = self._tp_hist[-1][1], self._tp_hist[-1][2]
        ax.text(0.99, 0.90, f"{_human_bytes(cur_b)}/s   |   {cur_p:.0f} pkt/s",
                transform=ax.transAxes, ha="right", va="top",
                fontsize=8, color=THEME_FG)
        self.tp_canvas.draw_idle()

    def _locate_me(self):
        info = geo_lookup.locate_self()
        if info and info.get("lat") is not None:
            self._me_coords = (info["lat"], info["lon"])
            label = info.get("city") or info.get("country") or "You"
            self.root.after(0, lambda: self.ops_map.set_self(
                self._me_coords[0], self._me_coords[1], f"YOU ({label})"))

    def _refresh_map(self):
        try:
            ext = threat_detection.external_endpoints()
            top = sorted(ext.items(), key=lambda kv: kv[1], reverse=True)[:MAP_MAX_ENDPOINTS]
            maxv = max((c for _, c in top), default=1)
            flagged = self._flagged_ips()
            eps = []
            for ip, count in top:
                point = geo_lookup.coords(ip)
                if not point:
                    continue
                info = geo_lookup.get(ip)
                host = threat_detection.host_for(ip)
                detail = threat_detection.endpoint_detail(ip)
                apps = detail.get("apps") or []
                app = apps[0][0] if apps else "unknown"
                sni_list = detail.get("sni") or []
                label = (sni_list[0] if sni_list else None) or host or info.get("country") or ip
                fl = ip in flagged
                reason = ""
                if fl:
                    rs = self._flag_reasons(ip)
                    reason = rs[0][2] if rs else ""
                eps.append({
                    "label": str(label)[:20],
                    "app": app,
                    "lat": point[0], "lon": point[1],
                    "weight": count / maxv,
                    "out_bytes": detail.get("out_bytes", 0),
                    "in_bytes": detail.get("in_bytes", 0),
                    "flagged": fl,
                    "data": {"ip": ip, "count": count, "info": info,
                             "coords": point, "reason": reason},
                })
            self.ops_map.set_endpoints(eps)
        except Exception as e:
            print("Map refresh error:", e)
        self.root.after(8000, self._refresh_map)

    def _capture_running(self):
        s = getattr(self, "sniffer", None)
        if not s:
            return False
        r = getattr(s, "running", None)
        if r is not None:
            return bool(r)
        t = getattr(s, "thread", None)
        return bool(t and t.is_alive())

    def _flag_reasons(self, ip):
        # The specific reasons an IP is flagged: recent ALERT/WARNING events
        # whose source is this IP, most-recent first, de-duplicated.
        hits = []
        try:
            for e in events.recent(limit=800):
                if e.get("source") == ip and e.get("severity") in ("ALERT", "WARNING") \
                        and not events.is_acked(events.event_key(e)):
                    hits.append((e["severity"], e["category"], e["message"]))
        except Exception:
            pass
        seen, out = set(), []
        for sev, cat, msg in reversed(hits):
            if msg in seen:
                continue
            seen.add(msg)
            out.append((sev, cat, msg))
            if len(out) >= 5:
                break
        return out

    def _flagged_ips(self):
        # IPs that are the source of an unacknowledged ALERT flag red on the map.
        # Acknowledging an alert in the Alerts tab clears its flag here.
        flagged = set()
        try:
            for e in events.recent(limit=400):
                if e.get("severity") == "ALERT" and not events.is_acked(events.event_key(e)):
                    flagged.add(e.get("source"))
        except Exception:
            pass
        return flagged

    # ---------- map interaction ----------

    def _on_endpoint_select(self, data):
        data = data or {}
        info = data.get("info") or {}
        ip = data.get("ip", "")
        detail = threat_detection.endpoint_detail(ip)
        host = threat_detection.host_for(ip)

        win = tk.Toplevel(self.root)
        win.title(f"Endpoint {ip}")
        win.resizable(False, False)

        apps = ", ".join(f"{n} ({c})" for n, c in detail.get("apps", [])[:4]) or "?"
        protos = ", ".join(f"{n}" for n, _ in detail.get("protos", [])[:5]) or "?"
        ports = ", ".join(str(p) for p, _ in detail.get("ports", [])[:8]) or "?"
        intel = detail.get("intel")
        rep = f"{intel['category']} ({intel['source']})" if intel else "no known reputation"
        sni = detail.get("sni") or []
        ja3 = detail.get("ja3") or []

        lines = [
            f"IP:         {ip}",
            f"Hostname:   {host or '(none seen via DNS)'}",
            f"TLS SNI:    {', '.join(sni) if sni else '(none seen)'}",
            f"JA3:        {', '.join(ja3) if ja3 else '(none seen)'}",
            f"Reputation: {rep}",
            f"Country:    {info.get('country') or '?'}",
            f"City:       {info.get('city') or '?'}",
            f"ISP / org:  {info.get('isp') or '?'}",
            f"ASN:        {info.get('asn') or '?'}",
            f"Coords:     {data.get('coords', '')}",
            "",
            f"Application:{'':1}{apps}",
            f"Protocols:  {protos}",
            f"Ports:      {ports}",
            f"Direction:  {_human_bytes(detail.get('out_bytes', 0))} out / "
            f"{_human_bytes(detail.get('in_bytes', 0))} in",
            f"Rate:       {_human_bytes(int(detail.get('rate', 0)))}/s",
            f"Packets:    {detail.get('packets', data.get('count', 0))}",
            f"Bytes:      {_human_bytes(detail.get('bytes', 0))}",
            f"First seen: {_clock(detail.get('first'))}",
            f"Last seen:  {_clock(detail.get('last'))}",
        ]
        tk.Label(
            win, text="\n".join(lines), justify="left",
            font=("Consolas", 10), padx=18, pady=14,
        ).pack(anchor="w")

        reasons = self._flag_reasons(ip)
        if reasons:
            rtxt, cats = ["FLAGGED FOR:"], []
            for sev, cat, msg in reasons:
                rtxt.append(f"  [{sev}] {msg}")
                if cat not in cats:
                    cats.append(cat)
            for cat in cats:
                ex = events.explain(cat)
                if ex:
                    rtxt.append(f"   \u2192 {ex}")
            tk.Label(win, text="\n".join(rtxt), justify="left", fg=THEME_RED,
                     font=("Consolas", 9, "bold")).pack(anchor="w", padx=18, pady=(0, 6))

        tk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 12))

    # ---------- inspection: network scan ----------

    def _scan_network(self):
        self.scan_btn.config(state="disabled")
        self.insp_status.config(text="ARP-scanning the local network...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        try:
            devices = network_discovery.scan_network()
        except Exception as e:
            devices = []
            self.root.after(0, lambda e=e: self.insp_status.config(text=f"Scan error: {e}"))
        try:
            db_manager.store_devices(devices)
        except Exception:
            pass
        self.root.after(0, lambda: self._populate_devices(devices))

    def _populate_devices(self, devices):
        self.dev_tree.delete(*self.dev_tree.get_children())
        for d in devices:
            host = d.get("hostname") or d.get("vendor") or ""
            self.dev_tree.insert("", "end", values=(d.get("ip", ""), d.get("mac", ""), host))
        self.insp_status.config(text=f"{len(devices)} device(s) found.")
        self.scan_btn.config(state="normal")

    def _on_device_select(self, _evt):
        sel = self.dev_tree.selection()
        if sel:
            values = self.dev_tree.item(sel[0]).get("values") or []
            if values:
                self.target_var.set(str(values[0]))

    # ---------- inspection: focused capture ----------

    def _capture(self):
        ip = self.target_var.get().strip()
        if not ip:
            self.insp_status.config(text="Enter or select a target IP first.")
            return
        try:
            count = int(self.count_var.get())
        except ValueError:
            count = 50
        self.capture_btn.config(state="disabled")
        self.insp_status.config(
            text=f"Capturing up to {count} packets to/from {ip} - generate traffic to it..."
        )
        threading.Thread(target=self._capture_worker, args=(ip, count), daemon=True).start()

    def _capture_worker(self, ip, count):
        try:
            pcap_path, packets, findings = target_capture.capture_target(
                ip, count=count, timeout=30
            )
        except Exception as e:
            pcap_path, packets, findings = "", [], []
            self.root.after(0, lambda e=e: self.insp_status.config(text=f"Capture error: {e}"))
        self._last_packets = list(packets)
        self._last_findings = list(findings)
        self.root.after(0, lambda: self._populate_packets(ip, pcap_path))

    def _fill_packet_tree(self, limit=2000):
        # Fill the packet list from self._last_packets / _last_findings.
        # Displays at most `limit` rows (tree indices map 1:1 to the full
        # packet list, so follow-stream/export still see every packet).
        self.pkt_tree.delete(*self.pkt_tree.get_children())
        shown = min(len(self._last_packets), limit)
        for i in range(shown):
            pkt = self._last_packets[i]
            f = self._last_findings[i] if i < len(self._last_findings) else {}
            bits = []
            for key, lbl in (("dns_query", "DNS"), ("tls_sni", "SNI"), ("http", "HTTP")):
                if f.get(key):
                    bits.append(f"{lbl}={f[key]}")
            self.pkt_tree.insert("", "end", values=(i, pkt.summary(), " | ".join(bits)))
        return shown

    def _populate_packets(self, ip, pcap_path):
        self._fill_packet_tree()
        if self._last_packets:
            msg = f"Captured {len(self._last_packets)} packets from {ip}."
            if pcap_path:
                msg += f"  Saved: {pcap_path}"
        else:
            msg = f"No packets captured for {ip} (no traffic during the window?)."
        self.insp_status.config(text=msg)
        self.capture_btn.config(state="normal")

    # ---------- pcap import / export ----------

    def _import_pcap(self):
        path = filedialog.askopenfilename(
            title="Open a capture file",
            filetypes=[("Capture files", "*.pcap *.pcapng *.cap"), ("All files", "*.*")])
        if not path:
            return
        self.import_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.insp_status.config(text=f"Reading {path} ...")
        threading.Thread(target=self._import_worker, args=(path,), daemon=True).start()

    def _import_worker(self, path):
        try:
            packets = pcap_io.read_pcap(path)
        except Exception as e:
            self.root.after(0, lambda e=e: self._import_done(path, None, str(e)))
            return
        findings = []
        for p in packets:
            try:
                findings.append(dpi.inspect(p))
            except Exception:
                findings.append({})
        name = os.path.basename(path)
        events.log_event("INFO", "system", "import",
                         f"Imported {name}: reviewing {len(packets)} packets offline")
        # Full inspection stack over the file, isolated from live state.
        try:
            report = capture_review.review(packets)
        except Exception as exc:
            print("capture review error:", exc)
            report = None
        # The legacy anomaly/scan replay still feeds the Alerts tab.
        try:
            threat_detection.replay_detectors(packets)
        except Exception:
            pass
        self._last_packets = list(packets)
        self._last_findings = findings
        self._last_review = report
        self.root.after(0, lambda: self._import_done(path, len(packets), None))

    def _import_done(self, path, count, err):
        self.import_btn.config(state="normal")
        self.export_btn.config(state="normal")
        if err is not None:
            self.insp_status.config(text=f"Could not read {os.path.basename(path)}: {err}")
            return
        shown = self._fill_packet_tree()
        name = os.path.basename(path)
        rep = getattr(self, "_last_review", None)
        nf = len(rep["findings"]) if rep else 0
        msg = f"Reviewed {count} packets from {name}."
        if rep:
            msg += (f"  {len(rep['protocols'])} protocols, {len(rep['dns'])} DNS, "
                    f"{len(rep['certs'])} certs, {nf} finding(s).")
        msg += "  Click 'Capture review' for the full report."
        if count and shown < count:
            msg += f"  (showing first {shown})"
        self.insp_status.config(text=msg)
        if rep and nf:
            self._show_review()

    def _show_review(self):
        rep = getattr(self, "_last_review", None)
        win = tk.Toplevel(self.root)
        win.title("Capture review")
        win.configure(bg=THEME_BG)
        win.geometry("860x620")
        head = tk.Label(win, text="CAPTURE REVIEW", bg=THEME_HEAD, fg=THEME_ACCENT,
                        font=(FONT_HEAD, 13), anchor="w", padx=12, pady=8)
        head.pack(fill="x")
        tk.Frame(win, bg=THEME_ACCENT, height=2).pack(fill="x")
        body = scrolledtext.ScrolledText(
            win, bg=THEME_PANEL, fg=THEME_FG, insertbackground=THEME_FG,
            font=("Consolas", 10), wrap="word", padx=12, pady=10, bd=0)
        body.pack(fill="both", expand=True)
        if not rep:
            body.insert("1.0", "No capture has been reviewed yet.\n\n"
                        "Use 'Import .pcap' to load a capture file - it is analysed automatically, "
                        "then this report shows what's inside it.")
        else:
            try:
                text = "\n".join(capture_review.summarize(rep))
            except Exception as exc:
                text = f"Could not render the review: {exc}"
            body.insert("1.0", text)
            body.tag_configure("alert", foreground=THEME_RED)
            body.tag_configure("warn", foreground=THEME_AMBER)
            idx = "1.0"
            while True:
                pos = body.search("[ALERT]", idx, stopindex="end")
                if not pos:
                    break
                body.tag_add("alert", pos, f"{pos} lineend")
                idx = f"{pos}+1line"
            idx = "1.0"
            while True:
                pos = body.search("[WARNING]", idx, stopindex="end")
                if not pos:
                    break
                body.tag_add("warn", pos, f"{pos} lineend")
                idx = f"{pos}+1line"
        body.config(state="disabled")
        tk.Button(win, text="Close", command=win.destroy,
                  bg=THEME_PANEL, fg=THEME_FG, bd=0).pack(pady=(0, 10))

    def _export_pcap(self):
        pkts = getattr(self, "_last_packets", None)
        if not pkts:
            self.insp_status.config(text="Nothing to export yet - capture or import some packets first.")
            return
        path = filedialog.asksaveasfilename(
            title="Save capture as", defaultextension=".pcap",
            filetypes=[("pcap", "*.pcap"), ("All files", "*.*")])
        if not path:
            return
        try:
            pcap_io.write_pcap(path, pkts)
            self.insp_status.config(text=f"Exported {len(pkts)} packets to {path}")
        except Exception as e:
            self.insp_status.config(text=f"Export failed: {e}")

    def _on_packet_select(self, _evt):
        sel = self.pkt_tree.selection()
        if not sel:
            return
        values = self.pkt_tree.item(sel[0]).get("values") or []
        if not values:
            return
        try:
            idx = int(values[0])
        except (ValueError, TypeError):
            return
        if not (0 <= idx < len(self._last_packets)):
            return
        pkt = self._last_packets[idx]

        sections = dpi.full_analysis(pkt)
        intel = self._endpoint_intel(pkt)
        if intel:
            sections.append(("Intelligence (remote endpoint)", intel))
        creds = self._packet_creds(pkt)
        if creds:
            sections.append(("Cleartext credentials (exposed!)", creds))
        cert_rows, cert_bad = self._packet_cert(pkt)
        if cert_rows:
            title = "TLS certificate" + ("  (problems found)" if cert_bad else "")
            sections.append((title, cert_rows))
        proto_rows, proto_bad = self._packet_protocol(pkt)
        if proto_rows:
            title = "Protocol classification" + ("  (problems found)" if proto_bad else "")
            sections.append((title, proto_rows))
        self._render_anatomy(sections)

        # Hex / raw decode below.
        self.dump_text.config(state="normal")
        self.dump_text.delete("1.0", "end")
        self.dump_text.insert("1.0", dpi.dump(pkt))
        self.dump_text.config(state="disabled")

    def _follow_stream(self):
        pkts = getattr(self, "_last_packets", None)
        if not pkts:
            self.insp_status.config(text="Capture some packets first, then select a TCP packet.")
            return
        sel = self.pkt_tree.selection()
        if not sel:
            self.insp_status.config(text="Select a TCP packet in the list to follow its stream.")
            return
        try:
            idx = int(self.pkt_tree.item(sel[0]).get("values", [None])[0])
        except (ValueError, TypeError):
            return
        if not (0 <= idx < len(pkts)):
            return
        res = stream_follow.follow(pkts, pkts[idx])
        if not res:
            self.insp_status.config(text="That packet isn't TCP - follow-stream works on TCP only.")
            return
        if not res["chunks"]:
            self.insp_status.config(
                text="TCP conversation found, but no payload was captured (only handshake/ACKs).")
            return
        self._show_stream(res)

    def _show_stream(self, res):
        c, s = res["client"], res["server"]
        win = tk.Toplevel(self.root)
        win.title(f"Follow TCP stream   {c[0]}:{c[1]}  <->  {s[0]}:{s[1]}")
        win.geometry("840x580")

        head = tk.Frame(win, bg=THEME_HEAD)
        head.pack(fill="x")
        tk.Label(head, bg=THEME_HEAD, fg=THEME_ACCENT, font=("Consolas", 9, "bold"),
                 text=(f"client {c[0]}:{c[1]}      server {s[0]}:{s[1]}      "
                       f"{res['packets']} pkts      "
                       f"{_human_bytes(res['bytes_c2s'])} sent  /  "
                       f"{_human_bytes(res['bytes_s2c'])} recv"),
                 anchor="w", padx=12, pady=7).pack(side="left")

        bar = tk.Frame(win, bg=THEME_PANEL)
        bar.pack(fill="x", side="bottom")
        state = {"hex": False}
        leg = tk.Label(bar, bg=THEME_PANEL, font=("Consolas", 8),
                       text="  amber = client \u2192 server     cyan = server \u2192 client",
                       fg=THEME_FG)
        leg.pack(side="left", padx=6, pady=5)
        tbtn = tk.Button(bar, text="Show hex")
        tbtn.pack(side="right", padx=6, pady=5)
        tk.Button(bar, text="Close", command=win.destroy).pack(side="right", pady=5)

        body = tk.Frame(win)
        body.pack(fill="both", expand=True)
        txt = tk.Text(body, bg="#0c1014", fg=THEME_FG, insertbackground=THEME_FG,
                      font=("Consolas", 9), wrap="none", padx=8, pady=6)
        sb = ttk.Scrollbar(body, orient="vertical", command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(side="left", fill="both", expand=True)
        txt.tag_configure("c2s", foreground="#ff9b3d")   # client -> server
        txt.tag_configure("s2c", foreground="#4dd2ff")   # server -> client
        txt.tag_configure("meta", foreground=THEME_MUTED)

        def render():
            txt.config(state="normal")
            txt.delete("1.0", "end")
            for direction, data in res["chunks"]:
                arrow = "client \u2192 server" if direction == "c2s" else "server \u2192 client"
                txt.insert("end", f"\u2500\u2500 {arrow}  ({len(data)} bytes) \u2500\u2500\n", ("meta",))
                rendered = stream_follow.hexdump(data) if state["hex"] else stream_follow.to_text(data)
                txt.insert("end", rendered + "\n\n", (direction,))
            txt.config(state="disabled")

        def toggle():
            state["hex"] = not state["hex"]
            tbtn.config(text="Show ASCII" if state["hex"] else "Show hex")
            render()

        tbtn.config(command=toggle)
        render()

    def _endpoint_intel(self, pkt):
        # Geo / ASN / reputation / hostname for the external side of the packet.
        if not pkt.haslayer("IP"):
            return []
        ext = None
        for cand in (pkt["IP"].src, pkt["IP"].dst):
            if threat_detection.classify_ip(cand) == "external":
                ext = cand
                break
        if not ext:
            return []
        info = geo_lookup.get(ext) or {}
        host = threat_detection.host_for(ext)
        verdict = threat_intel.is_bad(ext)
        rows = [("Remote IP", ext)]
        if host:
            rows.append(("Hostname", host))
        rows.append(("Reputation",
                     f"{verdict['category']} ({verdict['source']})" if verdict else "no known reputation"))
        if info.get("country"):
            rows.append(("Country", info.get("country")))
        if info.get("city"):
            rows.append(("City", info.get("city")))
        if info.get("isp"):
            rows.append(("ISP / org", info.get("isp")))
        if info.get("asn"):
            rows.append(("ASN", info.get("asn")))
        return rows

    def _packet_creds(self, pkt):
        # If this packet carries cleartext credentials, return anatomy rows.
        try:
            if not (pkt.haslayer("TCP") and pkt.haslayer("Raw")):
                return []
            tcp = pkt["TCP"]
            sport, dport = int(tcp.sport), int(tcp.dport)
            server_port = dport if dport in cred_sniffer.PLAINTEXT_PORTS else sport
            found = cred_sniffer.find_credentials(bytes(pkt["Raw"].load), server_port)
        except Exception:
            return []
        if not found:
            return []
        kind, detail = found
        return [("Exposure", kind), ("Credentials", detail),
                ("Advice", "This login is unencrypted - move the service to TLS.")]

    def _packet_cert(self, pkt):
        """(rows, has_problems) for a TLS certificate carried by this packet."""
        try:
            if not pkt.haslayer("Raw"):
                return [], False
            payload = bytes(pkt["Raw"].load)
        except Exception:
            return [], False
        if not tls_certs.has_certificate(payload):
            return [], False
        try:
            ders = tls_certs.certs_from_records(payload)
            if not ders:
                return [], False
            cert = tls_certs.parse_certificate(ders[0])
        except Exception:
            return [], False
        if not cert:
            return [], False
        rows = list(tls_certs.describe(cert))
        if len(ders) > 1:
            rows.append(("Chain", f"{len(ders)} certificates presented"))
        findings = tls_certs.analyze(cert)
        for severity, label, detail in findings:
            rows.append((f"[{severity}] {label}", detail))
        return rows, any(f[0] != "INFO" for f in findings)

    def _packet_protocol(self, pkt):
        """(rows, has_problems) - what protocol this really is, by its bytes."""
        try:
            if not pkt.haslayer("Raw"):
                return [], False
            payload = bytes(pkt["Raw"].load)
            if len(payload) < 8:
                return [], False
            if pkt.haslayer("TCP"):
                layer, transport = pkt["TCP"], "TCP"
            elif pkt.haslayer("UDP"):
                layer, transport = pkt["UDP"], "UDP"
            else:
                return [], False
            result = protocol_id.classify(payload, int(layer.sport), int(layer.dport), transport)
        except Exception:
            return [], False
        if not result.get("protocol") or result["protocol"] == "unknown":
            return [], False
        rows = list(protocol_id.describe(result))
        verdict = protocol_id.assess(result)
        if verdict:
            rows.append((f"[{verdict[0]}] assessment", verdict[1]))
        return rows, bool(verdict)

    def _render_anatomy(self, sections):
        self.anatomy_tree.delete(*self.anatomy_tree.get_children())
        for title, rows in sections:
            danger = "credentials" in title.lower() or "problems" in title.lower()
            parent = self.anatomy_tree.insert(
                "", "end", text=title, values=("",), open=True, tags=("section",))
            for k, v in rows:
                flag = (str(k).startswith("[")
                        or (danger and "credentials" in title.lower())
                        or (k in ("Notes", "Reputation") and "no known" not in str(v)))
                tag = "flag" if flag else ""
                self.anatomy_tree.insert(parent, "end", text=k, values=(str(v),),
                                         tags=(tag,) if tag else ())

    # ---------- inspection: report ----------

    def _generate_report(self):
        self.report_btn.config(state="disabled")
        self.insp_status.config(text="Generating report...")
        threading.Thread(target=self._report_worker, daemon=True).start()

    def _report_worker(self):
        try:
            incidents = db_manager.get_all_incidents()
            ext = threat_detection.external_endpoints()
            summary = threat_detection.traffic_summary()
            summary["by_country"] = geo_lookup.group_by_country(ext)
            top_ext = sorted(ext.items(), key=lambda kv: kv[1], reverse=True)[:10]
            summary["top_external"] = [
                (ip, cnt, geo_lookup.get(ip).get("country") or "?",
                 geo_lookup.get(ip).get("isp") or "",
                 geo_lookup.get(ip).get("asn") or "")
                for ip, cnt in top_ext
            ]
            proc = threat_detection._safe_copy(threat_detection.process_counts)
            summary["by_process"] = sorted(
                proc.items(), key=lambda kv: kv[1], reverse=True
            )[:10]

            alerts = [e for e in events.recent(limit=500)
                      if e["severity"] in ("ALERT", "WARNING")]

            report_generator.generate_pdf_report(
                incidents,
                traffic=summary,
                devices=db_manager.get_devices(),
                captures=db_manager.get_captures(),
                alerts=alerts,
                watchlist_rules=watchlist.rules(),
            )
            self.root.after(0, lambda: self.insp_status.config(text="Report saved to report.pdf"))
        except Exception as e:
            self.root.after(0, lambda e=e: self.insp_status.config(text=f"Report error: {e}"))
        self.root.after(0, lambda: self.report_btn.config(state="normal"))

    # ---------- shutdown ----------

    def _on_close(self):
        for stop in (
            lambda: self.sniffer.stop(),
            geo_lookup.stop_resolver,
            process_lookup.stop,
            threat_intel.stop,
            threat_detection.stop_analytics,
        ):
            try:
                stop()
            except Exception:
                pass
        # Persist anything that accumulates in memory between explicit saves.
        # Each of these writes on change too, but a clean shutdown should not
        # depend on the last mutation having happened to flush.
        for save in (asset_registry.save, allowlist.save, watchlist.save,
                     settings.save):
            try:
                save()
            except Exception:
                pass
        self.root.destroy()


def _apply_theme(root):
    """Neutral SOC / enterprise dark theme, applied across ttk, classic tk, and
    matplotlib charts. Flat slate surfaces, a single steel-blue accent, clean
    Segoe UI chrome with Consolas reserved for data."""
    BG, PANEL, HEAD = THEME_BG, THEME_PANEL, THEME_HEAD
    FG, ACCENT, SEL, BORDER = THEME_FG, THEME_ACCENT, THEME_SEL, THEME_BORDER
    BTN, BTN_BORDER = THEME_BTN, THEME_BTN_BORDER

    root.configure(bg=BG)

    # Classic (tk) widget defaults - applied to widgets built after this call.
    # Setting Button defaults here means every plain tk.Button across the app
    # picks up the themed look and hover states without per-widget styling.
    for opt, val in (
        ("*Listbox.background", PANEL), ("*Listbox.foreground", FG),
        ("*Listbox.selectBackground", SEL), ("*Listbox.selectForeground", THEME_GLOW),
        ("*Listbox.highlightThickness", 0), ("*Listbox.borderWidth", 0),
        ("*Listbox.font", f"{{{FONT_DATA}}} 9"),
        ("*Text.background", PANEL), ("*Text.foreground", FG),
        ("*Text.insertBackground", ACCENT), ("*Text.selectBackground", SEL),
        ("*Text.highlightThickness", 0), ("*Text.borderWidth", 0),
        ("*Toplevel.background", BG),
        ("*Label.background", BG), ("*Label.foreground", FG),
        ("*Label.font", f"{{{FONT_UI}}} 9"),
        ("*Canvas.highlightThickness", 0),
        # Classic tk.Button - flat, themed face, blue hover.
        ("*Button.background", BTN), ("*Button.foreground", FG),
        ("*Button.activeBackground", SEL), ("*Button.activeForeground", THEME_GLOW),
        ("*Button.relief", "flat"), ("*Button.borderWidth", 1),
        ("*Button.highlightThickness", 1), ("*Button.highlightBackground", BTN_BORDER),
        ("*Button.highlightColor", ACCENT), ("*Button.font", f"{{{FONT_UI}}} 9"),
        ("*Button.padX", 10), ("*Button.padY", 4), ("*Button.cursor", "hand2"),
        ("*Menu.background", PANEL), ("*Menu.foreground", FG),
        ("*Menu.activeBackground", SEL), ("*Menu.activeForeground", THEME_GLOW),
        ("*Menu.borderWidth", 0), ("*Menu.font", f"{{{FONT_UI}}} 9"),
    ):
        root.option_add(opt, val)

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                    bordercolor=BORDER, lightcolor=PANEL, darkcolor=BG,
                    troughcolor=HEAD, focuscolor=BORDER)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=(FONT_UI, 9))
    style.configure("TLabelframe", background=BG, bordercolor=BORDER, relief="solid",
                    borderwidth=1)
    style.configure("TLabelframe.Label", background=BG, foreground=THEME_MUTED,
                    font=(FONT_HEAD, 9))
    # Buttons: flat outline style with a steel-blue hover.
    style.configure("TButton", background=BTN, foreground=FG, bordercolor=BTN_BORDER,
                    relief="flat", padding=(12, 5), font=(FONT_UI, 9))
    style.map("TButton",
              background=[("active", SEL), ("pressed", SEL)],
              foreground=[("active", THEME_GLOW)],
              bordercolor=[("active", ACCENT)])
    # A primary (accent) button variant for the main action on a screen.
    style.configure("Accent.TButton", background=ACCENT, foreground=THEME_HEAD,
                    bordercolor=ACCENT, relief="flat", padding=(12, 5),
                    font=(FONT_HEAD, 9))
    style.map("Accent.TButton", background=[("active", THEME_GLOW), ("pressed", THEME_GLOW)],
              foreground=[("active", THEME_HEAD)])
    style.configure("TNotebook", background=BG, bordercolor=BORDER, tabmargins=(2, 4, 2, 0))
    style.configure("TNotebook.Tab", background=BG, foreground=THEME_MUTED,
                    padding=(14, 7), bordercolor=BG, font=(FONT_UI, 9))
    # Selected tab: no heavy fill, just accent text + an underline via border.
    style.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", ACCENT), ("active", FG)],
              bordercolor=[("selected", ACCENT)])
    style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                    foreground=FG, bordercolor=BORDER, borderwidth=0, rowheight=24,
                    font=(FONT_DATA, 9))
    style.configure("Treeview.Heading", background=HEAD, foreground=THEME_MUTED,
                    relief="flat", font=(FONT_UI, 9), padding=(6, 4))
    style.map("Treeview", background=[("selected", SEL)],
              foreground=[("selected", THEME_GLOW)])
    style.map("Treeview.Heading", background=[("active", PANEL)],
              foreground=[("active", ACCENT)])
    style.configure("TCombobox", fieldbackground=PANEL, background=PANEL,
                    foreground=FG, arrowcolor=ACCENT, bordercolor=BORDER,
                    padding=(6, 3))
    style.map("TCombobox", fieldbackground=[("readonly", PANEL)],
              foreground=[("readonly", FG)], bordercolor=[("focus", ACCENT)])
    style.configure("TEntry", fieldbackground=PANEL, foreground=FG,
                    insertcolor=ACCENT, bordercolor=BORDER, padding=(6, 4))
    style.map("TEntry", bordercolor=[("focus", ACCENT)])
    style.configure("TCheckbutton", background=BG, foreground=FG, font=(FONT_UI, 9))
    style.map("TCheckbutton", foreground=[("active", ACCENT)])
    style.configure("TPanedwindow", background=BG)
    for sb in ("Vertical.TScrollbar", "Horizontal.TScrollbar"):
        style.configure(sb, background=PANEL, troughcolor=BG,
                        arrowcolor=THEME_MUTED, bordercolor=BG, relief="flat")
        style.map(sb, background=[("active", BTN_BORDER)])

    # Charts: rcParams persist across ax.clear() so refreshes stay themed.
    try:
        import matplotlib
        matplotlib.rcParams.update({
            "figure.facecolor": BG, "axes.facecolor": PANEL, "savefig.facecolor": BG,
            "figure.edgecolor": BG, "text.color": FG, "axes.labelcolor": THEME_MUTED,
            "axes.titlecolor": FG, "xtick.color": THEME_MUTED, "ytick.color": THEME_MUTED,
            "axes.edgecolor": BORDER, "grid.color": BORDER, "font.family": "sans-serif",
            "font.sans-serif": ["Segoe UI", "DejaVu Sans"],
        })
    except Exception:
        pass


def main():
    root = tk.Tk()
    _apply_theme(root)
    SentinelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
