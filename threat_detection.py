import ipaddress
import time
import threading
from collections import defaultdict, deque

from scapy.all import sniff, AsyncSniffer

import scan_detector
import process_lookup
import anomaly_detectors
import threat_intel
import dpi
import events
import lan_monitor
import dhcp_monitor
import ja3_intel
import tls_certs
import dns_log
import protocol_id
import http_log
import flow_tracker
import flow_analytics
import os_fingerprint
import rtt_tracker
import novelty
import cred_sniffer

# Endpoints already announced as known-bad (so we alert once per IP).
_intel_alerted = set()

# Protocol tally (kept from before).
times_found_dict = {}

# Where traffic is coming from / going to.
source_counts = defaultdict(int)   # source IP -> packet count
dest_counts = defaultdict(int)     # destination IP -> packet count
process_counts = defaultdict(int)  # application name -> packet count

# Rich per-endpoint detail (keyed by the EXTERNAL ip), and a passive
# DNS map so an answered IP shows the hostname it resolved from.
endpoint_stats = {}   # ext_ip -> {packets, bytes, apps, ports, protos, first, last}
host_fingerprints = {}   # ip -> {os, family, confidence, hops, detail, last}
# Bounded ring of recent raw packets for on-demand PCAP export of a connection.
# Kept small so memory stays flat; only the last few thousand packets are held.
_pkt_ring = deque(maxlen=6000)   # (ts, src_ip, dst_ip, packet)
_pkt_ring_lock = threading.Lock()
host_by_ip = {}       # ip -> hostname (learned from DNS answers)
flows = {}            # normalized 5-tuple -> per-connection record

# Live capture status (so the UI can show whether monitoring is really running).
_total_packets = 0
_total_bytes = 0
_last_packet_ts = 0.0


def capture_status():
    return {"packets": _total_packets, "bytes": _total_bytes, "last_ts": _last_packet_ts}


# JA3 fingerprints already alerted, so each (ip, ja3) fires only once.
_ja3_alerted = set()

# Cleartext credential exposures already alerted (ip, kind, detail).
_creds_alerted = set()


def _check_creds(ip, packet):
    # Flag credentials sent in the clear to/from a plaintext service.
    try:
        if not (packet.haslayer("TCP") and packet.haslayer("Raw")):
            return
        tcp = packet["TCP"]
        sport, dport = int(tcp.sport), int(tcp.dport)
    except Exception:
        return
    if sport not in cred_sniffer.PLAINTEXT_PORTS and dport not in cred_sniffer.PLAINTEXT_PORTS:
        return
    try:
        payload = bytes(packet["Raw"].load)
    except Exception:
        return
    server_port = dport if dport in cred_sniffer.PLAINTEXT_PORTS else sport
    found = cred_sniffer.find_credentials(payload, server_port)
    if not found:
        return
    kind, detail = found
    key = (ip, kind, detail)
    if key not in _creds_alerted:
        _creds_alerted.add(key)
        events.log_event("ALERT", "creds", ip,
                         f"Cleartext credentials to {ip}:{server_port} - {kind}: {detail}")


def _check_ja3(ip, ja3):
    if not ja3:
        return
    hit = ja3_intel.is_bad(ja3)
    if hit and (ip, ja3) not in _ja3_alerted:
        _ja3_alerted.add((ip, ja3))
        events.log_event("ALERT", "ja3", ip,
                         f"Malicious TLS fingerprint: {ip} JA3 {ja3} matches '{hit}'")


# Certificate problems already reported, keyed (ip, serial, label).
_cert_alerted = set()


def _check_cert(ip, packet, rec=None):
    """Parse a server certificate out of a TLS handshake and flag problems.

    Only sees TLS 1.2 and below - TLS 1.3 encrypts the Certificate message, so a
    1.3 handshake yields nothing here. The Network tab's active fetch covers that.
    """
    try:
        if not packet.haslayer("Raw"):
            return
        payload = bytes(packet["Raw"].load)
    except Exception:
        return
    if not tls_certs.has_certificate(payload):
        return
    try:
        ders = tls_certs.certs_from_records(payload)
    except Exception:
        return
    if not ders:
        return
    cert = tls_certs.parse_certificate(ders[0])          # the leaf comes first
    if not cert:
        return
    if rec is not None:
        rec["cert"] = cert

    # Judge the certificate against the SNI the client actually asked for.
    hostname = None
    if rec:
        names = rec.get("sni") or set()
        if len(names) == 1:
            hostname = next(iter(names))
    try:
        findings = tls_certs.analyze(cert, hostname=hostname)
    except Exception:
        return
    for severity, label, detail in findings:
        if severity == "INFO":
            continue
        key = (ip, cert.get("serial", ""), label)
        if key in _cert_alerted:
            continue
        _cert_alerted.add(key)
        subject = (cert.get("subject") or {}).get("CN") or "?"
        events.log_event(severity, "cert", ip,
                         f"TLS certificate ({subject}) - {label}: {detail}")


# Domains already reported as resolving to a known-bad IP.
_dns_intel_alerted = set()


def _log_dns(src, dst, sport, dport, packet):
    """Log a DNS transaction, learn IP -> name, and flag bad resolutions."""
    try:
        if not packet.haslayer("UDP"):
            return
        payload = bytes(packet["UDP"].payload)
    except Exception:
        return
    if not payload:
        return
    try:
        tx = dns_log.observe(src, dst, sport, dport, payload)
    except Exception:
        return
    if not tx:
        return
    name = (tx.get("name") or "").rstrip(".")
    for ip in tx.get("ips") or []:
        if name:
            host_by_ip[ip] = name          # keeps host_for() / dossiers working
            try:
                flow_tracker.set_host(ip, name)   # label flows to this IP
            except Exception:
                pass
        try:
            verdict = threat_intel.is_bad(ip)
        except Exception:
            verdict = None
        if verdict and (name, ip) not in _dns_intel_alerted:
            _dns_intel_alerted.add((name, ip))
            events.log_event(
                "ALERT", "intel", ip,
                f"DNS: {name} resolved to known-bad {ip} "
                f"({verdict.get('category', '?')} / {verdict.get('source', '?')})")


# Protocol/port mismatches already reported, keyed (ip, protocol, port).
_proto_alerted = set()


def _check_protocol(ip, packet, rec=None):
    """Identify the protocol from the payload bytes and flag it if it's turned
    up somewhere it shouldn't be (SSH on 443, a tunnel on 53, and so on)."""
    try:
        if not packet.haslayer("Raw"):
            return
        payload = bytes(packet["Raw"].load)
        if len(payload) < 8:
            return
        if packet.haslayer("TCP"):
            layer, transport = packet["TCP"], "TCP"
        elif packet.haslayer("UDP"):
            layer, transport = packet["UDP"], "UDP"
        else:
            return
        sport, dport = int(layer.sport), int(layer.dport)
    except Exception:
        return
    try:
        result = protocol_id.classify(payload, sport, dport, transport)
    except Exception:
        return
    proto = result.get("protocol")
    if not proto or proto == "unknown":
        return

    if rec is not None:
        rec.setdefault("protocols", set())
        if len(rec["protocols"]) < 8:
            rec["protocols"].add(proto)
        rec["_dpi_proto"] = proto

    verdict = protocol_id.assess(result)
    if not verdict:
        return
    severity, message = verdict
    key = (ip, proto, result.get("port"))
    if key in _proto_alerted:
        return
    _proto_alerted.add(key)
    events.log_event(severity, "protocol", ip, f"{ip}: {message}")


# HTTP transactions already flagged, keyed (client, url, flag-message).
_http_alerted = set()


def _log_http(src, dst, packet):
    """Reconstruct an HTTP transaction and flag anything notable."""
    try:
        if not (packet.haslayer("TCP") and packet.haslayer("Raw")):
            return
        tcp = packet["TCP"]
        sport, dport = int(tcp.sport), int(tcp.dport)
        payload = bytes(packet["Raw"].load)
    except Exception:
        return
    if not payload:
        return
    try:
        tx = http_log.observe(src, dst, sport, dport, payload)
    except Exception:
        return
    # Flags land on both the request (logged immediately) and the completed
    # transaction; alert from whichever we can see, deduped.
    row = tx
    if row is None:
        try:
            recents = http_log.recent(limit=1)
        except Exception:
            recents = []
        row = recents[-1] if recents else None
    if not row or not row.get("flags"):
        return
    client = row.get("client", src)
    url = row.get("url", "")
    for severity, message in row["flags"]:
        if severity == "INFO":
            continue
        key = (client, url, message)
        if key in _http_alerted:
            continue
        _http_alerted.add(key)
        where = url or row.get("host", "") or dst
        events.log_event(severity, "http", client, f"{message}  -  {row.get('method', '')} {where}")


def replay_detectors(packets):
    """Run ONLY the anomaly + port-scan detectors over a list of packets (an
    imported pcap), so detections surface to the events bus *without* touching
    the live endpoint / flow / map state. Returns the count processed.

    Note: the detectors judge timing by wall-clock, so a replayed capture is
    evaluated as if it arrived now -- a scan or sweep in the file will trip its
    alert, but an extremely bursty benign capture could read as one too.
    """
    n = 0
    for packet in packets:
        n += 1
        try:
            anomaly_detectors.process(packet)
        except Exception:
            pass
        try:
            if packet.haslayer("TCP") and packet.haslayer("IP"):
                tcp = packet["TCP"]
                flags = int(tcp.flags)
                if (flags & 0x02) and not (flags & 0x10):   # SYN, not ACK
                    ipl = packet["IP"]
                    scan_detector.record(ipl.src, ipl.dst, int(tcp.dport), "TCP")
        except Exception:
            pass
    return n

PROTOCOL_LOOKUP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    89: "OSPF",
    132: "SCTP",
}


def classify_ip(ip):
    # Bucket an IP into a coarse "where from" group.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private or addr.is_link_local:
        return "local"
    return "external"


def increment_or_add_to_dict(protocol):
    if protocol in times_found_dict:
        times_found_dict[protocol] += 1
    else:
        times_found_dict[protocol] = 1


_LAN_SVC_PORTS = {5353, 1900, 67, 68, 137}


def _lan_observe(packet):
    # ARP tells us ip<->mac for hosts on the segment.
    if packet.haslayer("ARP"):
        try:
            arp = packet["ARP"]
            if arp.psrc and arp.hwsrc:
                lan_monitor.note_arp(arp.psrc, arp.hwsrc)
        except Exception:
            pass
        return
    # Broadcast/multicast service announcements let us fingerprint devices.
    if not (packet.haslayer("UDP") and packet.haslayer("IP")):
        return
    try:
        udp = packet["UDP"]
        sport, dport = int(udp.sport), int(udp.dport)
    except Exception:
        return
    if sport not in _LAN_SVC_PORTS and dport not in _LAN_SVC_PORTS:
        return
    try:
        src_ip = packet["IP"].src
        src_mac = packet["Ether"].src if packet.haslayer("Ether") else ""
        payload = bytes(udp.payload)
    except Exception:
        return
    lan_monitor.observe(src_ip, src_mac, sport, dport, payload)
    if sport == 67 or dport == 67:
        dhcp_monitor.observe(src_ip, src_mac, sport, dport, payload)


def packet_callback(packet):
    # Heartbeat for the monitoring-status indicator.
    global _total_packets, _last_packet_ts, _total_bytes
    _total_packets += 1
    _last_packet_ts = time.time()
    try:
        _total_bytes += len(packet)
    except Exception:
        pass

    # Run the defensive detectors first (they handle ARP, ICMP, DNS, etc.).
    anomaly_detectors.process(packet)

    # Passive LAN inventory: learn hosts from ARP and broadcast service chatter.
    try:
        _lan_observe(packet)
    except Exception:
        pass

    if packet.haslayer("IP"):
        ip_layer = packet["IP"]

        # Retain the raw packet briefly so a connection can be exported to PCAP.
        try:
            _pkt_ring.append((time.time(), ip_layer.src, ip_layer.dst, packet))
        except Exception:
            pass

        protocol_num = ip_layer.proto
        packet_protocol = PROTOCOL_LOOKUP.get(protocol_num, str(protocol_num))
        increment_or_add_to_dict(packet_protocol)

        # Record both ends of the conversation.
        source_counts[ip_layer.src] += 1
        dest_counts[ip_layer.dst] += 1

        # Extract transport ports (TCP or UDP) for scan detection + attribution.
        sport = dport = None
        is_syn = False
        tcp_flags = None
        if packet.haslayer("TCP"):
            try:
                tcp = packet["TCP"]
                sport, dport = int(tcp.sport), int(tcp.dport)
                # Feed the port-scan detector with connection attempts only
                # (SYN set, ACK not set); replies and established flows are
                # ignored, so normal browsing doesn't look like a scan.
                flags = int(tcp.flags)
                tcp_flags = flags
                if (flags & 0x02) and not (flags & 0x10):
                    is_syn = True
                    scan_detector.record(ip_layer.src, ip_layer.dst, dport, "TCP")
                    # Passive OS fingerprint from the SYN (best effort).
                    try:
                        _capture_syn_fingerprint(packet, ip_layer, tcp)
                    except Exception:
                        pass
                    # Passive RTT: note the outbound SYN so we can time its reply.
                    if classify_ip(ip_layer.dst) == "external":
                        try:
                            rtt_tracker.note_syn(ip_layer.dst, dport)
                        except Exception:
                            pass
                elif (flags & 0x02) and (flags & 0x10):
                    # SYN-ACK coming back from a server we SYNed - one round trip.
                    if classify_ip(ip_layer.src) == "external":
                        try:
                            rtt_tracker.note_synack(ip_layer.src, sport)
                        except Exception:
                            pass
            except Exception:
                pass
        elif packet.haslayer("UDP"):
            try:
                udp = packet["UDP"]
                sport, dport = int(udp.sport), int(udp.dport)
                # Jitter: note arrivals from an external real-time UDP peer.
                if classify_ip(ip_layer.src) == "external":
                    try:
                        rtt_tracker.note_arrival(ip_layer.src)
                    except Exception:
                        pass
            except Exception:
                pass

        # Attribute this packet to the local application that owns the flow.
        proc = process_lookup.attribute(ip_layer.src, sport, ip_layer.dst, dport)
        process_counts[proc] += 1

        try:
            plen = len(packet)
        except Exception:
            plen = 0

        # Per-connection (5-tuple) flow tracking for the Connections view.
        if sport is not None and dport is not None:
            _record_flow(ip_layer.src, sport, ip_layer.dst, dport,
                         packet_protocol, plen, tcp_flags, proc, time.time())

        # Rich per-endpoint detail for the external side of the conversation.
        ext_ip = ext_port = None
        outbound = True
        if classify_ip(ip_layer.dst) == "external":
            ext_ip, ext_port, outbound = ip_layer.dst, dport, True     # we -> server
        elif classify_ip(ip_layer.src) == "external":
            ext_ip, ext_port, outbound = ip_layer.src, sport, False    # server -> we
        if ext_ip is not None:
            rec = endpoint_stats.get(ext_ip)
            now = time.time()
            if rec is None:
                rec = {
                    "packets": 0, "bytes": 0,
                    "in_bytes": 0, "out_bytes": 0, "in_pkts": 0, "out_pkts": 0,
                    "rate": 0.0, "conn_times": [], "sni": set(), "ja3": set(),
                    "apps": defaultdict(int), "ports": defaultdict(int),
                    "protos": defaultdict(int), "first": now, "last": now,
                }
                endpoint_stats[ext_ip] = rec
                # First time we've talked to this address - note it for novelty.
                try:
                    if novelty.observe("ip", ext_ip):
                        rec["is_new"] = True
                except Exception:
                    pass
            rec["packets"] += 1
            rec["bytes"] += plen
            if outbound:
                rec["out_bytes"] += plen
                rec["out_pkts"] += 1
            else:
                rec["in_bytes"] += plen
                rec["in_pkts"] += 1
            rec["last"] = now
            rec["apps"][proc] += 1
            rec["protos"][packet_protocol] += 1
            if ext_port is not None:
                rec["ports"][ext_port] += 1

            # Record outbound connection attempts for beaconing analysis.
            if is_syn and outbound:
                ct = rec["conn_times"]
                ct.append(now)
                if len(ct) > 40:
                    del ct[:-40]

            # Capture TLS SNI / JA3 (what this endpoint is actually talking).
            if dport == 443 or sport == 443:
                tls = dpi.tls_info(packet)
                if tls:
                    if tls.get("sni"):
                        rec.setdefault("sni", set())
                        if len(rec["sni"]) < 8:
                            rec["sni"].add(tls["sni"])
                    if tls.get("ja3"):
                        rec.setdefault("ja3", set())
                        if len(rec["ja3"]) < 5:
                            rec["ja3"].add(tls["ja3"])
                        _check_ja3(ext_ip, tls["ja3"])

                # Server certificate (TLS 1.2 and below; 1.3 encrypts it).
                _check_cert(ext_ip, packet, rec)

            # Cleartext credential exposure (defensive).
            _check_creds(ext_ip, packet)

            # What protocol is this actually, regardless of port?
            _check_protocol(ext_ip, packet, rec)

            # HTTP transaction logging (cleartext requests/responses).
            _log_http(ip_layer.src, ip_layer.dst, packet)

            # Session / flow record for this conversation. Direction is
            # normalised inside flow_tracker from the real src/dst.
            if sport is not None and dport is not None:
                try:
                    fkey = flow_tracker.update(
                        packet_protocol if packet_protocol in ("TCP", "UDP") else "TCP",
                        ip_layer.src, sport, ip_layer.dst, dport,
                        plen, tcp_flags or 0, rec.get("_dpi_proto", ""), now)
                    # Record arrival timing on this flow for beacon/RTP analysis.
                    flow_analytics.observe_gap(fkey, now)
                except Exception:
                    pass

            # Reputation check (memoized; fires an ALERT once per bad IP).
            verdict = threat_intel.is_bad(ext_ip)
            if verdict:
                rec["intel"] = verdict
                if ext_ip not in _intel_alerted:
                    _intel_alerted.add(ext_ip)
                    events.log_event(
                        "ALERT", "intel", ext_ip,
                        f"Known-bad endpoint {ext_ip} "
                        f"({verdict['category']} / {verdict['source']})",
                    )

        # DNS transaction log. This also learns the IP -> name mapping that
        # host_for() and the endpoint dossiers use, so it's the single DNS path.
        if sport == 53 or dport == 53:
            _log_dns(ip_layer.src, ip_layer.dst, sport, dport, packet)


def _safe_copy(d):
    # Copy a dict that a background thread may be mutating.
    for _ in range(5):
        try:
            return dict(d)
        except RuntimeError:
            continue
    return {}


def top_sources(n=10):
    # Busiest source IPs, highest first.
    return sorted(source_counts.items(), key=lambda kv: kv[1], reverse=True)[:n]


def group_by_scope(counts=None):
    # Total packets grouped into local / external / multicast / etc.
    counts = source_counts if counts is None else counts
    grouped = defaultdict(int)
    for ip, c in counts.items():
        grouped[classify_ip(ip)] += c
    return dict(grouped)


def external_endpoints():
    # External IPs seen as either source or destination, with combined
    # packet counts. These are the "remote ends" worth geolocating.
    combined = defaultdict(int)
    for d in (_safe_copy(source_counts), _safe_copy(dest_counts)):
        for ip, c in d.items():
            if classify_ip(ip) == "external":
                combined[ip] += c
    return dict(combined)


def host_for(ip):
    # Hostname this IP resolved from (passive DNS), or "".
    name = host_by_ip.get(ip, "")
    if not name:
        try:
            name = dns_log.name_for_ip(ip)
        except Exception:
            name = ""
    return name


def _capture_syn_fingerprint(packet, ip_layer, tcp):
    """Extract a passive OS fingerprint from a TCP SYN and store it per host."""
    src = ip_layer.src
    # Only fingerprint LAN hosts / the external side we can actually see SYN from.
    try:
        ttl = int(getattr(ip_layer, "ttl", 0)) or None
    except Exception:
        ttl = None
    try:
        window = int(getattr(tcp, "window", 0)) or None
    except Exception:
        window = None
    # TCP options: scapy exposes tcp.options as a list of (name, value) tuples.
    opts = []
    try:
        for o in (tcp.options or []):
            name = o[0] if isinstance(o, (tuple, list)) else o
            short = {"MSS": "MSS", "SAckOK": "SACK", "SAck": "SACK",
                     "Timestamp": "TS", "WScale": "WS", "NOP": "NOP",
                     "EOL": "EOL"}.get(str(name), str(name))
            opts.append(short)
    except Exception:
        opts = []
    df = None
    try:
        df = bool(int(getattr(ip_layer, "flags", 0)) & 0x2)
    except Exception:
        pass

    fp = os_fingerprint.fingerprint(ttl=ttl, window=window, options=opts, df=df)
    if fp.get("os") and fp["os"] != "unknown":
        prev = host_fingerprints.get(src)
        # Keep the highest-confidence reading we've seen for this host.
        if not prev or fp.get("confidence", 0) >= prev.get("confidence", 0):
            fp["last"] = time.time()
            host_fingerprints[src] = fp


def get_host_os(ip):
    """Return the stored OS fingerprint for a host, or None."""
    return host_fingerprints.get(ip)


def _record_flow(src, sport, dst, dport, proto, plen, tcp_flags, proc, now):
    # Track one connection (normalized so both directions share a key).
    a, b = (src, int(sport)), (dst, int(dport))
    ep1, ep2 = sorted([a, b])
    key = (proto, ep1, ep2)
    rec = flows.get(key)
    if rec is None:
        local = remote = None
        cs, cd = classify_ip(src), classify_ip(dst)
        if cs in ("local", "loopback") and cd == "external":
            local, remote = a, b
        elif cd in ("local", "loopback") and cs == "external":
            local, remote = b, a
        rec = {
            "proto": proto, "ep1": ep1, "ep2": ep2,
            "local": local, "remote": remote,
            "packets": 0, "bytes": 0, "out_bytes": 0, "in_bytes": 0,
            "first": now, "last": now, "app": proc, "state": "NEW",
        }
        flows[key] = rec
    rec["packets"] += 1
    rec["bytes"] += plen
    rec["last"] = now
    if proc and proc not in PSEUDO_APPS:
        rec["app"] = proc
    if rec["local"] is not None:
        if (src, int(sport)) == rec["local"]:
            rec["out_bytes"] += plen
        else:
            rec["in_bytes"] += plen
    # Coarse TCP state from flags (best effort).
    if proto == "TCP" and tcp_flags is not None:
        if tcp_flags & 0x04:        # RST
            rec["state"] = "RESET"
        elif tcp_flags & 0x01:      # FIN
            rec["state"] = "CLOSING"
        elif (tcp_flags & 0x02) and (tcp_flags & 0x10):  # SYN+ACK
            rec["state"] = "SYN_RECV"
        elif (tcp_flags & 0x02):    # SYN
            if rec["state"] == "NEW":
                rec["state"] = "SYN_SENT"
        elif (tcp_flags & 0x10):    # ACK / data
            if rec["state"] in ("NEW", "SYN_SENT", "SYN_RECV"):
                rec["state"] = "ESTABLISHED"
    elif proto == "UDP":
        rec["state"] = "ACTIVE"


def active_flows(limit=300):
    out = []
    for rec in list(flows.values()):
        out.append(dict(rec))
    out.sort(key=lambda r: r["last"], reverse=True)
    return out[:limit]


def export_flow_pcap(ip, path, peer=None, limit=5000):
    """Write the recently-retained packets involving `ip` to a .pcap file.

    Optionally restrict to packets also involving `peer`. Returns the number of
    packets written (0 if none retained / write failed).
    """
    with _pkt_ring_lock:
        snapshot = list(_pkt_ring)
    pkts = []
    for ts, src, dst, pkt in snapshot:
        if ip in (src, dst):
            if peer and peer not in (src, dst):
                continue
            pkts.append(pkt)
    pkts = pkts[-limit:]
    if not pkts:
        return 0
    try:
        import pcap_io
        pcap_io.write_pcap(path, pkts)
        return len(pkts)
    except Exception as exc:
        print("pcap export error:", exc)
        return 0


def retained_packet_count(ip=None):
    """How many retained packets we currently hold (optionally for one IP)."""
    with _pkt_ring_lock:
        snapshot = list(_pkt_ring)
    if ip is None:
        return len(snapshot)
    return sum(1 for _ts, s, d, _p in snapshot if ip in (s, d))


def endpoint_detail(ip):
    # Everything we know about one external endpoint, sorted for display.
    rec = endpoint_stats.get(ip)
    if not rec:
        return {}
    return {
        "packets": rec["packets"],
        "bytes": rec["bytes"],
        "in_bytes": rec.get("in_bytes", 0),
        "out_bytes": rec.get("out_bytes", 0),
        "rate": rec.get("rate", 0.0),
        "apps": sorted(rec["apps"].items(), key=lambda kv: kv[1], reverse=True),
        "ports": sorted(rec["ports"].items(), key=lambda kv: kv[1], reverse=True),
        "protos": sorted(rec["protos"].items(), key=lambda kv: kv[1], reverse=True),
        "first": rec["first"],
        "last": rec["last"],
        "intel": rec.get("intel"),
        "sni": sorted(rec.get("sni", [])),
        "ja3": sorted(rec.get("ja3", [])),
    }


# Buckets that aren't real applications (used to filter the app views).
PSEUDO_APPS = {"unknown", "other host", "no port (ICMP/etc.)", "n/a (install psutil)"}


# --- behavioural analytics (rate + exfil + beaconing) -----------------------
# Tunable thresholds.
EXFIL_BYTES = 100 * 1024 * 1024   # outbound volume to one endpoint to flag
EXFIL_RATIO = 3.0                 # outbound must dominate inbound this much
BEACON_MIN = 6                    # connection intervals required
BEACON_PERIOD_MIN = 2.0           # seconds; ignore rapid bursts
BEACON_CV = 0.15                  # max jitter (stdev/mean) to count as regular
FLOW_TTL = 120                    # seconds before an idle flow is dropped

_analytics_stop = threading.Event()
_rate_last = {}          # ip -> (ts, total_bytes)
_exfil_alerted = set()
_beacon_alerted = set()


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _check_beacon(ip, rec):
    if ip in _beacon_alerted:
        return
    times = list(rec.get("conn_times") or [])
    if len(times) < BEACON_MIN + 1:
        return
    deltas = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(deltas) < BEACON_MIN:
        return
    mean = sum(deltas) / len(deltas)
    if mean < BEACON_PERIOD_MIN:
        return
    var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
    cv = (var ** 0.5) / mean if mean else 1.0
    if cv < BEACON_CV:
        _beacon_alerted.add(ip)
        events.log_event(
            "ALERT", "beacon", ip,
            f"Possible beaconing to {ip}: {len(deltas) + 1} connections "
            f"~every {mean:.0f}s (jitter {cv * 100:.0f}%)",
        )


def _analytics_loop(interval):
    while not _analytics_stop.wait(interval):
        now = time.time()
        for ip in list(endpoint_stats.keys()):
            rec = endpoint_stats.get(ip)
            if not rec:
                continue
            # Live rate (bytes/sec over the last interval).
            tb = rec.get("bytes", 0)
            prev = _rate_last.get(ip)
            if prev and now > prev[0]:
                rec["rate"] = max(0.0, (tb - prev[1]) / (now - prev[0]))
            _rate_last[ip] = (now, tb)

            # Exfil: large, outbound-dominant transfer to a single endpoint.
            try:
                ob, ib = rec.get("out_bytes", 0), rec.get("in_bytes", 0)
                if ob >= EXFIL_BYTES and ob > ib * EXFIL_RATIO and ip not in _exfil_alerted:
                    _exfil_alerted.add(ip)
                    events.log_event(
                        "ALERT", "exfil", ip,
                        f"Large outbound transfer to {ip}: "
                        f"{_fmt_bytes(ob)} out / {_fmt_bytes(ib)} in",
                    )
            except Exception:
                pass

            # Beaconing: regularly-spaced outbound connections.
            try:
                _check_beacon(ip, rec)
            except Exception:
                pass

        # Drop idle connections so the Connections view stays current.
        for key in list(flows.keys()):
            fr = flows.get(key)
            if fr and now - fr["last"] > FLOW_TTL:
                del flows[key]

        # Per-flow behavioural analytics: beaconing, exfil and RTP at the
        # conversation level (catches what endpoint aggregation misses).
        try:
            snaps = flow_tracker.flows(limit=600, sort="last")
            keys = [(f["proto"], min((f["src"], f["sport"]), (f["dst"], f["dport"])),
                     max((f["src"], f["sport"]), (f["dst"], f["dport"]))) for f in snaps]
            for src, sev, cat, msg in flow_analytics.sweep(snaps, keyed=keys):
                events.log_event(sev, cat, src, msg)
            flow_analytics.expire(set(keys), now)
        except Exception:
            pass


def start_analytics(interval=1.0):
    _analytics_stop.clear()
    threading.Thread(target=_analytics_loop, args=(interval,), daemon=True).start()


def stop_analytics():
    _analytics_stop.set()


def app_names():
    # Real application names we've attributed traffic to.
    names = set(_safe_copy(process_counts).keys())
    for rec in list(endpoint_stats.values()):
        try:
            names.update(rec["apps"].keys())
        except RuntimeError:
            pass
    return sorted(n for n in names if n not in PSEUDO_APPS)


def endpoints_for_app(app):
    # Every external endpoint a given application talks to, with detail.
    out = []
    for ip in list(endpoint_stats.keys()):
        rec = endpoint_stats.get(ip)
        if not rec:
            continue
        try:
            apps = dict(rec["apps"])
            ports = dict(rec["ports"])
            protos = dict(rec["protos"])
            nbytes = rec["bytes"]
        except RuntimeError:
            continue
        n = apps.get(app, 0)
        if n > 0:
            out.append({
                "ip": ip,
                "host": host_by_ip.get(ip, ""),
                "packets": n,
                "bytes": nbytes,
                "ports": sorted(ports.items(), key=lambda kv: kv[1], reverse=True),
                "protos": sorted(protos.items(), key=lambda kv: kv[1], reverse=True),
            })
    out.sort(key=lambda d: d["packets"], reverse=True)
    return out


def process_map(app, *, geo_lookup=None, dns_log=None, flow_tracker=None,
                flow_analytics=None, service_roles=None):
    """Assemble every endpoint a process talks to and classify each by role.

    Modules are injected so this stays testable and cycle-free. Returns a list of
    classified endpoint dicts (ip, host, role, confidence, reasons, bytes, ...),
    sorted by traffic. The app passes the real modules.
    """
    out = []
    for ip in list(endpoint_stats.keys()):
        rec = endpoint_stats.get(ip)
        if not rec:
            continue
        try:
            apps = dict(rec["apps"])
        except RuntimeError:
            continue
        if apps.get(app, 0) <= 0:
            continue

        ports = sorted(dict(rec["ports"]).items(), key=lambda kv: kv[1], reverse=True)
        protos = sorted(dict(rec["protos"]).items(), key=lambda kv: kv[1], reverse=True)
        inb, outb = rec.get("in_bytes", 0), rec.get("out_bytes", 0)
        pkts = rec.get("packets", 0)
        host = host_for(ip) or (dns_log.name_for_ip(ip) if dns_log else "") or ""
        sni = sorted(rec.get("sni", []))
        mean_len = (rec.get("bytes", 0) / pkts) if pkts else None

        # Geo / ASN.
        asn = isp = ""
        if geo_lookup is not None:
            try:
                g = geo_lookup.get(ip) or {}
                asn, isp = g.get("asn", ""), g.get("isp", "")
            except Exception:
                pass

        # Did any flow to this IP look like an RTP media stream?
        is_rtp = False
        if flow_tracker is not None and flow_analytics is not None:
            try:
                for f in (flow_tracker.flows(500, "bytes") or []):
                    if ip in (f.get("src"), f.get("dst")):
                        verdict = flow_analytics.analyze_flow(f)
                        if verdict and "RTP" in (verdict[2] if len(verdict) > 2 else ""):
                            is_rtp = True
                            break
            except Exception:
                pass

        ep = {
            "ip": ip, "host": host, "sni": sni, "ports": ports, "protos": protos,
            "app_proto": rec.get("_dpi_proto", ""), "in_bytes": inb, "out_bytes": outb,
            "packets": pkts, "rate": rec.get("rate", 0.0), "mean_len": mean_len,
            "asn": asn, "isp": isp, "is_rtp": is_rtp,
        }
        if service_roles is not None:
            verdict = service_roles.classify(ep)
            ep.update(role=verdict["role"], confidence=verdict["confidence"],
                      reasons=verdict["reasons"])
        out.append(ep)

    out.sort(key=lambda d: d["in_bytes"] + d["out_bytes"], reverse=True)
    return out


def traffic_summary(top_n=10):
    return {
        "protocols": dict(times_found_dict),
        "top_sources": top_sources(top_n),
        "by_scope": group_by_scope(source_counts),
        "total_packets": sum(source_counts.values()),
        "unique_sources": len(source_counts),
    }


def start_async_monitor(iface=None):
    # Non-blocking capture on a background thread; keeps the counters
    # above updated until the returned sniffer is stopped. We capture IP
    # and ARP ("ip or arp") so the ARP-spoof detector can see replies.
    sniffer = AsyncSniffer(prn=packet_callback, filter="ip or arp", store=False, iface=iface)
    sniffer.start()
    return sniffer


def list_interfaces():
    """Return capture interfaces as [{'id', 'name', 'ip'}]. `id` is what to pass
    to start_async_monitor(iface=...). Falls back gracefully across scapy versions."""
    out = []
    try:
        from scapy.interfaces import get_working_ifaces
        for iface in get_working_ifaces():
            name = getattr(iface, "name", None)
            if not name:
                continue
            desc = getattr(iface, "description", None) or name
            out.append({"id": name, "name": desc, "ip": getattr(iface, "ip", None)})
    except Exception:
        pass
    if not out:
        try:
            from scapy.arch import get_if_list
            for n in get_if_list():
                out.append({"id": n, "name": n, "ip": None})
        except Exception:
            pass
    return out


def start_network_monitor(count=10):
    # Original one-shot, blocking capture. Kept for non-live use.
    capture = sniff(count=count, prn=packet_callback, filter="ip")
    capture.summary()
    print(times_found_dict)
