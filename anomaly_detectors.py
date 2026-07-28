# anomaly_detectors.py
#
# Defensive detectors that run on the live capture, in addition to the
# port-scan detector. Each one watches for an attack signature and reports
# to the event bus when it fires. process(packet) is called per packet.
import threading
import time
from collections import defaultdict

import events
import dns_analyzer

# --- tunable thresholds ---
PING_SWEEP_HOSTS = 15     # distinct hosts pinged by one source within the window
SWEEP_WINDOW = 60
SYN_FLOOD_COUNT = 200     # SYNs to one target:port within the window
FLOOD_WINDOW = 10

# Hosts whose normal job looks exactly like an attack. A default gateway ARPs
# and probes every address on the subnet (indistinguishable from a ping sweep)
# and relays every host's traffic (indistinguishable from a flood), so leaving it
# in guarantees permanent false positives. Excluding it is the correct fix -
# raising the thresholds high enough to silence a router would also blind the
# detectors to a genuine sweep or flood.
#
# Populated by the app at startup (network_discovery.default_gateway()); kept as
# injected state rather than an import so this module stays cycle-free.
INFRASTRUCTURE = set()


def set_infrastructure(ips):
    """Register hosts to exempt from sweep/flood detection (e.g. the gateway)."""
    INFRASTRUCTURE.clear()
    for ip in ips or []:
        if ip:
            INFRASTRUCTURE.add(str(ip))
    return set(INFRASTRUCTURE)

_lock = threading.Lock()

# ICMP ping sweep: src -> {dst_ip: last_seen}
_icmp_targets = defaultdict(dict)
_swept = set()

# SYN flood: (dst_ip, dst_port) -> [timestamps]
_syn_times = defaultdict(list)
_flooded = set()

# ARP table: ip -> mac (baseline), plus alerts already raised
_arp_table = {}
_arp_alerted = set()

# DNS zone transfers already reported
_axfr_alerted = set()


def process(packet):
    # Run every detector; never let one failure stop the others.
    for check in (_check_icmp_sweep, _check_syn_flood, _check_arp,
                  _check_dns_axfr, _check_dns_analysis):
        try:
            check(packet)
        except Exception:
            pass


def _check_icmp_sweep(packet):
    if not (packet.haslayer("ICMP") and packet.haslayer("IP")):
        return
    if int(getattr(packet["ICMP"], "type", -1)) != 8:  # echo request only
        return
    src = packet["IP"].src
    dst = packet["IP"].dst
    now = time.time()
    with _lock:
        targets = _icmp_targets[src]
        targets[dst] = now
        cutoff = now - SWEEP_WINDOW
        for ip in [k for k, t in targets.items() if t < cutoff]:
            del targets[ip]
        if (len(targets) >= PING_SWEEP_HOSTS and src not in _swept
                and src not in INFRASTRUCTURE):
            _swept.add(src)
            events.log_event(
                "ALERT", "sweep", src,
                f"Possible ICMP ping sweep: {src} pinged {len(targets)} "
                f"hosts in <= {SWEEP_WINDOW}s",
            )


def _check_syn_flood(packet):
    if not (packet.haslayer("TCP") and packet.haslayer("IP")):
        return
    flags = int(packet["TCP"].flags)
    if not ((flags & 0x02) and not (flags & 0x10)):  # SYN, not ACK
        return
    key = (packet["IP"].dst, int(packet["TCP"].dport))
    now = time.time()
    with _lock:
        times = _syn_times[key]
        times.append(now)
        cutoff = now - FLOOD_WINDOW
        while times and times[0] < cutoff:
            times.pop(0)
        if (len(times) >= SYN_FLOOD_COUNT and key not in _flooded
                and key[0] not in INFRASTRUCTURE):
            _flooded.add(key)
            events.log_event(
                "ALERT", "flood", key[0],
                f"Possible SYN flood: {len(times)} SYNs to {key[0]}:{key[1]} "
                f"in <= {FLOOD_WINDOW}s",
            )


def _check_arp(packet):
    if not packet.haslayer("ARP"):
        return
    arp = packet["ARP"]
    if int(getattr(arp, "op", 0)) != 2:  # replies (is-at) announce IP->MAC
        return
    ip, mac = arp.psrc, arp.hwsrc
    if not ip or not mac:
        return
    with _lock:
        known = _arp_table.get(ip)
        if known is None:
            _arp_table[ip] = mac
        elif known != mac and (ip, mac) not in _arp_alerted:
            _arp_alerted.add((ip, mac))
            _arp_table[ip] = mac
            events.log_event(
                "WARNING", "arp", ip,
                f"ARP change: {ip} now claims {mac} (was {known}) - possible spoofing",
            )


def _check_dns_axfr(packet):
    if not packet.haslayer("DNS"):
        return
    d = packet["DNS"]
    if int(getattr(d, "qr", 1)) != 0:  # queries only
        return
    qd = getattr(d, "qd", None)
    if qd is None:
        return
    qtype = int(getattr(qd, "qtype", 0))
    if qtype not in (252, 251):  # AXFR / IXFR
        return
    src = packet["IP"].src if packet.haslayer("IP") else "?"
    dst = packet["IP"].dst if packet.haslayer("IP") else "?"
    if (src, dst) in _axfr_alerted:
        return
    _axfr_alerted.add((src, dst))
    name = getattr(qd, "qname", b"")
    if isinstance(name, bytes):
        name = name.decode(errors="replace")
    kind = "AXFR" if qtype == 252 else "IXFR"
    events.log_event(
        "ALERT", "dns", src,
        f"DNS zone-transfer attempt ({kind}) {src} -> {dst} for {name}",
    )


def _check_dns_analysis(packet):
    # Feed DNS names into the tunneling / DGA analyzer.
    if not packet.haslayer("DNS"):
        return
    d = packet["DNS"]
    qd = getattr(d, "qd", None)
    if qd is None:
        return
    name = getattr(qd, "qname", b"")
    if isinstance(name, bytes):
        name = name.decode(errors="replace")
    if not name:
        return
    if int(getattr(d, "qr", 0)) == 0:                 # query
        dns_analyzer.observe_query(name, int(getattr(qd, "qtype", 0)))
    else:                                             # response
        dns_analyzer.observe_response(name, int(getattr(d, "rcode", 0)) == 3)
