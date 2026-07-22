# scan_detector.py
#
# Lightweight port-scan detector.
#
# It watches TCP connection attempts (SYN packets) and flags any single
# source that probes many different destination ports on the same target
# within a short time window -- the classic signature of a vertical port
# scan. Only SYN-without-ACK packets are counted, so ordinary return
# traffic and normal browsing (one service port per server) won't trip it.
import threading
import time

import events

WINDOW_SECONDS = 60        # how recent a probe must be to still count
PORT_SCAN_THRESHOLD = 25   # distinct ports to one target before we alert

_lock = threading.Lock()
_pair_ports = {}        # (src, dst) -> {dport: last_seen_ts}
_alerts = []            # all detected scans (dicts)
_alerted_pairs = set()  # pairs we've already alerted on
_new_alerts = []        # alerts not yet shown live
_record_count = 0


def _sweep(now):
    # Drop stale ports and empty pairs to keep memory bounded.
    cutoff = now - WINDOW_SECONDS
    for key in list(_pair_ports.keys()):
        ports = _pair_ports[key]
        for p in [p for p, ts in ports.items() if ts < cutoff]:
            del ports[p]
        if not ports:
            del _pair_ports[key]


def record(src, dst, dport, proto="TCP"):
    global _record_count
    now = time.time()
    key = (src, dst)
    with _lock:
        _record_count += 1
        if _record_count % 500 == 0:
            _sweep(now)

        ports = _pair_ports.setdefault(key, {})
        ports[dport] = now

        # Prune this pair's stale ports before counting.
        cutoff = now - WINDOW_SECONDS
        for p in [p for p, ts in ports.items() if ts < cutoff]:
            del ports[p]

        distinct = len(ports)

        if distinct >= PORT_SCAN_THRESHOLD and key not in _alerted_pairs:
            _alerted_pairs.add(key)
            alert = {
                "src": src,
                "dst": dst,
                "proto": proto,
                "port_count": distinct,
                "ports_sample": sorted(ports.keys())[:15],
                "first_seen": now,
                "last_seen": now,
            }
            _alerts.append(alert)
            _new_alerts.append(alert)
            print(
                f"[ALERT] Possible port scan: {src} -> {dst} "
                f"({distinct} ports in <= {WINDOW_SECONDS}s)"
            )
            try:
                events.log_event(
                    "ALERT", "scan", src,
                    f"Possible port scan: {src} -> {dst} "
                    f"({distinct} ports in <= {WINDOW_SECONDS}s)",
                )
            except Exception:
                pass
        elif key in _alerted_pairs:
            # Keep the existing alert's stats fresh.
            for a in _alerts:
                if a["src"] == src and a["dst"] == dst:
                    a["last_seen"] = now
                    a["port_count"] = max(a["port_count"], distinct)
                    a["ports_sample"] = sorted(ports.keys())[:15]
                    break


def get_alerts():
    with _lock:
        return [dict(a) for a in _alerts]


def drain_new_alerts():
    # Alerts that haven't been shown live yet (clears the queue).
    with _lock:
        out = list(_new_alerts)
        _new_alerts.clear()
        return out


def active_alert_count():
    with _lock:
        return len(_alerts)
