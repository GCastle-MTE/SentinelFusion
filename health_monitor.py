"""Health / self-monitoring - is the sensor itself healthy?

A monitoring tool that silently stops capturing is worse than none - the operator
thinks they're covered when they aren't. This panel watches the watcher: capture
throughput, whether packets are still arriving, how big the in-memory buffers and
the on-disk database have grown, and whether each subsystem is responding. It's
the "is the light still green" view every operations console has.

Signals are pulled from the live engine and modules; everything is best-effort so
a missing subsystem degrades to "unknown" rather than breaking the panel. Modules
are injected/imported lazily to avoid hard coupling.
"""

import os
import time

_start_time = time.time()
_rate_window = []      # (ts, total_packets) samples for rate calculation


def uptime_sec():
    return time.time() - _start_time


def capture_rate(threat_detection):
    """Packets/sec over the last sample interval, plus liveness."""
    try:
        counters = threat_detection.get_counters() if hasattr(threat_detection, "get_counters") \
            else {"packets": getattr(threat_detection, "_total_packets", 0),
                  "last_ts": getattr(threat_detection, "_last_packet_ts", 0.0)}
    except Exception:
        counters = {"packets": 0, "last_ts": 0.0}
    now = time.time()
    total = counters.get("packets", 0)
    _rate_window.append((now, total))
    # keep ~15s of samples
    while len(_rate_window) > 2 and now - _rate_window[0][0] > 15:
        _rate_window.pop(0)
    pps = 0.0
    if len(_rate_window) >= 2:
        dt = _rate_window[-1][0] - _rate_window[0][0]
        dp = _rate_window[-1][1] - _rate_window[0][1]
        pps = (dp / dt) if dt > 0 else 0.0
    last_ts = counters.get("last_ts", 0.0)
    idle = (now - last_ts) if last_ts else None
    live = idle is not None and idle < 5
    return {"pps": round(pps, 1), "total_packets": total, "idle_sec": idle, "live": live}


def buffer_sizes(*, threat_detection=None, flow_tracker=None, dns_log=None,
                 http_log=None, events=None):
    """Approximate in-memory footprint of the main buffers (item counts)."""
    out = {}

    def _count(mod, fn, *a):
        try:
            return fn(mod, *a)
        except Exception:
            return None

    if threat_detection is not None:
        out["endpoints"] = _safe_len(getattr(threat_detection, "endpoint_stats", None))
        out["retained_packets"] = _try(threat_detection, "retained_packet_count")
    if flow_tracker is not None:
        out["flows"] = _try(flow_tracker, "count")
    if dns_log is not None:
        out["dns_records"] = _try(dns_log, "count")
    if events is not None:
        try:
            out["event_buffer"] = len(events.recent(100000))
        except Exception:
            out["event_buffer"] = None
    return out


def db_size(path="incidents.db"):
    """On-disk size of the database, in bytes (or None)."""
    try:
        if os.path.exists(path):
            return os.path.getsize(path)
    except Exception:
        pass
    return None


def module_status(modules):
    """Ping each subsystem by calling a cheap read-only function. `modules` is a
    dict name -> (module, probe_attr). Returns name -> 'ok'/'error'/'absent'."""
    status = {}
    for name, (mod, probe) in modules.items():
        if mod is None:
            status[name] = "absent"
            continue
        try:
            fn = getattr(mod, probe, None)
            if fn is None:
                status[name] = "ok"          # imported but no probe: assume ok
            else:
                fn()
                status[name] = "ok"
        except Exception:
            status[name] = "error"
    return status


def report(*, threat_detection=None, flow_tracker=None, dns_log=None,
           http_log=None, events=None, db_path="incidents.db", modules=None):
    """Assemble the full health picture."""
    cap = capture_rate(threat_detection) if threat_detection else {"pps": 0, "live": False,
                                                                    "idle_sec": None,
                                                                    "total_packets": 0}
    return {
        "uptime_sec": uptime_sec(),
        "capture": cap,
        "buffers": buffer_sizes(threat_detection=threat_detection,
                                flow_tracker=flow_tracker, dns_log=dns_log,
                                http_log=http_log, events=events),
        "db_bytes": db_size(db_path),
        "modules": module_status(modules or {}),
    }


def summary(rep):
    """Plain-language health lines with a top-level verdict."""
    cap = rep.get("capture", {})
    live = cap.get("live")
    verdict = "HEALTHY" if live else "NO TRAFFIC"
    mods = rep.get("modules", {})
    if any(v == "error" for v in mods.values()):
        verdict = "DEGRADED"
    lines = [f"Status: {verdict}",
             f"Uptime: {_hms(rep.get('uptime_sec', 0))}"]
    idle = cap.get("idle_sec")
    idle_txt = f"{idle:.0f}s ago" if idle is not None else "never"
    lines.append(f"Capture: {cap.get('pps', 0)} pkt/s   "
                 f"(last packet {idle_txt}, {cap.get('total_packets', 0)} total)")
    b = rep.get("buffers", {})
    if b:
        parts = [f"{k} {v}" for k, v in b.items() if v is not None]
        lines.append("Buffers: " + ("  ".join(parts) if parts else "n/a"))
    if rep.get("db_bytes") is not None:
        lines.append(f"Database: {_mb(rep['db_bytes'])}")
    if mods:
        bad = [k for k, v in mods.items() if v != "ok"]
        if bad:
            lines.append("Subsystems needing attention: " + ", ".join(
                f"{k} ({mods[k]})" for k in bad))
        else:
            lines.append(f"Subsystems: all {len(mods)} responding")
    return lines


def _safe_len(obj):
    try:
        return len(obj)
    except Exception:
        return None


def _try(mod, fn):
    try:
        return getattr(mod, fn)()
    except Exception:
        return None


def _hms(sec):
    sec = int(sec or 0)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    if sec < 86400:
        return f"{sec // 3600}h {(sec % 3600) // 60}m"
    return f"{sec // 86400}d {(sec % 86400) // 3600}h"


def _mb(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
