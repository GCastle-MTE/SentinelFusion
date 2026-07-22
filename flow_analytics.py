"""Per-flow behavioural analytics.

The engine already flags beaconing and exfil at the *endpoint* level - aggregate
bytes and connection timing to an IP. That's a good coarse net, but it misses
things that only show up per-conversation:

  * A beaconing flow to a host you *also* browse normally. Endpoint aggregation
    averages the regular check-ins together with your ordinary traffic and the
    regularity disappears. Per-flow, the C2 channel stands on its own.
  * RTP. It can't be identified from a single packet (its header is basically two
    version bits), but across a flow the tell-tale signs are there: many small,
    steadily-timed UDP packets in both directions on a high, non-standard port.

This module reads the read-only snapshots `flow_tracker.flows()` already exposes
plus a small per-flow history of packet arrival gaps, and returns findings. It
never mutates flow state - it only observes. All logic is pure and testable.
"""

import time

# --- beaconing (per flow) ---
BEACON_MIN_HITS = 6            # packets/intervals needed before we judge
BEACON_MIN_PERIOD = 1.0        # seconds; ignore sub-second chatter
BEACON_MAX_CV = 0.20          # stdev/mean jitter ceiling to count as "regular"

# --- exfil (per flow) ---
EXFIL_MIN_OUT = 5 * 1024 * 1024   # 5 MB out on a single flow
EXFIL_RATIO = 8.0                 # out must dominate in by this much

# --- RTP (flow-level) ---
RTP_MIN_PKTS = 20             # need a real stream, not a couple of packets
RTP_MAX_MEAN_LEN = 400        # media frames are small and regular
RTP_MAX_CV = 0.6              # packet timing is fairly steady in a media stream

# Per-flow arrival-gap history, keyed by flow key. Bounded per flow.
_history = {}
_MAX_GAPS = 40

_beacon_seen = set()
_exfil_seen = set()
_rtp_seen = set()


def observe_gap(key, ts):
    """Record a packet arrival time for a flow so we can measure regularity."""
    h = _history.get(key)
    if h is None:
        h = {"last_ts": ts, "gaps": []}
        _history[key] = h
        return
    gap = ts - h["last_ts"]
    h["last_ts"] = ts
    if gap > 0:
        h["gaps"].append(gap)
        if len(h["gaps"]) > _MAX_GAPS:
            del h["gaps"][:-_MAX_GAPS]


def _cv(values):
    """Coefficient of variation (stdev/mean). Lower = more regular."""
    if len(values) < 2:
        return 1.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 1.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return (var ** 0.5) / mean


def _gaps_for(key):
    h = _history.get(key)
    return list(h["gaps"]) if h else []


def analyze_flow(flow, key=None):
    """Return a list of (severity, category, message) findings for one flow.

    `flow` is a snapshot dict from flow_tracker; `key` (optional) ties it to the
    arrival-gap history recorded via observe_gap.
    """
    out = []
    dst = flow.get("dst", "")
    remote = flow.get("host") or dst
    proto = flow.get("protocol") or flow.get("proto") or ""

    # --- exfil: heavily-outbound single flow ---
    ob, ib = flow.get("out_bytes", 0), flow.get("in_bytes", 0)
    fid = (key or (flow.get("src"), flow.get("dst"), flow.get("dport")))
    if ob >= EXFIL_MIN_OUT and ob > ib * EXFIL_RATIO:
        if fid not in _exfil_seen:
            _exfil_seen.add(fid)
            out.append((
                "ALERT", "exfil",
                f"Outbound-heavy flow to {remote}:{flow.get('dport')} - "
                f"{_fmt(ob)} out / {_fmt(ib)} in"
                f"{f' ({proto})' if proto else ''}. The shape of a data upload."))

    # --- beaconing: regularly-timed packets on one flow ---
    gaps = _gaps_for(key) if key else []
    if len(gaps) >= BEACON_MIN_HITS:
        mean = sum(gaps) / len(gaps)
        if mean >= BEACON_MIN_PERIOD:
            cv = _cv(gaps)
            if cv < BEACON_MAX_CV and fid not in _beacon_seen:
                _beacon_seen.add(fid)
                out.append((
                    "ALERT", "beacon",
                    f"Regular callouts to {remote}:{flow.get('dport')} - "
                    f"~every {mean:.0f}s (jitter {cv * 100:.0f}%){f' ({proto})' if proto else ''}. "
                    "Even timing to one endpoint is a classic C2 check-in pattern."))

    # --- RTP: media-stream shape on a UDP flow ---
    # --- RTP: media-stream shape on a UDP flow with no identified app protocol ---
    app_proto = flow.get("protocol") or ""      # empty = DPI didn't recognise it
    if (flow.get("proto") == "UDP" and not app_proto
            and flow.get("packets", 0) >= RTP_MIN_PKTS):
        avg_len = flow.get("bytes", 0) / max(1, flow.get("packets", 1))
        port = flow.get("dport", 0)
        both_ways = flow.get("out_pkts", 0) >= 5 and flow.get("in_pkts", 0) >= 5
        cv = _cv(gaps) if len(gaps) >= 5 else 1.0
        if (avg_len <= RTP_MAX_MEAN_LEN and both_ways and port > 1024
                and cv < RTP_MAX_CV):
            if fid not in _rtp_seen:
                _rtp_seen.add(fid)
                out.append((
                    "INFO", "protocol",
                    f"Likely RTP media stream {flow.get('src')} <-> {remote}:{port} - "
                    f"{flow.get('packets')} small, steadily-timed UDP packets both ways. "
                    "(Identified from flow behaviour, not a single packet.)"))
    return out


def sweep(flows, keyed=None):
    """Analyse a batch of flow snapshots. `keyed` optionally maps index->key.

    Returns (source_ip, severity, category, message) tuples so the caller can
    attribute each alert to the right endpoint. Deduped across calls.
    """
    findings = []
    for i, flow in enumerate(flows):
        key = keyed[i] if keyed and i < len(keyed) else None
        src = flow.get("src", "")
        for sev, cat, msg in analyze_flow(flow, key):
            findings.append((src, sev, cat, msg))
    return findings


def expire(active_keys, now=None):
    """Drop arrival-gap history for flows that no longer exist."""
    now = now or time.time()
    dead = [k for k in _history if k not in active_keys]
    for k in dead:
        _history.pop(k, None)


def _fmt(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def clear():
    _history.clear()
    _beacon_seen.clear()
    _exfil_seen.clear()
    _rtp_seen.clear()
