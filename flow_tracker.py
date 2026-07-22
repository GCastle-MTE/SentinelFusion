"""Session / flow records - netflow-style per-conversation accounting.

Individual packets are noise; the conversation is the signal. This groups
packets into bidirectional flows keyed by the 5-tuple (proto + the two
IP:port endpoints, direction-normalised) and tracks, for each one:

  * bytes and packets in each direction,
  * start / last-seen time and duration,
  * the TCP state (handshaking, established, closing, closed, reset),
  * the application protocol, once protocol_id recognises it,
  * the resolved hostname of the remote end, if DNS saw it.

That record is what turns raw capture into something you can hunt in: long-lived
connections, big asymmetric transfers (exfil looks like a lot out, little in),
half-open floods, and short evenly-spaced flows (beaconing) all become obvious
at the flow level in a way they never are packet-by-packet.

Accounting is pure - `update()` takes pre-extracted fields, so it's testable
without scapy. The engine feeds it; nothing here reaches back into live state.
"""

import threading
import time

MAX_FLOWS = 4000
IDLE_EXPIRE = 300           # drop a flow after this many seconds of silence
DIR_OUT = "out"             # initiator -> responder
DIR_IN = "in"               # responder -> initiator

# TCP flag bits
_FIN, _SYN, _RST, _PSH, _ACK = 0x01, 0x02, 0x04, 0x08, 0x10

_flows = {}
_lock = threading.Lock()
_totals = {"flows": 0, "expired": 0}


def _key(proto, a_ip, a_port, b_ip, b_port):
    """Direction-independent flow key. Returns (key, a_is_first) where a_is_first
    says whether (a_ip, a_port) sorts first - used to normalise direction."""
    left = (a_ip, a_port)
    right = (b_ip, b_port)
    if left <= right:
        return (proto, left, right), True
    return (proto, right, left), False


def _tcp_state(rec, flags, direction):
    """Advance a tiny TCP state machine. Best-effort, tolerant of missed packets."""
    state = rec["state"]
    if flags & _RST:
        return "reset"
    if flags & _SYN and not (flags & _ACK):
        return "syn_sent"
    if flags & _SYN and (flags & _ACK):
        return "syn_recv"
    if flags & _FIN:
        # First FIN starts teardown; a FIN from the other side finishes it.
        if state in ("closing", "closed"):
            return "closed"
        rec["_fin_from"] = rec.get("_fin_from") or direction
        return "closing"
    if flags & _ACK:
        if state in ("syn_sent", "syn_recv"):
            return "established"
        if state == "closing":
            # ACK after both FINs -> closed
            if rec.get("_fin_dirs", 0) >= 2:
                return "closed"
        return state if state not in ("new",) else "established"
    return state


def update(proto, src_ip, src_port, dst_ip, dst_port, length, flags=0,
           protocol="", ts=None):
    """Record one packet into its flow. Returns the flow's key."""
    ts = ts or time.time()
    key, src_is_a = _key(proto, src_ip, src_port, dst_ip, dst_port)

    with _lock:
        rec = _flows.get(key)
        if rec is None:
            # The first packet defines the initiator. For TCP we trust the SYN;
            # otherwise whoever we saw first is treated as the initiator.
            initiator_is_src = True
            if proto == "TCP" and (flags & _SYN) and not (flags & _ACK):
                initiator_is_src = True
            rec = {
                "key": key, "proto": proto,
                "src": src_ip, "sport": src_port, "dst": dst_ip, "dport": dst_port,
                "start": ts, "last": ts,
                "out_bytes": 0, "in_bytes": 0, "out_pkts": 0, "in_pkts": 0,
                "state": "new" if proto == "TCP" else "-",
                "protocol": protocol or "", "host": "",
                "_initiator_src": initiator_is_src, "_fin_dirs": 0,
            }
            _flows[key] = rec
            _totals["flows"] += 1
            if len(_flows) > MAX_FLOWS:
                _evict_locked()

        # Direction relative to the flow's initiator.
        outbound = (src_ip == rec["src"] and src_port == rec["sport"])
        direction = DIR_OUT if outbound else DIR_IN
        if outbound:
            rec["out_bytes"] += length
            rec["out_pkts"] += 1
        else:
            rec["in_bytes"] += length
            rec["in_pkts"] += 1
        rec["last"] = ts
        if protocol and not rec["protocol"]:
            rec["protocol"] = protocol

        if proto == "TCP":
            if flags & _FIN:
                rec["_fin_dirs"] = rec.get("_fin_dirs", 0) + 1
            rec["state"] = _tcp_state(rec, flags, direction)
    return key


def set_protocol(key, protocol):
    with _lock:
        rec = _flows.get(key)
        if rec and protocol and not rec["protocol"]:
            rec["protocol"] = protocol


def set_host(ip, host):
    """Attach a resolved hostname to every flow whose remote end is `ip`."""
    if not host:
        return
    with _lock:
        for rec in _flows.values():
            if rec["dst"] == ip or rec["src"] == ip:
                if not rec["host"]:
                    rec["host"] = host


def _evict_locked():
    # Drop the least-recently-active flows to stay under the cap.
    victims = sorted(_flows.values(), key=lambda r: r["last"])[:len(_flows) - MAX_FLOWS + 100]
    for v in victims:
        _flows.pop(v["key"], None)
        _totals["expired"] += 1


def expire(now=None):
    """Remove flows idle longer than IDLE_EXPIRE. Returns how many were dropped."""
    now = now or time.time()
    with _lock:
        dead = [k for k, r in _flows.items() if now - r["last"] > IDLE_EXPIRE]
        for k in dead:
            _flows.pop(k, None)
        _totals["expired"] += len(dead)
    return len(dead)


def _snapshot(rec, now):
    out_b, in_b = rec["out_bytes"], rec["in_bytes"]
    total = out_b + in_b
    duration = max(0.0, rec["last"] - rec["start"])
    ratio = (out_b / in_b) if in_b else (float("inf") if out_b else 0.0)
    return {
        "proto": rec["proto"], "protocol": rec["protocol"] or "",
        "src": rec["src"], "sport": rec["sport"],
        "dst": rec["dst"], "dport": rec["dport"], "host": rec["host"],
        "out_bytes": out_b, "in_bytes": in_b, "bytes": total,
        "out_pkts": rec["out_pkts"], "in_pkts": rec["in_pkts"],
        "packets": rec["out_pkts"] + rec["in_pkts"],
        "start": rec["start"], "last": rec["last"], "duration": duration,
        "state": rec["state"], "ratio": ratio,
        "idle": max(0.0, now - rec["last"]),
    }


def flows(limit=500, sort="bytes", active_only=False):
    now = time.time()
    with _lock:
        rows = [_snapshot(r, now) for r in _flows.values()]
    if active_only:
        rows = [r for r in rows if r["state"] not in ("closed", "reset")]
    keyfn = {
        "bytes": lambda r: r["bytes"],
        "duration": lambda r: r["duration"],
        "last": lambda r: r["last"],
        "packets": lambda r: r["packets"],
        "out": lambda r: r["out_bytes"],
    }.get(sort, lambda r: r["bytes"])
    rows.sort(key=keyfn, reverse=True)
    return rows[:limit]


def get(proto, a_ip, a_port, b_ip, b_port):
    key, _ = _key(proto, a_ip, a_port, b_ip, b_port)
    now = time.time()
    with _lock:
        rec = _flows.get(key)
        return _snapshot(rec, now) if rec else None


def stats():
    with _lock:
        rows = list(_flows.values())
        active = sum(1 for r in rows if r["state"] not in ("closed", "reset"))
        out_total = sum(r["out_bytes"] for r in rows)
        in_total = sum(r["in_bytes"] for r in rows)
        by_proto = {}
        for r in rows:
            p = r["protocol"] or r["proto"]
            by_proto[p] = by_proto.get(p, 0) + 1
    return {"total": len(rows), "active": active,
            "out_bytes": out_total, "in_bytes": in_total,
            "ever": _totals["flows"], "expired": _totals["expired"],
            "by_protocol": by_proto}


def count():
    with _lock:
        return len(_flows)


def clear():
    with _lock:
        _flows.clear()
    _totals["flows"] = 0
    _totals["expired"] = 0
