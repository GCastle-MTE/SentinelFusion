"""Passive link-quality measurement - RTT and jitter, without probing.

We never send a ping. Two things already on the wire tell us how good a link is:

  * TCP handshake RTT: the gap between the SYN we send and the SYN-ACK that comes
    back is one round trip to that server. Cheap, accurate, and we see it for
    free at the start of every TCP connection.

  * Real-time jitter: for a steady UDP stream (a game or voice session), the
    variation in packet inter-arrival time is jitter. Low jitter = smooth; high
    jitter = the stutter you feel in a match. We track the spread of arrival gaps.

This answers the question the game scenario really cares about: "which server is
laggy?" - per endpoint, with a rolling estimate. Pure bookkeeping over timestamps
fed in by the engine.
"""

import time
import threading

_lock = threading.Lock()

# ip -> {"rtt_ms": float, "samples": int, "min_ms": float}
_rtt = {}
# key -> ts of the outbound SYN awaiting its SYN-ACK
_pending_syn = {}
# ip -> list of recent inter-arrival gaps (seconds) for jitter
_gaps = {}
# ip -> last arrival timestamp (for gap computation)
_last_arrival = {}

MAX_GAPS = 50
SYN_TIMEOUT = 10.0     # forget an unanswered SYN after this long

# What counts as a continuous stream for jitter purposes. A media/game stream
# ticks at least a few times a second; anything slower is conversational.
STREAM_MAX_MEDIAN_GAP = 0.25     # seconds between packets, typical
STREAM_MAX_SPREAD_RATIO = 3.0    # stdev beyond this x median = bursty, not jittery


def note_syn(dst_ip, dst_port, ts=None):
    """Record an outbound TCP SYN so we can time its SYN-ACK."""
    ts = ts or time.time()
    with _lock:
        _pending_syn[(dst_ip, dst_port)] = ts
        # opportunistic cleanup of stale pending SYNs
        if len(_pending_syn) > 4096:
            cutoff = ts - SYN_TIMEOUT
            for k in [k for k, t in _pending_syn.items() if t < cutoff]:
                _pending_syn.pop(k, None)


def note_synack(src_ip, src_port, ts=None):
    """Record an inbound SYN-ACK; if it matches a pending SYN, record the RTT."""
    ts = ts or time.time()
    with _lock:
        sent = _pending_syn.pop((src_ip, src_port), None)
        if sent is None:
            return None
        rtt_ms = max(0.0, (ts - sent) * 1000.0)
        if rtt_ms > 60000:      # ignore absurd values (clock hiccups)
            return None
        rec = _rtt.get(src_ip)
        if rec is None:
            rec = {"rtt_ms": rtt_ms, "samples": 0, "min_ms": rtt_ms}
            _rtt[src_ip] = rec
        # exponential moving average keeps it current without storing history
        rec["rtt_ms"] = 0.7 * rec["rtt_ms"] + 0.3 * rtt_ms if rec["samples"] else rtt_ms
        rec["min_ms"] = min(rec["min_ms"], rtt_ms)
        rec["samples"] += 1
        return rtt_ms


def note_arrival(ip, ts=None):
    """Record a packet arrival from a real-time stream to update jitter."""
    ts = ts or time.time()
    with _lock:
        last = _last_arrival.get(ip)
        _last_arrival[ip] = ts
        if last is not None:
            gap = ts - last
            if 0 < gap < 5:     # ignore idle gaps; jitter is about steady streams
                g = _gaps.setdefault(ip, [])
                g.append(gap)
                if len(g) > MAX_GAPS:
                    del g[0]


def rtt_for(ip):
    """Smoothed RTT in ms for an IP, or None."""
    with _lock:
        rec = _rtt.get(ip)
        return round(rec["rtt_ms"], 1) if rec else None


def jitter_for(ip):
    """Jitter in ms (stdev of inter-arrival gaps), or None.

    Jitter is only meaningful for a *continuous* stream - voice, video, a game
    tick. Conversational traffic (a chat app, a web page, anything request/
    response over QUIC) sits idle between bursts, so the spread of its arrival
    gaps is huge and says nothing about link quality. Reporting it anyway
    produces nonsense like "jitter 1457ms" for a healthy connection.

    So we require the stream to actually look continuous: a short median gap and
    a spread that isn't wildly larger than that median. Anything burstier is
    reported as None rather than as a bad link.
    """
    with _lock:
        gaps = list(_gaps.get(ip, []))
    if len(gaps) < 10:
        return None

    ordered = sorted(gaps)
    median = ordered[len(ordered) // 2]
    # A real-time stream ticks many times a second; a median gap much longer
    # than this is a conversation, not a stream.
    if median > STREAM_MAX_MEDIAN_GAP:
        return None

    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    stdev = var ** 0.5
    # Spread far larger than the typical gap means bursty, not jittery.
    if stdev > median * STREAM_MAX_SPREAD_RATIO:
        return None
    return round(stdev * 1000.0, 1)


def quality(ip):
    """A compact quality readout for an endpoint."""
    rtt = rtt_for(ip)
    jit = jitter_for(ip)
    verdict = "unknown"
    if rtt is not None:
        if rtt < 50:
            verdict = "excellent"
        elif rtt < 100:
            verdict = "good"
        elif rtt < 200:
            verdict = "fair"
        else:
            verdict = "poor"
        if jit is not None and jit > 30 and verdict in ("excellent", "good"):
            verdict = "unstable (high jitter)"
    return {"ip": ip, "rtt_ms": rtt, "jitter_ms": jit, "verdict": verdict}


def describe(ip):
    q = quality(ip)
    if q["rtt_ms"] is None and q["jitter_ms"] is None:
        return "Link quality: not measured yet."
    parts = []
    if q["rtt_ms"] is not None:
        parts.append(f"RTT ~{q['rtt_ms']:.0f} ms")
    if q["jitter_ms"] is not None:
        parts.append(f"jitter {q['jitter_ms']:.0f} ms")
    return f"Link quality: {q['verdict']} ({', '.join(parts)})"


def clear():
    with _lock:
        _rtt.clear()
        _pending_syn.clear()
        _gaps.clear()
        _last_arrival.clear()
