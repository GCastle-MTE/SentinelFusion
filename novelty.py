"""Novelty detection - what have we never seen before?

A network you watch every day has a stable "normal": the same destinations, the
same domains, the same TLS fingerprints. The interesting events are the *new*
ones - a destination IP that appeared for the first time this session, a domain
never resolved before, a JA3/JARM fingerprint that doesn't match anything seen.
New infrastructure appearing mid-session is exactly what a defender wants flagged.

This keeps a first-seen ledger for each kind of observable and answers two
questions: "is this new?" and "what showed up recently?". It persists to disk so
"first seen ever" survives restarts, with an in-memory view of what's new *this
session* for quick highlighting.

Pure and dependency-light (json + time). The engine feeds observations in; the UI
reads novelty out.
"""

import os
import json
import time
import threading

_lock = threading.Lock()
_store_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "novelty_ledger.json")

# kind -> {value: first_seen_ts}
_ledger = {"ip": {}, "domain": {}, "ja3": {}, "jarm": {}, "asn": {}}
# values first seen during THIS session (for "new this session" highlighting)
_session_new = {"ip": set(), "domain": set(), "ja3": set(), "jarm": set(), "asn": set()}
_session_start = time.time()
_loaded = False


def _load():
    global _loaded
    if _loaded:
        return
    try:
        with open(_store_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for kind in _ledger:
            if isinstance(data.get(kind), dict):
                _ledger[kind].update({k: float(v) for k, v in data[kind].items()})
    except Exception:
        pass
    _loaded = True


def _save():
    try:
        with open(_store_path, "w", encoding="utf-8") as f:
            json.dump(_ledger, f)
    except Exception:
        pass


def observe(kind, value, ts=None):
    """Record an observation. Returns True if this value is brand new (first time
    ever seen), False if already known."""
    if not value or kind not in _ledger:
        return False
    ts = ts or time.time()
    with _lock:
        _load()
        known = value in _ledger[kind]
        if not known:
            _ledger[kind][value] = ts
            _session_new[kind].add(value)
            _save()
            return True
        # Seen before across history, but flag if this is its first appearance
        # this session.
        if _ledger[kind][value] < _session_start and value not in _session_new[kind]:
            pass
        return False


def is_new(kind, value):
    """True if this value was first seen during the current session."""
    with _lock:
        _load()
        return value in _session_new.get(kind, set())


def first_seen(kind, value):
    """Timestamp this value was first ever seen, or None."""
    with _lock:
        _load()
        return _ledger.get(kind, {}).get(value)


def recent_new(kind=None, limit=100):
    """Values first seen this session, newest first. If kind is None, all kinds."""
    with _lock:
        _load()
        out = []
        kinds = [kind] if kind else list(_ledger.keys())
        for k in kinds:
            for v in _session_new.get(k, set()):
                out.append({"kind": k, "value": v, "first_seen": _ledger[k].get(v, 0)})
    out.sort(key=lambda d: d["first_seen"], reverse=True)
    return out[:limit]


def stats():
    with _lock:
        _load()
        return {
            "known": {k: len(v) for k, v in _ledger.items()},
            "new_this_session": {k: len(v) for k, v in _session_new.items()},
            "session_start": _session_start,
        }


def clear(session_only=True):
    """Clear the session-new sets. If session_only is False, wipe the whole
    ledger (forgets all history - use with care)."""
    with _lock:
        for k in _session_new:
            _session_new[k].clear()
        if not session_only:
            for k in _ledger:
                _ledger[k].clear()
            _save()
