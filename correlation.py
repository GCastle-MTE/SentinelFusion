"""Alert correlation - turn scattered events into scored incidents.

Every detector fires on its own, so a single real intrusion shows up as a
scatter of unrelated alerts: a port scan, then a new service, then regular
beaconing, then a big upload - all to or from the same host, but presented as
four separate lines you have to connect in your head.

This does the connecting. It groups events that share an actor (an IP) inside a
time window into one **incident**, scores it by how many independent detectors
fired and how they chain together, and names the pattern when it recognises one
(recon -> foothold -> C2 -> exfil is the classic kill-chain shape).

Design:
  * Pure and incremental. `ingest(event)` folds one event into the running
    incident set; `incidents()` returns the current scored view. No global
    engine state is touched, so it's fully testable and safe to run offline over
    a reviewed capture as well as live.
  * Scores are explainable. Each incident carries the exact signals that built
    its score, so the UI can show *why* something is HIGH, not just that it is.
"""

import time

# How long a quiet actor stays part of the same incident before it's considered
# a new one (seconds).
INCIDENT_WINDOW = 900          # 15 minutes

# Base weight per category - how much one signal of this kind moves the needle.
CATEGORY_WEIGHT = {
    "scan": 3, "sweep": 3, "flood": 4, "arp": 3, "dns": 2, "tunnel": 5,
    "dga": 4, "intel": 6, "ja3": 5, "creds": 5, "rogue": 6, "service": 2,
    "cert": 3, "protocol": 4, "http": 2, "exfil": 8, "beacon": 7, "watch": 4,
    "device": 1, "system": 0,
}

# Severity multiplier.
SEV_MULT = {"ALERT": 2.0, "WARNING": 1.0, "INFO": 0.4}

# Kill-chain stages - a category maps to the phase of an attack it represents.
# An incident that spans multiple stages is far more serious than one that
# repeats a single stage, so we reward breadth across stages.
STAGE = {
    "scan": "recon", "sweep": "recon", "service": "recon", "device": "recon",
    "arp": "access", "rogue": "access", "creds": "access", "ja3": "access",
    "cert": "access", "protocol": "evade", "tunnel": "evade", "dns": "evade",
    "dga": "c2", "beacon": "c2", "intel": "c2", "watch": "c2",
    "exfil": "exfil", "flood": "impact", "http": "recon",
}

STAGE_ORDER = ["recon", "access", "evade", "c2", "exfil", "impact"]

# Thresholds for the human-readable level.
LEVEL_BANDS = [(30, "CRITICAL"), (18, "HIGH"), (9, "MEDIUM"), (1, "LOW")]

_incidents = {}                # actor -> incident dict
_next_id = [1]


def _blank(actor, ts):
    return {
        "id": _next_id[0], "actor": actor, "first": ts, "last": ts,
        "score": 0.0, "events": [], "categories": {}, "stages": set(),
        "severity_max": "INFO", "acked": False,
    }


def ingest(event):
    """Fold one event dict into the incident set. Returns the incident id, or
    None if the event has no usable actor.

    `event` needs: source, category, severity, ts (epoch) and stamp/message.
    """
    actor = (event.get("source") or "").strip()
    category = event.get("category", "")
    if not actor or actor in ("import", "system", "-", ""):
        return None
    if category == "system":
        return None
    ts = float(event.get("ts") or time.time())

    inc = _incidents.get(actor)
    if inc is None or ts - inc["last"] > INCIDENT_WINDOW:
        inc = _blank(actor, ts)
        _next_id[0] += 1
        _incidents[actor] = inc

    inc["last"] = max(inc["last"], ts)
    inc["first"] = min(inc["first"], ts)
    inc["events"].append({
        "ts": ts, "stamp": event.get("stamp", ""), "severity": event.get("severity", "INFO"),
        "category": category, "message": event.get("message", ""),
    })
    if len(inc["events"]) > 200:
        inc["events"] = inc["events"][-200:]
    inc["categories"][category] = inc["categories"].get(category, 0) + 1
    stage = STAGE.get(category)
    if stage:
        inc["stages"].add(stage)

    sev = event.get("severity", "INFO")
    if SEV_MULT.get(sev, 0) > SEV_MULT.get(inc["severity_max"], 0):
        inc["severity_max"] = sev

    _rescore(inc)
    return inc["id"]


def _rescore(inc):
    """Recompute an incident's score from its component signals.

    Score = sum over distinct categories of (weight x severity), with
    diminishing returns for repeats, plus a multiplier for spanning multiple
    kill-chain stages (breadth is what separates a real intrusion from noise).
    """
    base = 0.0
    for cat, count in inc["categories"].items():
        weight = CATEGORY_WEIGHT.get(cat, 1)
        # First occurrence full weight; repeats add sqrt-damped extra.
        base += weight * (1 + 0.4 * ((max(0, count - 1)) ** 0.5))
    base *= SEV_MULT.get(inc["severity_max"], 1.0)

    # Reward breadth across the kill chain: 1 stage x1, 2 stages x1.4, etc.
    n_stages = len(inc["stages"])
    stage_mult = 1.0 + 0.35 * max(0, n_stages - 1)
    inc["score"] = round(base * stage_mult, 1)


def _level(score):
    for threshold, name in LEVEL_BANDS:
        if score >= threshold:
            return name
    return "INFO"


def _pattern(inc):
    """Name the shape of the incident if it matches a known chain."""
    stages = inc["stages"]
    cats = inc["categories"]
    if {"recon", "c2", "exfil"} <= stages:
        return "Full kill chain (recon -> C2 -> exfil)"
    if "exfil" in stages and ("c2" in stages or "beacon" in cats):
        return "C2 with data exfiltration"
    if "beacon" in cats and "dga" in cats:
        return "Beaconing to generated domains (DGA C2)"
    if {"recon", "access"} <= stages:
        return "Recon followed by access activity"
    if "exfil" in stages:
        return "Data exfiltration"
    if "beacon" in cats or "intel" in cats:
        return "Command-and-control indicators"
    if {"recon"} == stages and cats:
        return "Reconnaissance / scanning"
    return ""


def _snapshot(inc):
    ordered = sorted(inc["stages"], key=lambda s: STAGE_ORDER.index(s)
                     if s in STAGE_ORDER else 99)
    return {
        "id": inc["id"], "actor": inc["actor"], "score": inc["score"],
        "level": _level(inc["score"]), "pattern": _pattern(inc),
        "first": inc["first"], "last": inc["last"],
        "duration": max(0.0, inc["last"] - inc["first"]),
        "event_count": len(inc["events"]),
        "categories": dict(inc["categories"]),
        "distinct_signals": len(inc["categories"]),
        "stages": ordered, "severity_max": inc["severity_max"],
        "acked": inc["acked"],
        "events": list(inc["events"]),
    }


def incidents(min_score=1.0, include_acked=False):
    """Return scored incidents, worst first."""
    out = [_snapshot(i) for i in _incidents.values() if i["score"] >= min_score]
    if not include_acked:
        out = [i for i in out if not i["acked"]]
    out.sort(key=lambda i: i["score"], reverse=True)
    return out


def get(actor):
    inc = _incidents.get(actor)
    return _snapshot(inc) if inc else None


def acknowledge(actor):
    inc = _incidents.get(actor)
    if inc:
        inc["acked"] = True
        return True
    return False


def stats():
    levels = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    top = 0.0
    for i in _incidents.values():
        if i["acked"]:
            continue
        levels[_level(i["score"])] += 1
        top = max(top, i["score"])
    return {"total": len(_incidents), "top_score": top, "levels": levels,
            "open": sum(1 for i in _incidents.values() if not i["acked"])}


def expire(now=None):
    """Drop incidents whose last activity is well outside the window."""
    now = now or time.time()
    dead = [a for a, i in _incidents.items()
            if now - i["last"] > INCIDENT_WINDOW * 4]
    for a in dead:
        _incidents.pop(a, None)
    return len(dead)


def rebuild(events):
    """Rebuild the whole incident set from a list of events (e.g. a retro-hunt
    over stored history, or an offline capture review). Clears first."""
    clear()
    for ev in sorted(events, key=lambda e: float(e.get("ts") or 0)):
        ingest(ev)
    return incidents(min_score=0.0, include_acked=True)


def clear():
    _incidents.clear()
    _next_id[0] = 1
