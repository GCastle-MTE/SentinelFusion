"""Allowlist - stop known-good destinations generating the same alert forever.

The watchlist says "tell me whenever this appears". This is its mirror: "I have
already decided this destination is fine, stop raising it." Without one, every
service you use heavily - a cloud drive, a backup target, an AI assistant, a game
platform - trips volume and behaviour detectors permanently, and an analyst
learns to ignore the alert stream. That habit is the real damage.

Three design choices make this safe rather than a blindfold:

**Suppression is category-scoped.** An entry names which detections it silences.
Allowlisting your backup provider for `exfil` is sensible - large uploads there
are the point. It should not also silence a threat-intel hit or a beaconing
pattern involving that same address, because those mean something entirely
different. The default is narrow, not "ignore this host".

**Some categories are never suppressible.** A reputation-feed match, cleartext
credentials, or a known CVE stay loud no matter what the allowlist says. If a
destination you trust starts showing up on a threat feed, that is precisely the
moment you need to hear about it - and an attacker abusing a legitimate cloud
service for exfiltration is a documented technique, not a hypothetical.

**Suppression is counted, never silent.** Every match increments a counter the UI
can show. An allowlist you cannot audit is indistinguishable from a broken
detector, so the tool always knows how much it is holding back and why.

Matching supports individual addresses, CIDR ranges, ASNs and domain suffixes;
ASN is usually the right granularity for a cloud provider whose addresses move.
"""

import os
import json
import threading

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.json")
_LOCK = threading.RLock()

# each: {kind, value, categories: [..] or [] for "all suppressible", note,
#        hits: int}
_rules = []

KINDS = ("ip", "cidr", "asn", "domain")

# Detections that stay loud regardless of any allowlist entry. These either
# indicate the trusted party itself is now a problem, or expose something about
# your own hosts that an allowlist has no business hiding.
NEVER_SUPPRESS = frozenset({
    "intel",    # the destination is on a threat-intelligence feed
    "creds",    # our own credentials crossed the wire in cleartext
    "vuln",     # a known CVE on one of our assets
    "cert",     # certificate problems - the identity itself is in question
    "system",   # tool status
    "soar",     # automation audit trail
})


def load():
    global _rules
    with _LOCK:
        try:
            with open(_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                _rules = [_clean(r) for r in data if isinstance(r, dict)]
        except Exception:
            _rules = []
    return list(_rules)


def save():
    with _LOCK:
        try:
            with open(_PATH, "w", encoding="utf-8") as f:
                json.dump(_rules, f, indent=2)
            return True
        except Exception:
            return False


def rules():
    with _LOCK:
        return [dict(r) for r in _rules]


def add(kind, value, categories=None, note=""):
    """Allow `value`, optionally only for specific detection categories.

    categories=None or [] means "every suppressible category". Anything in
    NEVER_SUPPRESS is stripped out, so it cannot be allowlisted by accident.
    """
    kind = (kind or "").strip().lower()
    value = (value or "").strip()
    if kind not in KINDS or not value:
        return None
    cats = [c.strip().lower() for c in (categories or []) if c and c.strip()]
    cats = [c for c in cats if c not in NEVER_SUPPRESS]
    entry = {"kind": kind, "value": value, "categories": cats,
             "note": note.strip()[:200], "hits": 0}
    with _LOCK:
        for r in _rules:
            if r["kind"] == kind and r["value"].lower() == value.lower():
                r["categories"] = cats
                r["note"] = entry["note"]
                save()
                return dict(r)
        _rules.append(entry)
        save()
    return dict(entry)


def remove(index):
    with _LOCK:
        if 0 <= index < len(_rules):
            gone = _rules.pop(index)
            save()
            return gone
    return None


def clear():
    with _LOCK:
        _rules.clear()
        save()


def suppresses(category, ip=None, asn=None, hostname=None):
    """Return the matching entry if this detection should be held back, else None.

    A detection is suppressed when an entry matches the destination *and* covers
    that category. Categories in NEVER_SUPPRESS always return None.
    """
    category = (category or "").strip().lower()
    if category in NEVER_SUPPRESS:
        return None
    with _LOCK:
        for r in _rules:
            cats = r.get("categories") or []
            if cats and category not in cats:
                continue
            if _matches(r, ip, asn, hostname):
                r["hits"] = r.get("hits", 0) + 1
                return dict(r)
    return None


def _matches(rule, ip, asn, hostname):
    kind, value = rule.get("kind"), (rule.get("value") or "")
    try:
        if kind == "ip":
            return bool(ip) and str(ip) == value
        if kind == "cidr":
            if not ip:
                return False
            import ipaddress
            return ipaddress.ip_address(str(ip)) in ipaddress.ip_network(value, strict=False)
        if kind == "asn":
            if not asn:
                return False
            return _asn_num(asn) == _asn_num(value)
        if kind == "domain":
            if not hostname:
                return False
            h, v = str(hostname).lower().rstrip("."), value.lower().lstrip(".")
            return h == v or h.endswith("." + v)
    except Exception:
        return False
    return False


def validate(kind, value):
    """Check an entry before adding it. Returns (ok, message)."""
    kind = (kind or "").strip().lower()
    value = (value or "").strip()
    if kind not in KINDS:
        return (False, f"kind must be one of {', '.join(KINDS)}")
    if not value:
        return (False, "value cannot be empty")
    if kind == "ip":
        try:
            import ipaddress
            ipaddress.ip_address(value)
        except Exception:
            return (False, f"'{value}' is not a valid IP address")
    elif kind == "cidr":
        try:
            import ipaddress
            ipaddress.ip_network(value, strict=False)
        except Exception:
            return (False, f"'{value}' is not a valid CIDR range")
    elif kind == "asn":
        if _asn_num(value) is None:
            return (False, f"'{value}' is not a valid ASN (e.g. AS399358)")
    return (True, "")


def stats():
    """How much the allowlist is holding back - so it can be audited."""
    with _LOCK:
        total = sum(r.get("hits", 0) for r in _rules)
        return {
            "entries": len(_rules),
            "suppressed": total,
            "by_rule": [{"kind": r["kind"], "value": r["value"],
                         "categories": r.get("categories") or ["all"],
                         "hits": r.get("hits", 0)} for r in _rules],
        }


def summarize():
    st = stats()
    if not st["entries"]:
        return ["No allowlist entries. Known-good destinations will keep "
                "generating the same alerts."]
    lines = [f"{st['entries']} entry(s), {st['suppressed']} detection(s) held back "
             "this session:"]
    for r in st["by_rule"]:
        cats = ", ".join(r["categories"])
        lines.append(f"   {r['kind']}:{r['value']}  [{cats}]  - {r['hits']} suppressed")
    lines.append("")
    lines.append("Never suppressed regardless of entry: "
                 + ", ".join(sorted(NEVER_SUPPRESS)))
    return lines


def _clean(r):
    return {
        "kind": str(r.get("kind", "")).lower(),
        "value": str(r.get("value", "")),
        "categories": [str(c).lower() for c in (r.get("categories") or [])
                       if str(c).lower() not in NEVER_SUPPRESS],
        "note": str(r.get("note", ""))[:200],
        "hits": int(r.get("hits", 0) or 0),
    }


def _asn_num(s):
    try:
        return int(str(s).upper().replace("AS", "").strip())
    except Exception:
        return None
