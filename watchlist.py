"""User watchlist - raise an alert when traffic touches something you care about.

Rules match an external endpoint by IP/CIDR, country, or ASN. Matching reuses
the geo/ASN info that geo_lookup already resolves (online or from the offline
MaxMind DB), so a rule like "country = RU" or "ASN = 13335" just works once the
endpoint is geolocated. Rules persist to watchlist.json next to the app.
"""

import json
import os
import re
import threading
import ipaddress

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "watchlist.json")
_LOCK = threading.RLock()
_rules = []   # each: {"kind": "ip"|"country"|"asn", "value": str, "note": str}

KINDS = ("ip", "country", "asn")


def _asn_num(s):
    m = re.search(r"(\d+)", str(s or ""))
    return m.group(1) if m else None


def load():
    global _rules
    with _LOCK:
        data = []
        try:
            if os.path.exists(_PATH):
                with open(_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception:
            data = []
        clean = []
        if isinstance(data, list):
            for r in data:
                if not isinstance(r, dict):
                    continue
                kind = str(r.get("kind", "")).lower()
                val = str(r.get("value", "")).strip()
                if kind in KINDS and val:
                    clean.append({"kind": kind, "value": val,
                                  "note": str(r.get("note", "")).strip()})
        _rules = clean
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
        return list(_rules)


def add(kind, value, note=""):
    kind = str(kind).lower().strip()
    value = str(value).strip()
    if kind not in KINDS or not value:
        return False
    with _LOCK:
        # avoid exact duplicates
        for r in _rules:
            if r["kind"] == kind and r["value"].lower() == value.lower():
                return False
        _rules.append({"kind": kind, "value": value, "note": str(note).strip()})
        save()
        return True


def remove(index):
    with _LOCK:
        if 0 <= index < len(_rules):
            _rules.pop(index)
            save()
            return True
        return False


def clear():
    global _rules
    with _LOCK:
        _rules = []
        save()


def validate(kind, value):
    """Return (ok, message) for a prospective rule - used by the UI."""
    kind = str(kind).lower().strip()
    value = str(value).strip()
    if not value:
        return False, "enter a value"
    if kind == "ip":
        try:
            ipaddress.ip_network(value, strict=False)
            return True, ""
        except ValueError:
            try:
                ipaddress.ip_address(value)
                return True, ""
            except ValueError:
                return False, "not a valid IP or CIDR"
    if kind == "country":
        return True, ""   # 2-letter code or name; matched case-insensitively
    if kind == "asn":
        if _asn_num(value):
            return True, ""
        return False, "ASN needs a number (e.g. 13335 or AS13335)"
    return False, "unknown rule type"


def match(ip, info):
    """Return the first rule this endpoint matches, or None.

    `info` is the geo dict from geo_lookup.get(ip) (may include countryCode,
    country, and asn like 'AS15169 Google LLC').
    """
    info = info or {}
    cc = (info.get("countryCode") or "").upper()
    country = (info.get("country") or "").upper()
    asn_num = _asn_num(info.get("asn"))
    with _LOCK:
        current = list(_rules)
    for r in current:
        kind, val = r["kind"], r["value"].strip()
        if kind == "ip":
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(val, strict=False):
                    return r
            except ValueError:
                if ip == val:
                    return r
        elif kind == "country":
            v = val.upper()
            if v and (v == cc or v == country):
                return r
        elif kind == "asn":
            vnum = _asn_num(val)
            if vnum and asn_num and vnum == asn_num:
                return r
    return None
