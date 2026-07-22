"""Detection rules catalog - see and tune every detector.

A professional detection tool isn't a black box: an analyst can see exactly what
each rule fires on, what its threshold is, and turn it up, down, on, or off. This
catalog is the single source of truth for SentinelFusion's detectors. Each entry
describes a rule in plain language, links it to its event category and ATT&CK
technique, and - where the rule has a tunable threshold - points at the live
module attribute so a UI can read and change it at runtime.

Thresholds live as constants on their detector modules (e.g.
threat_detection.EXFIL_BYTES). Rather than duplicate them, a rule stores the
module name and attribute; get/set reflect straight onto the running detector, so
tuning takes effect immediately without a restart.

Enable/disable is tracked here and honoured by the engine: a disabled rule's
category is suppressed at event-emit time (wired in events.log_event).
"""

import importlib

# Rules that expose a tunable numeric threshold. `module`/`attr` point at the
# live constant; `kind` hints the UI (bytes / count / seconds). `scale` lets us
# present bytes as MB etc. without changing the stored value.
_TUNABLE = [
    {"id": "exfil_volume", "name": "Data exfiltration volume",
     "category": "exfil", "module": "threat_detection", "attr": "EXFIL_BYTES",
     "kind": "bytes", "detail": "Outbound bytes to one endpoint before flagging exfiltration."},
    {"id": "beacon_intervals", "name": "Beaconing interval count",
     "category": "beacon", "module": "threat_detection", "attr": "BEACON_MIN",
     "kind": "count", "detail": "Regular connection intervals required to call it beaconing."},
    {"id": "port_scan", "name": "Port scan threshold",
     "category": "scan", "module": "scan_detector", "attr": "PORT_SCAN_THRESHOLD",
     "kind": "count", "detail": "Distinct ports touched on one host before flagging a scan."},
    {"id": "deauth_flood", "name": "Wi-Fi deauth flood",
     "category": "wifi", "module": "wifi_wids", "attr": "DEAUTH_FLOOD",
     "kind": "count", "detail": "Deauth/disassoc frames in the window to call it a flood."},
    {"id": "incident_window", "name": "Incident correlation window",
     "category": "soar", "module": "correlation", "attr": "INCIDENT_WINDOW",
     "kind": "seconds", "detail": "Time window over which events group into one incident."},
]

# Detectors described for the catalog but without a single numeric knob.
_DESCRIPTIVE = [
    {"id": "dga", "name": "DGA / algorithmic domains", "category": "dga",
     "detail": "High-entropy domain names typical of malware domain generation."},
    {"id": "dns_tunnel", "name": "DNS tunnelling", "category": "tunnel",
     "detail": "Data smuggled inside DNS queries (long/odd labels, high volume)."},
    {"id": "arp_spoof", "name": "ARP anomalies", "category": "arp",
     "detail": "ARP replies that conflict with known IP/MAC bindings."},
    {"id": "creds", "name": "Cleartext credentials", "category": "creds",
     "detail": "Credentials seen in unencrypted protocols (masked in output)."},
    {"id": "ja3", "name": "JA3 client fingerprint intel", "category": "ja3",
     "detail": "TLS client fingerprints matching known-bad tooling."},
    {"id": "cert", "name": "TLS certificate issues", "category": "cert",
     "detail": "Expired, self-signed, or mismatched certificates."},
    {"id": "rogue_ap", "name": "Rogue AP / evil twin", "category": "rogue",
     "detail": "Your SSID from an unexpected BSSID, or one SSID on many BSSIDs."},
    {"id": "protocol_mismatch", "name": "Protocol/port mismatch", "category": "protocol",
     "detail": "An application protocol on a non-standard port."},
    {"id": "intel_hit", "name": "Threat-intel match", "category": "intel",
     "detail": "Contact with an IP/domain on a threat-intelligence feed."},
]

# category -> enabled?  (default all on). Only categories present here can be
# toggled; unknown categories are always considered enabled.
_enabled = {}


def _init_enabled():
    if _enabled:
        return
    for r in _TUNABLE + _DESCRIPTIVE:
        _enabled.setdefault(r["category"], True)


def rules():
    """Full catalog with live threshold values and enabled state + ATT&CK."""
    _init_enabled()
    try:
        import mitre_attack
    except Exception:
        mitre_attack = None
    out = []
    for r in _TUNABLE:
        entry = dict(r)
        entry["tunable"] = True
        entry["value"] = _get_value(r)
        entry["enabled"] = _enabled.get(r["category"], True)
        entry["techniques"] = (mitre_attack.techniques_for_category(r["category"])
                               if mitre_attack else [])
        out.append(entry)
    for r in _DESCRIPTIVE:
        entry = dict(r)
        entry["tunable"] = False
        entry["value"] = None
        entry["enabled"] = _enabled.get(r["category"], True)
        entry["techniques"] = (mitre_attack.techniques_for_category(r["category"])
                               if mitre_attack else [])
        out.append(entry)
    return out


def _get_value(rule):
    try:
        mod = importlib.import_module(rule["module"])
        return getattr(mod, rule["attr"], None)
    except Exception:
        return None


def set_threshold(rule_id, value):
    """Set a tunable rule's threshold on its live module. Returns True on success."""
    rule = next((r for r in _TUNABLE if r["id"] == rule_id), None)
    if not rule:
        return False
    try:
        mod = importlib.import_module(rule["module"])
        cur = getattr(mod, rule["attr"], None)
        cast = type(cur) if cur is not None else float
        setattr(mod, rule["attr"], cast(value))
        return True
    except Exception:
        return False


def set_enabled(category, enabled):
    _init_enabled()
    _enabled[category] = bool(enabled)
    return True


def is_enabled(category):
    _init_enabled()
    return _enabled.get(category, True)


def disabled_categories():
    _init_enabled()
    return sorted(c for c, on in _enabled.items() if not on)


def snapshot():
    """Serialisable view of tuning state for config export."""
    _init_enabled()
    return {
        "thresholds": {r["id"]: _get_value(r) for r in _TUNABLE},
        "enabled": dict(_enabled),
    }


def restore(state):
    """Apply a snapshot() dict (from config import)."""
    if not isinstance(state, dict):
        return
    for rid, val in (state.get("thresholds") or {}).items():
        if val is not None:
            set_threshold(rid, val)
    for cat, on in (state.get("enabled") or {}).items():
        set_enabled(cat, on)
