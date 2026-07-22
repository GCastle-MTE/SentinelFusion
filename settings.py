"""Persistent configuration store for SentinelFusion.

A tiny JSON-backed key/value store so things the user tunes -- the WiGLE
token, detection thresholds, the threat-intel refresh interval -- survive a
restart instead of resetting to code defaults every launch.

The file lives next to the app as ``sentinel_config.json``.  Only keys that
appear in DEFAULTS are honoured, and numeric values are coerced/validated on
load, so a hand-edited or corrupted file can never inject junk or crash the app.
"""

import json
import os
import threading

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                     "sentinel_config.json")
_LOCK = threading.RLock()

# Canonical set of settings + their defaults.  The *type* of each default also
# drives validation: int defaults force their stored value to a clamped int.
DEFAULTS = {
    "wigle_token": "",            # WiGLE "Encode for use" base64 token
    "port_scan_threshold": 25,    # distinct ports to one host before "scan"
    "ping_sweep_hosts": 15,       # distinct hosts pinged before "sweep"
    "syn_flood_count": 200,       # SYNs to one target:port before "flood"
    "exfil_mb": 100,              # outbound MB to one endpoint before "exfil"
    "beacon_min_intervals": 6,    # evenly-timed callouts before "beacon"
    "intel_refresh_hours": 6,     # how often to re-pull reputation feeds
    "geoip_dir": "",              # optional folder holding GeoLite2 .mmdb files
    "ja3_file": "",               # optional JA3 blocklist file
    "capture_iface": "",          # capture interface id ('' = scapy default)
    "proxy_enabled": 0,           # 1 = route OSINT lookups through the proxy
    "notify_enabled": 1,          # 1 = show desktop toast on serious alerts
    "notify_warnings": 0,         # 1 = also toast on warnings (not just alerts)
    "proxy_url": "socks5h://127.0.0.1:9050",   # Tor SOCKS by default
}

# Lower bounds so a zero/blank field can never make a detector fire on
# everything (or an interval of 0 spin the feed thread).
_MINIMUMS = {
    "port_scan_threshold": 2,
    "ping_sweep_hosts": 2,
    "syn_flood_count": 10,
    "exfil_mb": 1,
    "beacon_min_intervals": 3,
    "intel_refresh_hours": 1,
}

_config = dict(DEFAULTS)


def _coerce(data):
    """Return a clean config dict: defaults overlaid with valid stored values."""
    merged = dict(DEFAULTS)
    if isinstance(data, dict):
        for key, default in DEFAULTS.items():
            if key not in data:
                continue
            val = data[key]
            if isinstance(default, int):
                try:
                    val = int(val)
                except (TypeError, ValueError):
                    val = default
                val = max(_MINIMUMS.get(key, 0), val)
            else:
                val = str(val).strip()
            merged[key] = val
    return merged


def load():
    """Read the config file (creating nothing); return the active config."""
    global _config
    with _LOCK:
        data = {}
        try:
            if os.path.exists(_PATH):
                with open(_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
        except Exception:
            data = {}
        _config = _coerce(data)
        return dict(_config)


def save():
    """Persist the active config to disk. Returns True on success."""
    with _LOCK:
        try:
            with open(_PATH, "w", encoding="utf-8") as f:
                json.dump(_config, f, indent=2)
            return True
        except Exception:
            return False


def get(key, default=None):
    with _LOCK:
        return _config.get(key, DEFAULTS.get(key, default))


def set(key, value):
    """Set one key (validated against DEFAULTS); does not auto-save."""
    with _LOCK:
        if key in DEFAULTS:
            _config.update(_coerce({**_config, key: value}))
        else:
            _config[key] = value


def update(values):
    """Bulk-set from a dict (validated); does not auto-save."""
    global _config
    with _LOCK:
        _config = _coerce({**_config, **(values or {})})
        return dict(_config)


def snapshot():
    with _LOCK:
        return dict(_config)


def reset():
    """Restore every setting to its default and persist."""
    global _config
    with _LOCK:
        _config = dict(DEFAULTS)
        save()
        return dict(_config)


def path():
    return _PATH
