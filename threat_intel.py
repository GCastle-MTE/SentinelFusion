# threat_intel.py
#
# Defensive threat intelligence: pull free, no-key IP reputation feeds and
# answer "is this endpoint known-bad?" fast. Used to auto-flag endpoints red
# on the map and raise ALERT events when traffic touches a listed IP.
#
# Feeds are fetched on the user's machine (needs internet). Each feed failure
# is tolerated - we keep whatever loaded and log a warning.
import ipaddress
import json
import os
import threading
import time

import requests

import events
import net_proxy

_CACHE = os.path.join(os.path.dirname(__file__), "intel_cache.json")
REFRESH_HOURS = 6

# type "ip"  -> one IP address per line
# type "cidr" -> one network per line (e.g. 1.2.3.0/24)
# lines starting with # or ; are comments; trailing "; note" is stripped.
SOURCES = [
    {"name": "Feodo C2", "category": "botnet C2",
     "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "type": "ip"},
    {"name": "SSLBL", "category": "botnet C2 (SSL)",
     "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt", "type": "ip"},
    {"name": "blocklist.de", "category": "known attacker",
     "url": "https://lists.blocklist.de/lists/all.txt", "type": "ip"},
    {"name": "Spamhaus DROP", "category": "hijacked netblock",
     "url": "https://www.spamhaus.org/drop/drop.txt", "type": "cidr"},
    {"name": "Tor exit", "category": "Tor exit node",
     "url": "https://check.torproject.org/torbulkexitlist", "type": "ip"},
]

_lock = threading.Lock()
_bad_ips = {}        # ip -> {"category", "source"}
_bad_cidrs = []      # list of (ip_network, category, source)
_verdict_cache = {}  # ip -> verdict-or-None (memoized)
_last_refresh = 0
_stop = threading.Event()


def _parse_line(line):
    line = line.strip()
    if not line or line[0] in "#;":
        return None
    token = line.split(";")[0].split()[0].strip()
    return token or None


def _load_cache():
    global _bad_ips, _bad_cidrs, _last_refresh
    try:
        with open(_CACHE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False
    cidrs = []
    for entry in data.get("cidrs", []):
        try:
            cidrs.append((ipaddress.ip_network(entry[0]), entry[1], entry[2]))
        except (ValueError, IndexError):
            pass
    with _lock:
        _bad_ips = data.get("ips", {})
        _bad_cidrs = cidrs
        _last_refresh = data.get("ts", 0)
    return True


def _save_cache():
    try:
        with _lock:
            data = {
                "ts": _last_refresh,
                "ips": _bad_ips,
                "cidrs": [[str(n), c, s] for (n, c, s) in _bad_cidrs],
            }
        with open(_CACHE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def refresh(force=False):
    global _bad_ips, _bad_cidrs, _last_refresh, _verdict_cache
    if not force and _last_refresh and (time.time() - _last_refresh) < REFRESH_HOURS * 3600:
        return

    new_ips, new_cidrs, feeds = {}, [], 0
    for src in SOURCES:
        try:
            r = requests.get(src["url"], timeout=20, proxies=net_proxy.proxies())
            if r.status_code != 200:
                events.log_event("WARNING", "intel", src["name"],
                                 f"feed returned HTTP {r.status_code}")
                continue
            count = 0
            for line in r.text.splitlines():
                token = _parse_line(line)
                if not token:
                    continue
                if src["type"] == "ip":
                    try:
                        ipaddress.ip_address(token)
                    except ValueError:
                        continue
                    new_ips[token] = {"category": src["category"], "source": src["name"]}
                    count += 1
                else:
                    try:
                        net = ipaddress.ip_network(token, strict=False)
                    except ValueError:
                        continue
                    new_cidrs.append((net, src["category"], src["name"]))
                    count += 1
            if count:
                feeds += 1
        except Exception as e:
            events.log_event("WARNING", "intel", src["name"], f"feed fetch failed: {e}")

    if new_ips or new_cidrs:
        with _lock:
            _bad_ips, _bad_cidrs = new_ips, new_cidrs
            _last_refresh = time.time()
            _verdict_cache = {}
        _save_cache()
        events.log_event("INFO", "intel", "threat_intel",
                         f"loaded {len(new_ips)} IPs + {len(new_cidrs)} ranges from {feeds} feeds")
    else:
        events.log_event("WARNING", "intel", "threat_intel", "no feeds loaded")


def is_bad(ip):
    # Memoized reputation lookup -> {"category","source"} or None.
    with _lock:
        if ip in _verdict_cache:
            return _verdict_cache[ip]
        verdict = _bad_ips.get(ip)
        if verdict is None and _bad_cidrs:
            try:
                addr = ipaddress.ip_address(ip)
                for net, cat, src in _bad_cidrs:
                    if addr in net:
                        verdict = {"category": cat, "source": src}
                        break
            except ValueError:
                verdict = None
        _verdict_cache[ip] = verdict
        return verdict


def indicator_count():
    with _lock:
        return len(_bad_ips), len(_bad_cidrs)


def start(refresh_hours=REFRESH_HOURS):
    _load_cache()  # instant if we have a recent cache

    def worker():
        refresh()  # refresh now if stale
        while not _stop.wait(refresh_hours * 3600):
            refresh(force=True)

    threading.Thread(target=worker, daemon=True).start()


def stop():
    _stop.set()
