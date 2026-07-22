# geo_lookup.py
#
# Resolves external IP addresses to a country / city / ISP using ip-api.com.
# - Free, no API key required.
# - Free tier is HTTP-only and rate limited (~15 batch requests / minute).
# - The batch endpoint resolves up to 100 IPs in a single request.
#
# Results are cached in geo_cache.json next to this file, so any given IP is
# only ever looked up once, even across separate runs.
import json
import os
import threading
import time

import requests

import geoip_local
import net_proxy

_CACHE_PATH = os.path.join(os.path.dirname(__file__), "geo_cache.json")
_FIELDS = "status,message,country,countryCode,city,lat,lon,isp,org,query"

_cache = {}
_lock = threading.Lock()
_stop = threading.Event()
_thread = None


def _load():
    global _cache
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    except Exception:
        _cache = {}


def _save():
    try:
        with _lock:
            snapshot = dict(_cache)
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(snapshot, f)
    except Exception as e:
        print("Could not save geo cache:", e)


_load()


def _ensure(ip):
    # Return the cached info for an IP. On a miss, try the offline MaxMind DB
    # (instant, no network); never block on the online API here. Returns the
    # info dict, or None if still unknown.
    info = _cache.get(ip)
    if info is not None:
        return info
    if geoip_local.available():
        off = geoip_local.lookup(ip)
        if off:
            with _lock:
                _cache[ip] = off
            return off
    return None


def get(ip):
    # Cached info for an IP, or {} if it hasn't been resolved yet.
    return _ensure(ip) or {}


def coords(ip):
    # (lat, lon) for a resolved IP, or None if unknown / not yet resolved.
    info = _ensure(ip)
    if info and info.get("lat") is not None and info.get("lon") is not None:
        return (info["lat"], info["lon"])
    return None


_self_info = None


def locate_self():
    # Geolocate this machine's own public IP (for the "you are here" marker).
    global _self_info
    if _self_info is not None:
        return _self_info
    try:
        resp = requests.get(
            "http://ip-api.com/json/", params={"fields": _FIELDS}, timeout=10
        )
        data = resp.json()
        if isinstance(data, dict) and data.get("status") == "success":
            _self_info = {
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "city": data.get("city"),
                "country": data.get("country"),
                "isp": data.get("isp"),
                "query": data.get("query"),
            }
        else:
            _self_info = {}
    except Exception as e:
        print("Self-location failed:", e)
        _self_info = {}
    return _self_info


def resolve(ips):
    # Look up a list of IPs in batches and store the results in the cache.
    ips = [ip for ip in dict.fromkeys(ips) if ip not in _cache]  # unique + uncached
    if not ips:
        return

    # Offline MaxMind DB first (instant, unlimited). Anything it can't resolve
    # falls through to the rate-limited online batch below.
    if geoip_local.available():
        remaining = []
        for ip in ips:
            off = geoip_local.lookup(ip)
            if off:
                with _lock:
                    _cache[ip] = off
            else:
                remaining.append(ip)
        _save()
        ips = remaining
        if not ips:
            return

    for i in range(0, len(ips), 100):  # batch size limit is 100
        chunk = ips[i:i + 100]
        try:
            resp = requests.post(
                "http://ip-api.com/batch",
                params={"fields": _FIELDS},
                json=chunk,
                timeout=10,
                proxies=net_proxy.proxies(),
            )
            if resp.status_code == 429:
                print("ip-api rate limit hit; backing off.")
                time.sleep(5)
                return
            results = resp.json()
        except Exception as e:
            print("Geo lookup failed for a batch:", e)
            return  # leave them uncached; the next cycle will retry

        if not isinstance(results, list):
            print("Unexpected geo response; skipping batch.")
            return

        with _lock:
            for entry in results:
                ip = entry.get("query")
                if not ip:
                    continue
                if entry.get("status") == "success":
                    _cache[ip] = {
                        "country": entry.get("country"),
                        "countryCode": entry.get("countryCode"),
                        "city": entry.get("city"),
                        "lat": entry.get("lat"),
                        "lon": entry.get("lon"),
                        "isp": entry.get("isp") or entry.get("org"),
                    }
                else:
                    # Remember the miss so we don't keep re-querying it.
                    _cache[ip] = {"country": None, "isp": None}
        _save()


def group_by_country(ip_counts):
    # Aggregate packet counts per country using whatever is cached so far.
    grouped = {}
    for ip, count in ip_counts.items():
        info = _cache.get(ip)
        if info is None:
            label = "Resolving..."
        elif info.get("country"):
            label = info["country"]
        else:
            label = "Unknown"
        grouped[label] = grouped.get(label, 0) + count
    return grouped


def _loop(get_ips, interval):
    while not _stop.is_set():
        try:
            pending = [ip for ip in get_ips() if ip not in _cache]
            if pending:
                resolve(pending)
        except Exception as e:
            print("Geo resolver error:", e)
        _stop.wait(interval)


def start_resolver(get_ips, interval=5):
    # get_ips: a callable returning the current external IPs (any iterable).
    global _thread
    _stop.clear()
    _thread = threading.Thread(target=_loop, args=(get_ips, interval), daemon=True)
    _thread.start()


def stop_resolver():
    _stop.set()
