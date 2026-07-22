# wifi_osint.py
#
# WiFi OSINT against public wardrive / geolocation databases.
#   - wigle_search_area(): networks WiGLE users have logged in an area.
#   - geolocate_bssid():   locate an access point by its BSSID (MAC),
#                          via Mylnikov (no key) and WiGLE.
#
# Uses only `requests`. WiGLE needs a free API token (the "Encode for use"
# base64 string from your WiGLE account page).
import math

import requests
import net_proxy

_wigle_token = None  # base64 "name:token" from WiGLE's "Encode for use"


def set_wigle_token(token):
    global _wigle_token
    _wigle_token = (token or "").strip() or None


def _wigle_headers():
    if not _wigle_token:
        return None
    return {"Authorization": f"Basic {_wigle_token}", "Accept": "application/json"}


def wigle_search_area(lat, lon, radius_km=1.0, ssid=None, max_results=50):
    headers = _wigle_headers()
    if not headers:
        return {"error": "No WiGLE token set."}

    dlat = radius_km / 111.0
    dlon = radius_km / (111.0 * max(math.cos(math.radians(lat)), 0.01))
    params = {
        "latrange1": lat - dlat,
        "latrange2": lat + dlat,
        "longrange1": lon - dlon,
        "longrange2": lon + dlon,
        "resultsPerPage": min(int(max_results), 100),
    }
    if ssid:
        params["ssid"] = ssid

    try:
        r = requests.get(
            "https://api.wigle.net/api/v2/network/search",
            params=params, headers=headers, timeout=20,
            proxies=net_proxy.proxies(),
        )
        if r.status_code == 401:
            return {"error": "WiGLE auth failed - check your token."}
        if r.status_code == 429:
            return {"error": "WiGLE rate limit reached - try again later."}
        data = r.json()
    except Exception as e:
        return {"error": f"WiGLE request failed: {e}"}

    networks = []
    for n in data.get("results", []) or []:
        networks.append({
            "ssid": n.get("ssid") or "(hidden)",
            "bssid": n.get("netid"),
            "lat": n.get("trilat"),
            "lon": n.get("trilong"),
            "encryption": n.get("encryption"),
            "channel": n.get("channel"),
            "last": n.get("lastupdt"),
        })
    return {"networks": networks, "total": data.get("totalResults")}


def geolocate_bssid(bssid):
    bssid = (bssid or "").strip()
    if not bssid:
        return {"error": "No BSSID given."}
    results = {}

    # Mylnikov - free, no key.
    try:
        r = requests.get(
            "https://api.mylnikov.org/geolocation/wifi",
            params={"v": "1.1", "bssid": bssid}, timeout=15,
            proxies=net_proxy.proxies(),
        )
        d = r.json()
        if d.get("result") == 200 and d.get("data"):
            results["mylnikov"] = {
                "lat": d["data"].get("lat"),
                "lon": d["data"].get("lon"),
                "range": d["data"].get("range"),
            }
        else:
            results["mylnikov"] = None
    except Exception as e:
        results["mylnikov"] = {"error": str(e)}

    # WiGLE by BSSID (netid) - uses your token if set.
    headers = _wigle_headers()
    if headers:
        try:
            r = requests.get(
                "https://api.wigle.net/api/v2/network/search",
                params={"netid": bssid}, headers=headers, timeout=20,
                proxies=net_proxy.proxies(),
            )
            d = r.json()
            res = d.get("results") or []
            if res:
                n = res[0]
                results["wigle"] = {
                    "ssid": n.get("ssid"),
                    "lat": n.get("trilat"),
                    "lon": n.get("trilong"),
                    "encryption": n.get("encryption"),
                }
            else:
                results["wigle"] = None
        except Exception as e:
            results["wigle"] = {"error": str(e)}

    return results
