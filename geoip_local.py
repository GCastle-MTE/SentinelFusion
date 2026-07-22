"""Offline GeoIP + ASN lookups via MaxMind GeoLite2 .mmdb databases.

This is entirely optional. If the `geoip2` package isn't installed, or the
database files can't be found, every call reports "unavailable" and the app
falls back to the online ip-api lookups in geo_lookup.py -- nothing breaks.

When the databases ARE present, lookups are instant, unlimited, and add real
ASN / organisation data that the free online tier doesn't reliably give.

Getting the databases (free):
  1. Make a free account at https://www.maxmind.com/en/geolite2/signup
  2. Download "GeoLite2 City" and "GeoLite2 ASN" in MaxMind DB (.mmdb) format.
  3. Drop GeoLite2-City.mmdb and GeoLite2-ASN.mmdb next to the app, or in a
     ./geoip subfolder, or point the GeoIP directory in the Settings tab at them.
  4. pip install geoip2   (in the same Python the app runs on)
"""

import os
import threading

try:
    import geoip2.database
    _HAVE_LIB = True
except Exception:                       # geoip2 not installed
    geoip2 = None
    _HAVE_LIB = False

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_CITY_NAMES = ("GeoLite2-City.mmdb", "GeoIP2-City.mmdb")
_ASN_NAMES = ("GeoLite2-ASN.mmdb", "GeoIP2-ASN.mmdb")

_lock = threading.Lock()
_city_reader = None
_asn_reader = None
_city_path = None
_asn_path = None
_extra_dir = None        # optional user-configured search directory


def _search_dirs():
    dirs = []
    if _extra_dir:
        dirs.append(_extra_dir)
    dirs.append(_APP_DIR)
    dirs.append(os.path.join(_APP_DIR, "geoip"))
    dirs.append(os.path.join(_APP_DIR, "GeoLite2"))
    return dirs


def _find(names):
    for d in _search_dirs():
        for n in names:
            p = os.path.join(d, n)
            if os.path.isfile(p):
                return p
    return None


def configure(directory):
    """Add a directory to the search path and (re)load the databases."""
    global _extra_dir
    _extra_dir = directory.strip() if isinstance(directory, str) and directory.strip() else None
    reload()


def reload():
    """(Re)open whatever databases can be found. Safe to call repeatedly."""
    global _city_reader, _asn_reader, _city_path, _asn_path
    with _lock:
        for r in (_city_reader, _asn_reader):
            try:
                if r:
                    r.close()
            except Exception:
                pass
        _city_reader = _asn_reader = None
        _city_path = _asn_path = None
        if not _HAVE_LIB:
            return
        cp = _find(_CITY_NAMES)
        ap = _find(_ASN_NAMES)
        try:
            if cp:
                _city_reader = geoip2.database.Reader(cp)
                _city_path = cp
        except Exception:
            _city_reader = None
        try:
            if ap:
                _asn_reader = geoip2.database.Reader(ap)
                _asn_path = ap
        except Exception:
            _asn_reader = None


def available():
    """True if at least one database is loaded and usable."""
    return bool(_city_reader or _asn_reader)


def lib_present():
    return _HAVE_LIB


def status():
    """Human-facing status for the Settings tab."""
    return {"lib": _HAVE_LIB, "city": _city_path, "asn": _asn_path,
            "available": available()}


def lookup(ip):
    """Return {country, countryCode, city, lat, lon, isp, asn, org} for `ip`,
    or {} if unavailable / not found. Keys mirror the online geo schema so the
    rest of the app treats both sources identically."""
    if not available():
        return {}
    out = {}
    if _city_reader is not None:
        try:
            r = _city_reader.city(ip)
            out["country"] = r.country.name
            out["countryCode"] = r.country.iso_code
            out["city"] = r.city.name
            if r.location is not None and r.location.latitude is not None:
                out["lat"] = r.location.latitude
                out["lon"] = r.location.longitude
        except Exception:
            pass
    if _asn_reader is not None:
        try:
            a = _asn_reader.asn(ip)
            num = a.autonomous_system_number
            org = a.autonomous_system_organization
            if num is not None:
                out["asn"] = f"AS{num}" + (f" {org}" if org else "")
            if org:
                out["org"] = org
                out.setdefault("isp", org)
        except Exception:
            pass
    return out


# Best-effort load at import time.
reload()
