"""Asset registry - one record per host, accumulating everything we learn.

Before this, knowledge about a device was scattered across five stores that
never spoke: lan_monitor held IP/MAC/vendor, threat_detection held traffic,
service_fingerprint produced product versions that were printed and discarded,
smb_fingerprint produced an exact Windows build that was discarded, and
cve_lookup produced vulnerabilities that lived only in whichever window was
open. Each scan rediscovered everything from scratch, and nothing downstream -
reports, cases, forensics - could reference what a device actually was.

This is the join. One record per IP, written to by whichever subsystem learns
something, read by anything that needs to know what a host is.

Two design points worth stating:

**Better evidence displaces worse, and says so.** An OS can be inferred from a
TCP fingerprint (a guess), read from a banner, or negotiated over SMB (exact).
Each claim carries its source and a rank; a weaker source cannot overwrite a
stronger one. The record keeps the source so an operator can see whether
"Windows 11 24H2" was measured or inferred.

**It records observations, not verdicts.** A CVE list attached to a host is what
the databases say about that version, not proof the host is exploitable - the
same caveat the vulnerability layer carries. The record stores findings and
their provenance; judgement stays with the analyst.

Persisted to disk so an inventory survives restarts, which is the point of an
inventory.
"""

import os
import json
import time
import threading

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets.json")
_LOCK = threading.RLock()
_assets = {}

# How much to trust a claim about the operating system. A passive TCP fingerprint
# is an educated guess; an SMB negotiate is the host telling you directly.
OS_SOURCE_RANK = {
    "": 0,
    "passive": 1,      # TTL / window-size inference
    "banner": 2,       # a service named it (e.g. OpenSSH_for_Windows)
    "dhcp": 2,
    "smb": 5,          # SMB2 negotiate + NTLMSSP: exact build
}


def _now():
    return time.time()


def _blank(ip):
    return {
        "ip": ip,
        "mac": "", "vendor": "", "hostname": "", "kind": "",
        "os": {"name": "", "version": "", "build": "", "source": "",
               "confidence": 0},
        "services": {},        # "port/proto" -> {port, service, product, version, cpe, confidence}
        "vulns": {},           # cpe -> {product, version, count, worst, worst_score, precision}
        "cert_issues": [],     # [{port, severity, label, detail}]
        "notes": [],
        "first_seen": _now(), "last_seen": _now(),
    }


def record(ip):
    """Get or create the record for an IP."""
    with _LOCK:
        r = _assets.get(ip)
        if r is None:
            r = _blank(ip)
            _assets[ip] = r
        r["last_seen"] = _now()
        return r


def get(ip):
    with _LOCK:
        r = _assets.get(ip)
        return json.loads(json.dumps(r)) if r else None


def assets():
    with _LOCK:
        return json.loads(json.dumps(list(_assets.values())))


def count():
    with _LOCK:
        return len(_assets)


# --- writers ---------------------------------------------------------------

def note_identity(ip, mac=None, vendor=None, hostname=None, kind=None):
    """Record who a device is at the link layer. Blank values never overwrite
    something we already know."""
    r = record(ip)
    with _LOCK:
        for key, val in (("mac", mac), ("vendor", vendor),
                         ("hostname", hostname), ("kind", kind)):
            if val:
                r[key] = val
    return r


def note_os(ip, name, source, version="", build="", confidence=0):
    """Record an OS claim, keeping the best-sourced one.

    Returns True if this claim was accepted. A passive guess will not overwrite
    an SMB-negotiated build; the reverse always wins.
    """
    if not name:
        return False
    r = record(ip)
    with _LOCK:
        current = r["os"]
        if OS_SOURCE_RANK.get(source, 0) < OS_SOURCE_RANK.get(current["source"], 0):
            return False
        r["os"] = {"name": name, "version": version, "build": build,
                   "source": source, "confidence": confidence}
    return True


def note_services(ip, rows):
    """Record identified services from service_fingerprint.identify_findings().

    `rows` are the enriched findings: each has port, service, banner and a
    products list. Only the best product per port is kept - a banner naming both
    Apache and OpenSSL yields two entries under distinct keys.
    """
    r = record(ip)
    with _LOCK:
        for row in rows or []:
            port = row.get("port")
            if port is None:
                continue
            products = row.get("products") or []
            if not products:
                _put_service(r, port, row, None)
                continue
            for p in products:
                _put_service(r, port, row, p)
                # An OS learned from SMB is the strongest claim we can make.
                if p.get("product") == "windows" and p.get("version"):
                    note_os(ip, p.get("label", "Windows"), "smb",
                            version=p["version"], confidence=95)
                elif "windows" in (p.get("label", "") + p.get("evidence", "")).lower() \
                        and p.get("vendor") == "openbsd":
                    note_os(ip, "Windows", "banner", confidence=60)
    return r


def _put_service(rec, port, row, product):
    key = f"{port}/tcp" if product is None else \
        f"{port}/tcp:{product.get('product') or product.get('label', '')}"
    rec["services"][key] = {
        "port": port,
        "service": row.get("service", ""),
        "banner": (row.get("banner") or "")[:120],
        "product": (product or {}).get("label", ""),
        "version": (product or {}).get("version", ""),
        "cpe": (product or {}).get("cpe", ""),
        "confidence": (product or {}).get("confidence", "none"),
        "evidence": (product or {}).get("evidence", ""),
        "seen": _now(),
    }


def note_vulnerabilities(ip, assessments):
    """Record CVE assessments from cve_lookup.assess_products().

    Stores counts and the worst severity per product rather than every CVE - the
    detail belongs in the report, and a Windows release carries four figures of
    history that has no business inflating an inventory record.
    """
    r = record(ip)
    with _LOCK:
        for a in assessments or []:
            if a.get("skipped") or not a.get("cpe"):
                continue
            cves = a.get("cves") or []
            worst, worst_score = "", 0.0
            for c in cves:
                if (c.get("score") or 0) > worst_score:
                    worst_score = c.get("score") or 0
                    worst = c.get("severity") or ""
            r["vulns"][a["cpe"]] = {
                "product": a.get("product", ""),
                "version": a.get("version", ""),
                "count": len(cves),
                "worst": worst,
                "worst_score": worst_score,
                "precision": a.get("precision", "version"),
                "checked": _now(),
            }
    return r


def note_cert_issues(ip, port, issues):
    """Record TLS certificate problems found on a port."""
    r = record(ip)
    with _LOCK:
        r["cert_issues"] = [c for c in r["cert_issues"] if c.get("port") != port]
        for sev, label, detail in issues or []:
            r["cert_issues"].append({"port": port, "severity": sev,
                                     "label": label, "detail": detail})
    return r


def note(ip, text):
    r = record(ip)
    with _LOCK:
        r["notes"].append({"ts": _now(), "text": str(text)[:200]})
        r["notes"] = r["notes"][-40:]
    return r


# --- readers ---------------------------------------------------------------

def describe(ip):
    """Best short label for a host: what it is, not just where it is."""
    r = get(ip)
    if not r:
        return ""
    if r["os"]["name"]:
        os_bit = r["os"]["name"]
        if r["os"].get("version"):
            os_bit += f" ({r['os']['version']})"
        return os_bit
    # Fall back to the most confident identified product.
    best = ""
    for s in r["services"].values():
        if s.get("confidence") == "high" and s.get("product"):
            return f"{s['product']} {s['version']}".strip()
        if s.get("product") and not best:
            best = s["product"]
    return best or r.get("vendor", "") or ""


def risk_summary(ip):
    """Compact risk picture for a host, or None."""
    r = get(ip)
    if not r:
        return None
    worst, score = "", 0.0
    total = 0
    for v in r["vulns"].values():
        if v.get("precision") == "release":
            continue          # release history is not this host's exposure
        total += v.get("count", 0)
        if v.get("worst_score", 0) > score:
            score, worst = v["worst_score"], v.get("worst", "")
    cert_bad = [c for c in r["cert_issues"] if c.get("severity") in ("ALERT", "WARNING")]
    return {"cves": total, "worst": worst, "worst_score": score,
            "cert_issues": len(cert_bad),
            "services": len(r["services"]),
            "os": r["os"]["name"], "os_source": r["os"]["source"]}


def summarize(ip):
    """Plain-language lines describing an asset."""
    r = get(ip)
    if not r:
        return [f"{ip}: nothing recorded."]
    lines = [f"ASSET  {ip}"]
    ident = "  ".join(x for x in (r.get("hostname"), r.get("vendor"),
                                  r.get("mac")) if x)
    if ident:
        lines.append(f"   {ident}")
    if r["os"]["name"]:
        src = r["os"]["source"]
        how = {"smb": "negotiated over SMB", "passive": "inferred from TCP "
               "fingerprint", "banner": "named by a service"}.get(src, src)
        ver = f" {r['os']['version']}" if r["os"].get("version") else ""
        lines.append(f"   OS: {r['os']['name']}{ver}  ({how})")
    if r["services"]:
        lines.append(f"   {len(r['services'])} identified service(s):")
        for s in sorted(r["services"].values(), key=lambda x: x["port"]):
            tag = f"{s['product']} {s['version']}".strip() or s["service"] or "?"
            lines.append(f"      {s['port']:>5}/tcp  {tag}")
    risk = risk_summary(ip)
    if risk and risk["cves"]:
        lines.append(f"   {risk['cves']} CVE(s) on exact versions "
                     f"- worst {risk['worst'].title()} ({risk['worst_score']})")
    for c in r["cert_issues"][:4]:
        lines.append(f"   TLS {c['port']}: {c['label']} - {c['detail'][:60]}")
    return lines


def stats():
    with _LOCK:
        recs = list(_assets.values())
    identified = sum(1 for r in recs if r["os"]["name"] or r["services"])
    with_vulns = sum(1 for r in recs if r["vulns"])
    return {"assets": len(recs), "identified": identified,
            "with_vulnerabilities": with_vulns}


# --- persistence -----------------------------------------------------------

def save():
    with _LOCK:
        try:
            with open(_PATH, "w", encoding="utf-8") as f:
                json.dump(_assets, f)
            return True
        except Exception:
            return False


def load():
    global _assets
    with _LOCK:
        try:
            with open(_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                _assets = {k: v for k, v in data.items() if isinstance(v, dict)}
        except Exception:
            _assets = {}
    return len(_assets)


def clear():
    global _assets
    with _LOCK:
        _assets = {}
        save()
