"""IP enrichment - everything known about one address, in one place.

Threat hunting is mostly pivoting: you see an IP in an alert and want the whole
picture without hopping between six tabs. This assembles that picture from the
sources the tool already maintains:

  * classification (external / local / loopback / ...) and reputation feeds,
  * geolocation and ASN / ISP,
  * the hostname it resolved from (passive DNS) and any DNS history,
  * the flows to/from it - bytes each way, protocols, state,
  * cleartext HTTP it was involved in,
  * the correlated incident it belongs to, if any.

Everything is read-only and best-effort: a missing source is simply omitted, so
this never fails just because Tor is off or GeoIP data isn't installed. Returns
plain dicts/lists so the UI can render it and it stays testable.
"""


def _safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception:
        return None


def profile(ip, *, geo_lookup=None, threat_intel=None, threat_detection=None,
            dns_log=None, flow_tracker=None, http_log=None, correlation=None,
            rtt_tracker=None, dns_chain=None):
    """Assemble an enrichment profile for `ip`.

    Modules are passed in (dependency injection) so this is trivially testable
    and has no import cycles. The app passes the real modules.
    """
    out = {"ip": ip, "classification": "", "reputation": None, "hostname": "",
           "geo": {}, "dns": [], "flows": [], "http": [], "incident": None,
           "quality": None, "resolution": None,
           "totals": {"flows": 0, "out_bytes": 0, "in_bytes": 0, "packets": 0}}

    if threat_detection is not None:
        out["classification"] = _safe(threat_detection.classify_ip, ip) or ""
        out["hostname"] = _safe(threat_detection.host_for, ip) or ""
        out["os"] = _safe(threat_detection.get_host_os, ip)
        # Cumulative totals for the whole session. The detectors work from these,
        # while the flow table below only holds currently-live flows (idle ones
        # are dropped after FLOW_TTL). Showing both means an analyst can
        # reconcile a volume-based alert with what they're looking at, instead of
        # seeing a "large transfer" alert next to a few KB of current traffic.
        try:
            rec = threat_detection.endpoint_stats.get(ip) or {}
            if rec:
                out["session"] = {
                    "out_bytes": rec.get("out_bytes", 0),
                    "in_bytes": rec.get("in_bytes", 0),
                    "packets": rec.get("packets", 0),
                    "first": rec.get("first"),
                    "last": rec.get("last"),
                }
        except Exception:
            pass
    if not out["hostname"] and dns_log is not None:
        out["hostname"] = _safe(dns_log.name_for_ip, ip) or ""

    if threat_intel is not None:
        out["reputation"] = _safe(threat_intel.is_bad, ip)

    if geo_lookup is not None:
        out["geo"] = _safe(geo_lookup.get, ip) or {}

    # DNS history: every lookup that resolved to this IP, or asked for its name.
    if dns_log is not None:
        rows = _safe(dns_log.recent, 400) or []
        seen = set()
        for r in rows:
            if ip in (r.get("ips") or []):
                key = (r.get("name"), tuple(r.get("ips") or []))
                if key not in seen:
                    seen.add(key)
                    out["dns"].append({"name": r.get("name", ""),
                                       "type": r.get("type", ""),
                                       "ips": r.get("ips", []),
                                       "ts": r.get("ts", 0)})

    # Flows touching this IP.
    if flow_tracker is not None:
        flows = _safe(flow_tracker.flows, 800, "bytes") or []
        for f in flows:
            if f.get("src") == ip or f.get("dst") == ip:
                out["flows"].append(f)
                out["totals"]["flows"] += 1
                # Orient bytes relative to this IP: what it sent vs received.
                if f.get("src") == ip:
                    out["totals"]["out_bytes"] += f.get("out_bytes", 0)
                    out["totals"]["in_bytes"] += f.get("in_bytes", 0)
                else:
                    out["totals"]["out_bytes"] += f.get("in_bytes", 0)
                    out["totals"]["in_bytes"] += f.get("out_bytes", 0)
                out["totals"]["packets"] += f.get("packets", 0)
        out["flows"] = out["flows"][:40]

    # Cleartext HTTP involving this IP.
    if http_log is not None:
        rows = _safe(http_log.recent, 400) or []
        for r in rows:
            if ip in (r.get("client", ""), r.get("server_ip", "")):
                out["http"].append({"method": r.get("method", ""),
                                    "url": r.get("url", "") or r.get("host", ""),
                                    "status": r.get("status", 0),
                                    "flags": [f[1] for f in (r.get("flags") or [])]})
        out["http"] = out["http"][:20]

    # Correlated incident, if this IP is an actor.
    if correlation is not None:
        out["incident"] = _safe(correlation.get, ip)

    # Passive link quality (RTT / jitter).
    if rtt_tracker is not None:
        out["quality"] = _safe(rtt_tracker.quality, ip)

    # DNS resolution chain (which lookup led here).
    if dns_chain is not None:
        out["resolution"] = _safe(dns_chain.chains_for_ip, ip, dns_log=dns_log,
                                  flow_tracker=flow_tracker)

    out["risk"] = _risk(out)
    return out


def _risk(p):
    """A quick headline verdict so the UI can lead with it."""
    if p.get("reputation"):
        rep = p["reputation"]
        cat = rep.get("category", "known-bad") if isinstance(rep, dict) else "known-bad"
        return ("HOSTILE", f"On a threat feed ({cat}).")
    inc = p.get("incident")
    if inc and inc.get("level") in ("HIGH", "CRITICAL"):
        return (inc["level"], f"Part of a {inc['level'].lower()} incident: {inc.get('pattern') or 'multiple signals'}.")
    # heavy outbound = worth a look
    t = p.get("totals", {})
    if t.get("out_bytes", 0) > 20 * 1024 * 1024 and t["out_bytes"] > t.get("in_bytes", 0) * 5:
        return ("WATCH", "Large outbound transfer to this address.")
    if p.get("classification") == "external":
        return ("NORMAL", "External address, nothing flagged.")
    if p.get("classification"):
        return ("NORMAL", f"{p['classification'].capitalize()} address.")
    return ("UNKNOWN", "No information gathered.")


def summarize(p):
    """Human-readable lines for the enrichment panel."""
    if not p:
        return ["Nothing to show."]
    lines = []
    level, why = p.get("risk", ("UNKNOWN", ""))
    lines.append(f"{p['ip']}    [{level}]")
    if p.get("hostname"):
        lines.append(f"Hostname:  {p['hostname']}")
    if p.get("os") and p["os"].get("os") not in (None, "unknown"):
        osd = p["os"]
        lines.append(f"OS guess:  {osd['os']} ({osd.get('confidence', 0)}% - passive)")
    q = p.get("quality")
    if q and (q.get("rtt_ms") is not None or q.get("jitter_ms") is not None):
        bits = []
        if q.get("rtt_ms") is not None:
            bits.append(f"RTT ~{q['rtt_ms']:.0f}ms")
        if q.get("jitter_ms") is not None:
            bits.append(f"jitter {q['jitter_ms']:.0f}ms")
        lines.append(f"Link:  {q.get('verdict', '')} ({', '.join(bits)})")
    lines.append(why)
    lines.append("")

    geo = p.get("geo") or {}
    where = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
    if where or geo.get("isp") or geo.get("asn"):
        lines.append("LOCATION / NETWORK")
        if where:
            lines.append(f"   {where}")
        if geo.get("isp"):
            lines.append(f"   ISP:  {geo['isp']}")
        if geo.get("asn"):
            lines.append(f"   ASN:  {geo['asn']}")
        lines.append("")

    if p.get("reputation"):
        rep = p["reputation"]
        if isinstance(rep, dict):
            lines.append("REPUTATION")
            lines.append(f"   {rep.get('category', 'flagged')}  (source: {rep.get('source', '?')})")
            lines.append("")

    if p.get("dns"):
        lines.append(f"DNS ({len(p['dns'])} name(s) resolved here)")
        for d in p["dns"][:6]:
            lines.append(f"   {d['name']}  ({d['type']})")
        lines.append("")

    sess = p.get("session")
    if sess and (sess.get("out_bytes") or sess.get("in_bytes")):
        lines.append("SESSION TOTALS  (cumulative - what the detectors measure)")
        lines.append(f"   sent to this host:      {_fmt(sess['out_bytes'])}")
        lines.append(f"   received from it:       {_fmt(sess['in_bytes'])}")
        if sess.get("first") and sess.get("last"):
            span = max(0.0, sess["last"] - sess["first"])
            lines.append(f"   observed over:          {_duration(span)}")
        lines.append("")

    t = p.get("totals", {})
    if t.get("flows"):
        lines.append(f"LIVE FLOWS  ({t['flows']} currently active - idle flows age out)")
        lines.append(f"   sent by this host:  {_fmt(t['out_bytes'])}")
        lines.append(f"   received here:      {_fmt(t['in_bytes'])}")
        protos = {}
        for f in p["flows"]:
            key = f.get("protocol") or f.get("proto") or "?"
            protos[key] = protos.get(key, 0) + 1
        if protos:
            lines.append("   protocols:  " + ", ".join(f"{k} ({v})" for k, v in
                                                       sorted(protos.items(), key=lambda kv: -kv[1])))
        lines.append("")

    if p.get("http"):
        lines.append(f"HTTP ({len(p['http'])} request(s))")
        for h in p["http"][:5]:
            flag = "  [!]" if h["flags"] else ""
            lines.append(f"   {h['method']} {h['url'][:60]}  [{h['status'] or '-'}]{flag}")
        lines.append("")

    inc = p.get("incident")
    if inc:
        lines.append(f"INCIDENT #{inc['id']}  -  {inc['level']} (score {inc['score']})")
        if inc.get("pattern"):
            lines.append(f"   {inc['pattern']}")
        lines.append(f"   {inc['distinct_signals']} distinct detector(s), "
                     f"{inc['event_count']} event(s)")

    res = p.get("resolution")
    if res:
        lines.append("")
        if res.get("names"):
            top = res["names"][0]
            age = top.get("age")
            when = f"{age:.0f}s ago" if age is not None else "recently"
            lines.append("RESOLVED FROM")
            lines.append(f"   {top['name']} ({top['qtype']}, {when})")
            for nm in res["names"][1:3]:
                lines.append(f"   also: {nm['name']}")
        else:
            lines.append("RESOLVED FROM")
            lines.append("   no DNS lookup seen (hard-coded IP / cached / IP-literal)")
    return lines


def _duration(sec):
    sec = int(sec or 0)
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    return f"{sec // 3600}h {(sec % 3600) // 60}m"


def _fmt(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
