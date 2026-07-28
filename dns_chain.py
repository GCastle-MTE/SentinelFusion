"""DNS resolution chains - why does this connection exist?

Every outbound connection to a named host started with a DNS lookup. This links
the two back together: given a live flow to some IP, it finds the DNS query that
resolved to that IP, when it was asked, and which process now holds the
connection. Read forwards it answers "this lookup led to these connections"; read
backwards it answers "this connection exists because the app resolved this
domain."

That backwards direction is the useful one for inspection: you see a flow to
104.16.x.x, and instead of a bare IP you get "chrome.exe -> resolved
telemetry.example (2s ago) -> this TLS flow." A connection to an IP with *no*
preceding DNS lookup is itself notable (hard-coded IP, IP-literal C2, or a cached
resolution) and gets flagged.

Injected dns_log / flow_tracker so it stays testable and cycle-free.
"""

import time


def chains_for_ip(ip, *, dns_log=None, flow_tracker=None, max_age=1800):
    """Build the resolution chain(s) for one IP:

        {ip, names:[{name, qtype, ts, age, client}], flows:[...], had_dns}

    `names` are the DNS queries that resolved to this IP (most recent first).
    `flows` are current flows touching the IP. `had_dns` is False when the IP was
    contacted with no observed lookup - worth noting.
    """
    now = time.time()
    out = {"ip": ip, "names": [], "flows": [], "had_dns": False}

    if dns_log is not None:
        try:
            rows = dns_log.recent(500) or []
        except Exception:
            rows = []
        seen = set()
        for r in rows:
            if ip in (r.get("ips") or []):
                name = r.get("name", "")
                key = (name, r.get("type", ""))
                if key in seen:
                    continue
                seen.add(key)
                ts = r.get("ts", 0)
                age = now - ts if ts else None
                if age is not None and age > max_age:
                    continue
                out["names"].append({
                    "name": name, "qtype": r.get("type", ""), "ts": ts,
                    "age": age, "client": r.get("client", ""),
                })
        out["names"].sort(key=lambda d: d["ts"] or 0, reverse=True)
        out["had_dns"] = bool(out["names"])

    if flow_tracker is not None:
        try:
            for f in (flow_tracker.flows(800, "bytes") or []):
                if ip in (f.get("src"), f.get("dst")):
                    out["flows"].append(f)
        except Exception:
            pass
    return out


def chain_summary(chain):
    """One-line-per-fact plain-language account of a resolution chain."""
    ip = chain.get("ip", "?")
    lines = []
    if chain.get("names"):
        top = chain["names"][0]
        age = top.get("age")
        when = f"{age:.0f}s ago" if age is not None else "recently"
        lines.append(f"{ip} was resolved from {top['name']} ({top['qtype']}, {when}).")
        for n in chain["names"][1:4]:
            lines.append(f"   also: {n['name']} ({n['qtype']})")
    else:
        if _is_local(ip):
            # A LAN address is reached directly, never through DNS. Calling that
            # "hard-coded / IP-literal" implies something suspicious about a
            # router or printer behaving entirely normally.
            lines.append(f"{ip} is a local address - reached directly, so no "
                         "DNS lookup is expected.")
        else:
            lines.append(f"{ip} was contacted with no observed DNS lookup "
                         "(hard-coded IP, cached resolution, or IP-literal).")
    fl = chain.get("flows") or []
    if fl:
        lines.append(f"{len(fl)} active flow(s) to this address:")
        for f in fl[:4]:
            proto = f.get("protocol") or f.get("proto", "")
            lines.append(f"   {f.get('src')}:{f.get('sport')} -> "
                         f"{f.get('dst')}:{f.get('dport')} {proto}")
    return lines


def resolution_graph(*, dns_log=None, flow_tracker=None, max_age=1800, limit=200):
    """A forward view: recent domains -> the IPs they resolved to -> whether any
    of those IPs currently have a live flow. Returns rows for a table/graph.
    """
    now = time.time()
    rows = []
    if dns_log is None:
        return rows

    # Which IPs are live right now?
    live_ips = set()
    if flow_tracker is not None:
        try:
            for f in (flow_tracker.flows(800, "bytes") or []):
                for k in ("src", "dst"):
                    if f.get(k):
                        live_ips.add(f[k])
        except Exception:
            pass

    try:
        recs = dns_log.recent(limit) or []
    except Exception:
        recs = []
    for r in recs:
        ts = r.get("ts", 0)
        if ts and (now - ts) > max_age:
            continue
        ips = r.get("ips") or []
        rows.append({
            "name": r.get("name", ""),
            "qtype": r.get("type", ""),
            "ips": ips,
            "ts": ts,
            "client": r.get("client", ""),
            "live": any(ip in live_ips for ip in ips),
        })
    rows.sort(key=lambda d: d["ts"] or 0, reverse=True)
    return rows


_LOCAL_NETS = None


def _is_local(ip):
    """True for addresses reached directly rather than via public DNS.

    Deliberately explicit instead of using ipaddress.is_private, which also
    covers documentation ranges (192.0.2.0/24, 203.0.113.0/24 and friends).
    Those are not addresses anyone reaches on a LAN, and quietly treating them
    as local would suppress a genuine IP-literal finding if one ever appeared.
    """
    global _LOCAL_NETS
    try:
        import ipaddress
        addr = ipaddress.ip_address(str(ip or ""))
    except Exception:
        return False
    if (addr.is_loopback or addr.is_link_local or addr.is_multicast
            or addr.is_unspecified):
        return True
    if _LOCAL_NETS is None:
        import ipaddress as _ip
        _LOCAL_NETS = [_ip.ip_network(n) for n in (
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC1918
            "100.64.0.0/10",                                    # CGNAT
            "fc00::/7",                                         # IPv6 ULA
        )]
    for net in _LOCAL_NETS:
        try:
            if addr in net:
                return True
        except TypeError:
            continue        # v4 address against a v6 network
    return False
