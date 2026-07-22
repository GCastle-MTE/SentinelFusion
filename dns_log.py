"""DNS query log - every lookup this network makes, and what came back.

DNS is the most useful single source in threat hunting because it shows *intent*
before the connection happens: a machine asks for a name, then talks to whatever
IP came back. Logging both halves gives you three things:

  * A timeline of what was actually asked for, by which host.
  * A reverse map (`name_for_ip`) so a bare IP elsewhere in the app can be
    labelled with the domain it came from - "34.49.39.67" becomes meaningful.
  * The NXDOMAIN / SERVFAIL picture, which is where DGA malware shows up.

This is a plain, complete DNS message parser (header, questions, and A / AAAA /
CNAME / PTR / MX / TXT / SRV answers). Pure bytes-in, dict-out, so it is fully
testable without scapy.

Note: `dns_analyzer` does the tunneling/DGA *detection*; this module does the
logging and the reverse map. They read the same traffic for different purposes.
"""

import threading
import time
from collections import deque

QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
          28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS", 46: "RRSIG", 48: "DNSKEY",
          41: "OPT", 64: "SVCB", 65: "HTTPS", 252: "AXFR", 255: "ANY"}

RCODES = {0: "OK", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP",
          5: "REFUSED", 9: "NOTAUTH"}

MAX_LOG = 3000
PENDING_TTL = 30          # seconds to wait for a reply before forgetting a query

_log = deque(maxlen=MAX_LOG)
_pending = {}
_by_ip = {}
_by_domain = {}
_lock = threading.Lock()


# ---------- parser ----------

def decode_name(data, off, depth=0):
    """Decode a DNS name, following compression pointers. -> (name, next_off)."""
    labels = []
    n = len(data)
    jumped = False
    after = off
    steps = 0
    while 0 <= off < n and steps < 128:
        steps += 1
        length = data[off]
        if length == 0:
            off += 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= n:
                break
            ptr = ((length & 0x3F) << 8) | data[off + 1]
            if not jumped:
                after = off + 2
            jumped = True
            depth += 1
            if depth > 12:
                break
            off = ptr
            continue
        off += 1
        if off + length > n:
            break
        labels.append(data[off:off + length].decode("latin-1", "replace"))
        off += length
    if not jumped:
        after = off
    return ".".join(labels), after


def _ipv4(raw):
    return ".".join(str(b) for b in raw[:4])


def _ipv6(raw):
    groups = [f"{raw[i]:02x}{raw[i + 1]:02x}" for i in range(0, 16, 2)]
    return ":".join(g.lstrip("0") or "0" for g in groups)


def _rdata(data, rtype, start, end):
    """Decode RDATA for the record types worth logging."""
    raw = data[start:end]
    try:
        if rtype == 1 and len(raw) >= 4:
            return _ipv4(raw)
        if rtype == 28 and len(raw) >= 16:
            return _ipv6(raw)
        if rtype in (5, 2, 12):                      # CNAME / NS / PTR
            return decode_name(data, start)[0]
        if rtype == 15 and len(raw) >= 3:            # MX
            return decode_name(data, start + 2)[0]
        if rtype == 33 and len(raw) >= 7:            # SRV
            return decode_name(data, start + 6)[0]
        if rtype == 16:                              # TXT
            out, p = [], start
            while p < end:
                ln = data[p]
                p += 1
                out.append(data[p:p + ln].decode("latin-1", "replace"))
                p += ln
            return " ".join(out)[:120]
    except Exception:
        pass
    return ""


def parse_message(payload):
    """Parse a DNS message -> dict, or None if it isn't one."""
    data = bytes(payload)
    if len(data) < 12:
        return None
    flags = (data[2] << 8) | data[3]
    msg = {
        "id": (data[0] << 8) | data[1],
        "qr": (flags >> 15) & 1,
        "opcode": (flags >> 11) & 0xF,
        "rcode": flags & 0xF,
        "truncated": bool((flags >> 9) & 1),
        "questions": [],
        "answers": [],
    }
    qd = (data[4] << 8) | data[5]
    an = (data[6] << 8) | data[7]
    if qd > 20 or an > 100:
        return None
    off = 12
    try:
        for _ in range(qd):
            name, off = decode_name(data, off)
            if off + 4 > len(data):
                return None
            qtype = (data[off] << 8) | data[off + 1]
            off += 4
            msg["questions"].append((name, qtype))
        for _ in range(an):
            name, off = decode_name(data, off)
            if off + 10 > len(data):
                break
            rtype = (data[off] << 8) | data[off + 1]
            ttl = int.from_bytes(data[off + 4:off + 8], "big")
            rdlen = (data[off + 8] << 8) | data[off + 9]
            off += 10
            end = off + rdlen
            if end > len(data):
                break
            msg["answers"].append({
                "name": name,
                "type": QTYPES.get(rtype, str(rtype)),
                "ttl": ttl,
                "data": _rdata(data, rtype, off, end),
            })
            off = end
    except (IndexError, ValueError):
        return None
    if not msg["questions"]:
        return None
    return msg


# ---------- registry ----------

def _prune(now):
    stale = [k for k, tx in _pending.items() if now - tx["ts"] > PENDING_TTL]
    for k in stale:
        _pending.pop(k, None)


def _blank(ts, client, server, name, qtype):
    return {"ts": ts, "client": client, "server": server, "name": name,
            "type": QTYPES.get(qtype, str(qtype)), "rcode": "", "ips": [],
            "cnames": [], "ttl": 0, "answered": False}


def observe(src_ip, dst_ip, sport, dport, payload, ts=None):
    """Feed a DNS packet. Returns the completed transaction on a response, else None."""
    if 53 not in (sport, dport):
        return None
    msg = parse_message(payload)
    if not msg or msg["opcode"] != 0:
        return None
    qname, qtype = msg["questions"][0]
    if not qname:
        return None
    ts = ts or time.time()
    key = (msg["id"], src_ip if msg["qr"] == 0 else dst_ip, qname.lower())

    with _lock:
        _prune(ts)
        if msg["qr"] == 0:                            # query
            tx = _blank(ts, src_ip, dst_ip, qname, qtype)
            _pending[key] = tx
            _log.append(tx)
            return None

        tx = _pending.pop(key, None)                  # response
        if tx is None:
            tx = _blank(ts, dst_ip, src_ip, qname, qtype)
            _log.append(tx)
        tx["answered"] = True
        tx["rcode"] = RCODES.get(msg["rcode"], str(msg["rcode"]))
        for ans in msg["answers"]:
            if ans["type"] in ("A", "AAAA") and ans["data"]:
                if ans["data"] not in tx["ips"]:
                    tx["ips"].append(ans["data"])
                _by_ip[ans["data"]] = {"name": qname, "ts": ts}
            elif ans["type"] == "CNAME" and ans["data"]:
                if ans["data"] not in tx["cnames"]:
                    tx["cnames"].append(ans["data"])
            if ans["ttl"] and not tx["ttl"]:
                tx["ttl"] = ans["ttl"]

        agg = _by_domain.get(qname.lower())
        if agg is None:
            agg = {"name": qname, "count": 0, "first": ts, "last": ts,
                   "ips": set(), "types": set(), "nx": 0, "clients": set()}
            _by_domain[qname.lower()] = agg
        agg["count"] += 1
        agg["last"] = ts
        agg["ips"].update(tx["ips"])
        agg["types"].add(tx["type"])
        agg["clients"].add(tx["client"])
        if tx["rcode"] == "NXDOMAIN":
            agg["nx"] += 1
        return dict(tx)


def name_for_ip(ip):
    """The domain this IP was resolved from, if we saw the lookup."""
    with _lock:
        rec = _by_ip.get(ip)
        return rec["name"] if rec else ""


def recent(limit=300, contains=None, only_answered=False):
    with _lock:
        rows = list(_log)
    if contains:
        needle = contains.lower()
        rows = [r for r in rows
                if needle in r["name"].lower() or needle in r["client"]
                or any(needle in ip for ip in r["ips"])]
    if only_answered:
        rows = [r for r in rows if r["answered"]]
    return [dict(r) for r in rows[-limit:]]


def domains(limit=200):
    with _lock:
        out = []
        for agg in _by_domain.values():
            d = dict(agg)
            d["ips"] = sorted(agg["ips"])
            d["types"] = sorted(agg["types"])
            d["clients"] = sorted(agg["clients"])
            out.append(d)
    out.sort(key=lambda d: d["count"], reverse=True)
    return out[:limit]


def stats():
    with _lock:
        total = len(_log)
        nx = sum(1 for r in _log if r["rcode"] == "NXDOMAIN")
        fail = sum(1 for r in _log if r["rcode"] in ("SERVFAIL", "REFUSED"))
        unanswered = sum(1 for r in _log if not r["answered"])
        uniq = len(_by_domain)
        mapped = len(_by_ip)
    return {"total": total, "domains": uniq, "nxdomain": nx, "failed": fail,
            "unanswered": unanswered, "mapped_ips": mapped}


def count():
    with _lock:
        return len(_log)


def clear():
    with _lock:
        _log.clear()
        _pending.clear()
        _by_ip.clear()
        _by_domain.clear()
