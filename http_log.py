"""HTTP transaction log - every cleartext HTTP request and response.

For traffic that isn't encrypted, HTTP tells you almost everything: what was
requested, from which host, what came back, and - through the User-Agent and
Server headers - what software is actually running on the network. That last
part is a passive software inventory you get for free, and it's genuinely useful
defensively: outdated browsers, curl/python/powershell user-agents that shouldn't
be talking to the internet, and IoT firmware strings all show up here.

It also catches the things worth flagging: credentials in a URL, downloads of
executables, requests to a bare IP with no Host header, and the beaconing-style
User-Agents that malware families use.

The parser is pure (bytes in, dict out) and never trusts the port - it keys off
the actual request line / status line, so HTTP on an odd port is still parsed.
`dns_log` and `protocol_id` see the same packets for different jobs; this one
reconstructs the transaction.
"""

import re
import threading
import time
from collections import deque

MAX_LOG = 2000
PENDING_TTL = 30

METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
           "TRACE", "CONNECT", "PROPFIND", "MKCOL", "COPY", "MOVE", "LOCK")

# Executable / installer extensions worth flagging on download.
RISKY_EXT = re.compile(
    r"\.(exe|dll|scr|bat|cmd|ps1|vbs|jar|msi|apk|sh|elf|bin|hta|com|cpl)(\?|$)", re.I)

# User-Agents that are automation/tooling rather than a browser.
TOOL_UA = re.compile(
    r"\b(curl|wget|python-requests|python-urllib|go-http-client|powershell|"
    r"libwww-perl|winhttp|axios|okhttp|java/|ruby|node-fetch|httpie|nikto|"
    r"sqlmap|nmap|masscan|metasploit|havij|zgrab)\b", re.I)

_log = deque(maxlen=MAX_LOG)
_pending = {}                 # (client, server, sport, dport) -> request awaiting response
_agents = {}                  # user-agent string -> {count, hosts, first, last}
_servers = {}                 # Server header -> {count, hosts}
_lock = threading.Lock()


# ---------- pure parsing ----------

def _headers(block):
    """Parse a header block (after the first line) into a lowercase-keyed dict."""
    out = {}
    for line in block.split("\r\n"):
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        out[key.strip().lower()] = val.strip()
    return out


def parse_request(payload):
    """Parse an HTTP request. Returns dict or None."""
    data = bytes(payload)
    head = data[:8192]
    nl = head.find(b"\r\n")
    if nl < 0:
        return None
    try:
        line = head[:nl].decode("latin-1")
    except Exception:
        return None
    parts = line.split(" ")
    if len(parts) != 3 or parts[0] not in METHODS or not parts[2].startswith("HTTP/"):
        return None
    method, target, version = parts
    blk_end = head.find(b"\r\n\r\n")
    headers = _headers(head[nl + 2:blk_end].decode("latin-1", "replace")
                       if blk_end > 0 else head[nl + 2:].decode("latin-1", "replace"))
    return {
        "kind": "request", "method": method, "target": target, "version": version,
        "host": headers.get("host", ""),
        "user_agent": headers.get("user-agent", ""),
        "referer": headers.get("referer", ""),
        "content_type": headers.get("content-type", ""),
        "content_length": headers.get("content-length", ""),
        "authorization": bool(headers.get("authorization")),
        "cookie": bool(headers.get("cookie")),
    }


def parse_response(payload):
    """Parse an HTTP response status line + headers. Returns dict or None."""
    data = bytes(payload)
    head = data[:8192]
    if not head.startswith(b"HTTP/"):
        return None
    nl = head.find(b"\r\n")
    if nl < 0:
        return None
    try:
        line = head[:nl].decode("latin-1")
    except Exception:
        return None
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})\s*(.*)", line)
    if not m:
        return None
    blk_end = head.find(b"\r\n\r\n")
    headers = _headers(head[nl + 2:blk_end].decode("latin-1", "replace")
                       if blk_end > 0 else head[nl + 2:].decode("latin-1", "replace"))
    return {
        "kind": "response", "status": int(m.group(1)), "reason": m.group(2).strip(),
        "server": headers.get("server", ""),
        "content_type": headers.get("content-type", ""),
        "content_length": headers.get("content-length", ""),
        "location": headers.get("location", ""),
    }


def parse(payload):
    """Parse either a request or a response from a payload."""
    return parse_request(payload) or parse_response(payload)


# ---------- transaction assembly ----------

def _prune(now):
    stale = [k for k, tx in _pending.items() if now - tx["ts"] > PENDING_TTL]
    for k in stale:
        _pending.pop(k, None)


def _url(host, target):
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{host}{target}" if host else target


def _note_agent(ua, host, ts):
    if not ua:
        return
    a = _agents.get(ua)
    if a is None:
        a = {"count": 0, "hosts": set(), "first": ts, "last": ts,
             "tool": bool(TOOL_UA.search(ua))}
        _agents[ua] = a
    a["count"] += 1
    a["last"] = ts
    if host:
        a["hosts"].add(host)


def _note_server(server, host):
    if not server:
        return
    s = _servers.get(server)
    if s is None:
        s = {"count": 0, "hosts": set()}
        _servers[server] = s
    s["count"] += 1
    if host:
        s["hosts"].add(host)


def observe(src_ip, dst_ip, sport, dport, payload, ts=None):
    """Feed a packet payload. Returns a completed transaction dict, or None.

    Findings are surfaced via the returned transaction's 'flags' list; the caller
    decides whether to raise events (keeps this module free of event coupling).
    """
    if not payload:
        return None
    msg = parse(payload)
    if not msg:
        return None
    ts = ts or time.time()

    with _lock:
        _prune(ts)
        if msg["kind"] == "request":
            key = (src_ip, dst_ip, sport, dport)
            url = _url(msg["host"], msg["target"])
            tx = {
                "ts": ts, "client": src_ip, "server_ip": dst_ip, "port": dport,
                "method": msg["method"], "host": msg["host"], "url": url,
                "target": msg["target"], "user_agent": msg["user_agent"],
                "referer": msg["referer"], "req_type": msg["content_type"],
                "authorization": msg["authorization"], "cookie": msg["cookie"],
                "status": 0, "reason": "", "server": "", "resp_type": "",
                "length": msg["content_length"], "location": "", "flags": [],
            }
            _note_agent(msg["user_agent"], msg["host"], ts)
            _pending[key] = tx
            _log.append(tx)
            _flag(tx)
            return None

        # response: match to the pending request on the mirrored 4-tuple
        key = (dst_ip, src_ip, dport, sport)
        tx = _pending.pop(key, None)
        if tx is None:
            tx = {"ts": ts, "client": dst_ip, "server_ip": src_ip, "port": sport,
                  "method": "", "host": "", "url": "", "target": "",
                  "user_agent": "", "referer": "", "req_type": "",
                  "authorization": False, "cookie": False, "flags": []}
            _log.append(tx)
        tx["status"] = msg["status"]
        tx["reason"] = msg["reason"]
        tx["server"] = msg["server"]
        tx["resp_type"] = msg["content_type"]
        if msg["content_length"]:
            tx["length"] = msg["content_length"]
        tx["location"] = msg["location"]
        _note_server(msg["server"], tx.get("host", ""))
        _flag(tx)
        return dict(tx)


def _flag(tx):
    """Attach finding tags to a transaction (idempotent)."""
    flags = set(tx.get("flags") or [])
    ua = tx.get("user_agent", "")
    target = tx.get("target", "")

    if tx.get("authorization"):
        flags.add(("WARNING", "HTTP Basic auth over cleartext - credentials are exposed"))
    if target and ("password=" in target.lower() or "passwd=" in target.lower()
                   or re.search(r"[?&](pwd|pass|token|api_?key|secret)=", target, re.I)):
        flags.add(("WARNING", "Sensitive-looking parameter in a cleartext URL"))
    if target and RISKY_EXT.search(target):
        flags.add(("WARNING", "Download of an executable/script over cleartext HTTP"))
    if ua and TOOL_UA.search(ua):
        tool = TOOL_UA.search(ua).group(0)
        flags.add(("INFO", f"Non-browser client ({tool}) - automation or tooling"))
    if tx.get("method") and not tx.get("host") and not target.startswith("http"):
        flags.add(("INFO", "Request with no Host header"))
    tx["flags"] = sorted(flags)


# ---------- read API ----------

def recent(limit=300, contains=None, only_flagged=False):
    with _lock:
        rows = list(_log)
    if contains:
        needle = contains.lower()
        rows = [r for r in rows
                if needle in (r.get("url", "") + r.get("host", "")
                              + r.get("user_agent", "") + r.get("client", "")).lower()]
    if only_flagged:
        rows = [r for r in rows if r.get("flags")]
    return [dict(r) for r in rows[-limit:]]


def user_agents(limit=100):
    with _lock:
        out = []
        for ua, a in _agents.items():
            out.append({"agent": ua, "count": a["count"], "tool": a["tool"],
                        "hosts": len(a["hosts"]), "first": a["first"], "last": a["last"]})
    out.sort(key=lambda d: d["count"], reverse=True)
    return out[:limit]


def servers(limit=100):
    with _lock:
        out = [{"server": s, "count": v["count"], "hosts": len(v["hosts"])}
               for s, v in _servers.items()]
    out.sort(key=lambda d: d["count"], reverse=True)
    return out[:limit]


def stats():
    with _lock:
        total = len(_log)
        requests = sum(1 for r in _log if r.get("method"))
        errors = sum(1 for r in _log if r.get("status", 0) >= 400)
        flagged = sum(1 for r in _log if r.get("flags"))
        tools = sum(1 for a in _agents.values() if a["tool"])
        n_ua = len(_agents)
    return {"total": total, "requests": requests, "errors": errors,
            "flagged": flagged, "user_agents": n_ua, "tool_agents": tools}


def count():
    with _lock:
        return len(_log)


def clear():
    with _lock:
        _log.clear()
        _pending.clear()
        _agents.clear()
        _servers.clear()
