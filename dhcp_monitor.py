"""Rogue DHCP server detection.

A healthy network has exactly one DHCP server. If a second one starts answering,
whoever runs it can hand out their own address as your default gateway or DNS
server - which quietly puts them in the middle of your traffic. It's one of the
classic LAN attacks, and it also happens by accident (a spare router plugged in
with its DHCP still switched on, or a VM bridging its own DHCP onto the LAN).

This watches DHCP replies that are already broadcast to the segment, tracks which
servers are answering, and alerts when an unexpected one shows up. Purely
passive - it never sends DHCP traffic of its own.

The parser is pure (bytes in, dict out) so it's testable without scapy.
"""

import threading
import time

import events

MSG_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
             5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}

# DHCP replies (server -> client). These are the ones that identify a server.
SERVER_MSGS = {2, 5, 6}

_servers = {}
_lock = threading.Lock()
_expected = None          # the DHCP server we consider legitimate
_alerted = set()


def parse_dhcp_options(payload):
    """Pull the interesting options out of a BOOTP/DHCP payload.
    Returns {'msg_type', 'server_id', 'router', 'dns', 'lease', 'domain'}."""
    data = bytes(payload)
    out = {"msg_type": 0, "server_id": "", "router": "", "dns": [],
           "lease": 0, "domain": ""}
    idx = data.find(b"\x63\x82\x53\x63")          # DHCP magic cookie
    if idx < 0:
        return out
    i = idx + 4
    n = len(data)
    steps = 0
    while i < n and steps < 256:
        steps += 1
        opt = data[i]
        i += 1
        if opt == 0:                               # pad
            continue
        if opt == 255 or i >= n:                   # end
            break
        ln = data[i]
        i += 1
        if i + ln > n:
            break
        val = data[i:i + ln]
        i += ln
        if opt == 53 and ln >= 1:
            out["msg_type"] = val[0]
        elif opt == 54 and ln >= 4:
            out["server_id"] = ".".join(str(b) for b in val[:4])
        elif opt == 3 and ln >= 4:
            out["router"] = ".".join(str(b) for b in val[:4])
        elif opt == 6:
            out["dns"] = [".".join(str(b) for b in val[j:j + 4])
                          for j in range(0, ln - 3, 4)]
        elif opt == 51 and ln >= 4:
            out["lease"] = int.from_bytes(val[:4], "big")
        elif opt == 15:
            out["domain"] = val.decode("latin-1", "replace").strip("\x00")
    return out


def set_expected(ip):
    """Mark the DHCP server we trust (normally the default gateway). Anything
    else that answers is then treated as rogue."""
    global _expected
    if ip:
        _expected = ip


def expected():
    return _expected


def observe(src_ip, src_mac, sport, dport, payload):
    """Feed a DHCP packet. Only server replies are considered."""
    if sport != 67 and dport != 67:
        return
    info = parse_dhcp_options(payload)
    mtype = info.get("msg_type")
    if mtype not in SERVER_MSGS:
        return
    server = info.get("server_id") or src_ip
    if not server or server in ("0.0.0.0", "255.255.255.255"):
        return

    now = time.time()
    with _lock:
        rec = _servers.get(server)
        if rec is None:
            rec = {"ip": server, "mac": src_mac or "", "first": now, "last": now,
                   "count": 0, "router": "", "dns": [], "domain": "", "rogue": False}
            _servers[server] = rec
        rec["last"] = now
        rec["count"] += 1
        if src_mac and not rec["mac"]:
            rec["mac"] = src_mac
        if info.get("router"):
            rec["router"] = info["router"]
        if info.get("dns"):
            rec["dns"] = info["dns"]
        if info.get("domain"):
            rec["domain"] = info["domain"]

        # First server we ever see becomes the reference if none was set.
        global _expected
        if _expected is None:
            _expected = server
            return

        if server == _expected:
            return
        rec["rogue"] = True
        fire = server not in _alerted
        if fire:
            _alerted.add(server)

    if fire:
        detail = f"Unexpected DHCP server {server}"
        if src_mac:
            detail += f" ({src_mac})"
        detail += f" is answering {MSG_TYPES.get(mtype, mtype)}s; expected {_expected}"
        if info.get("router"):
            detail += f". It advertises gateway {info['router']}"
        if info.get("dns"):
            detail += f", DNS {', '.join(info['dns'][:2])}"
        detail += ". A rogue DHCP server can redirect your traffic through it."
        events.log_event("ALERT", "rogue", server, detail)


def servers():
    with _lock:
        return [dict(r) for r in sorted(_servers.values(), key=lambda r: r["ip"])]


def count():
    with _lock:
        return len(_servers)


def rogue_count():
    with _lock:
        return sum(1 for r in _servers.values() if r["rogue"])


def reset():
    global _expected
    with _lock:
        _servers.clear()
        _alerted.clear()
        _expected = None
