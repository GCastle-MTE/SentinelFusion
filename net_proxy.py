"""Optional privacy routing for the tool's OWN outbound requests - now with chains.

Sends the OSINT / API lookups (threat-intel feeds, IP reputation, WiGLE) through
one or several proxy hops, so the queried services see the exit proxy's IP
instead of yours. This is analyst opsec: when you look up adversary-adjacent
infrastructure against public feeds, you don't hand those services your real
address. It routes *this tool's* research traffic only - it does not touch, hide,
or reroute anything else your machine does.

We do NOT launch Tor or any proxy - we route through whatever is already running.
Your own location lookup (geo_lookup.locate_self) deliberately stays direct so
the map still centres on you rather than an exit node.

A single hop is applied directly (requests' native proxy support). A *chain* of
two or more hops is served through a tiny local SOCKS5 forwarder that dials each
hop in turn (CONNECT through CONNECT through CONNECT...), so the tool points at
127.0.0.1 and the traffic exits the last hop. SOCKS support needs PySocks for the
single-hop path; the chain forwarder is pure stdlib.
"""

import socket
import struct
import threading
import importlib.util

_lock = threading.Lock()
_enabled = False
_chain = [{"scheme": "socks5", "host": "127.0.0.1", "port": 9050, "name": "Tor"}]
_socks_ok = None

_fwd_server = None
_fwd_port = None
_fwd_lock = threading.Lock()

TOR_HOST, TOR_PORT = "127.0.0.1", 9050
FORWARD_HOST = "127.0.0.1"


def configure(enabled, chain=None):
    """Set routing on/off and (optionally) replace the hop chain."""
    global _enabled
    with _lock:
        _enabled = bool(enabled)
        if chain is not None:
            parsed = _parse_chain(chain)
            if parsed:
                _restart_forwarder(parsed)
                globals()["_chain"] = parsed


def _parse_chain(chain):
    if isinstance(chain, str):
        chain = [chain]
    out = []
    for item in chain or []:
        hop = _parse_hop(item) if isinstance(item, str) else _norm_hop(item)
        if hop:
            out.append(hop)
    return out


def _parse_hop(s):
    s = str(s).strip()
    if not s:
        return None
    scheme = "socks5"
    if "://" in s:
        scheme, s = s.split("://", 1)
        scheme = scheme.lower()
    host, _, port = s.partition(":")
    try:
        port = int(port) if port else (9050 if "socks" in scheme else 8080)
    except ValueError:
        return None
    if not host:
        return None
    return {"scheme": scheme, "host": host, "port": port, "name": f"{host}:{port}"}


def _norm_hop(d):
    try:
        return {"scheme": str(d.get("scheme", "socks5")).lower(),
                "host": str(d["host"]), "port": int(d["port"]),
                "name": str(d.get("name") or f"{d['host']}:{d['port']}")}
    except Exception:
        return None


def chain():
    with _lock:
        return [dict(h) for h in _chain]


def enabled():
    with _lock:
        return _enabled


def socks_supported():
    global _socks_ok
    if _socks_ok is None:
        _socks_ok = importlib.util.find_spec("socks") is not None
    return _socks_ok


def active():
    """True if a proxy will actually be applied (enabled, set, usable)."""
    with _lock:
        hops = list(_chain)
        on = _enabled
    if not (on and hops):
        return False
    if len(hops) == 1 and hops[0]["scheme"].startswith("socks") and not socks_supported():
        return False
    return True


def _hop_url(hop):
    scheme = hop["scheme"]
    if scheme == "socks5":
        scheme = "socks5h"
    return f"{scheme}://{hop['host']}:{hop['port']}"


def proxies():
    """requests-style proxies dict, or None when routing is off/unusable."""
    if not active():
        return None
    with _lock:
        hops = list(_chain)
    if len(hops) == 1:
        u = _hop_url(hops[0])
        return {"http": u, "https": u}
    port = _ensure_forwarder(hops)
    if not port:
        u = _hop_url(hops[-1])
        return {"http": u, "https": u}
    u = (f"socks5h://{FORWARD_HOST}:{port}" if socks_supported()
         else f"http://{FORWARD_HOST}:{port}")
    return {"http": u, "https": u}


def hop_status(timeout=0.8):
    """Per-hop reachability, for the UI."""
    out = []
    for hop in chain():
        d = dict(hop)
        d["up"] = _reachable(hop["host"], hop["port"], timeout)
        out.append(d)
    return out


def _reachable(host, port, timeout=0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tor_running(host=TOR_HOST, port=TOR_PORT, timeout=0.6):
    return _reachable(host, port, timeout)


def check_exit_ip(timeout=15):
    """Public IP as seen through the current chain (or direct), or None."""
    import requests
    try:
        r = requests.get("https://api.ipify.org?format=json",
                         proxies=proxies(), timeout=timeout)
        return r.json().get("ip")
    except Exception:
        return None


def _ensure_forwarder(hops):
    global _fwd_server, _fwd_port
    with _fwd_lock:
        if _fwd_server is not None and _fwd_port:
            return _fwd_port
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((FORWARD_HOST, 0))
            srv.listen(16)
            _fwd_port = srv.getsockname()[1]
            _fwd_server = srv
            threading.Thread(target=_forward_accept_loop, args=(srv, list(hops)),
                             daemon=True).start()
            return _fwd_port
        except Exception:
            _fwd_server, _fwd_port = None, None
            return None


def _restart_forwarder(new_hops):
    global _fwd_server, _fwd_port
    with _fwd_lock:
        if _fwd_server is not None:
            try:
                _fwd_server.close()
            except Exception:
                pass
        _fwd_server, _fwd_port = None, None


def _forward_accept_loop(srv, hops):
    while True:
        try:
            client, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_handle_client, args=(client, hops),
                         daemon=True).start()


def _handle_client(client, hops):
    try:
        target = _socks5_server_handshake(client)
        if not target:
            client.close()
            return
        host, port = target
        upstream = _dial_through_chain(hops, host, port)
        if upstream is None:
            try:
                client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            except Exception:
                pass
            client.close()
            return
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        _splice(client, upstream)
    except Exception:
        try:
            client.close()
        except Exception:
            pass


def _recvn(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _socks5_server_handshake(client):
    """Act as a SOCKS5 server to our own requests call. Returns (host, port)."""
    hdr = _recvn(client, 2)
    if not hdr or hdr[0] != 0x05:
        return None
    nmethods = hdr[1]
    _recvn(client, nmethods)
    client.sendall(b"\x05\x00")
    req = _recvn(client, 4)
    if not req or req[1] != 0x01:
        return None
    atyp = req[3]
    if atyp == 0x01:
        host = socket.inet_ntoa(_recvn(client, 4))
    elif atyp == 0x03:
        ln = _recvn(client, 1)[0]
        host = _recvn(client, ln).decode("latin-1")
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, _recvn(client, 16))
    else:
        return None
    port = struct.unpack(">H", _recvn(client, 2))[0]
    return host, port


def _dial_through_chain(hops, dest_host, dest_port):
    """Open first hop, then SOCKS5-CONNECT through each hop to the destination."""
    try:
        sock = socket.create_connection((hops[0]["host"], hops[0]["port"]), timeout=8)
    except Exception:
        return None
    try:
        for i, hop in enumerate(hops):
            if i + 1 < len(hops):
                nxt_host, nxt_port = hops[i + 1]["host"], hops[i + 1]["port"]
            else:
                nxt_host, nxt_port = dest_host, dest_port
            if not _socks5_client_connect(sock, nxt_host, nxt_port):
                sock.close()
                return None
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        return None


def _socks5_client_connect(sock, host, port):
    """SOCKS5 CONNECT to (host, port) over an established socket."""
    try:
        sock.sendall(b"\x05\x01\x00")
        resp = _recvn(sock, 2)
        if not resp or resp[1] != 0x00:
            return False
        addr = host.encode("latin-1")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr + struct.pack(">H", port))
        rep = _recvn(sock, 4)
        if not rep or rep[1] != 0x00:
            return False
        atyp = rep[3]
        if atyp == 0x01:
            _recvn(sock, 4)
        elif atyp == 0x03:
            _recvn(sock, _recvn(sock, 1)[0])
        elif atyp == 0x04:
            _recvn(sock, 16)
        _recvn(sock, 2)
        return True
    except Exception:
        return False


def _splice(a, b):
    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except Exception:
                    pass
    threading.Thread(target=pump, args=(a, b), daemon=True).start()
    threading.Thread(target=pump, args=(b, a), daemon=True).start()
