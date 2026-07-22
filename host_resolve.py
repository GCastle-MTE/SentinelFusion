"""Resolve hostnames for devices on your own LAN.

Reverse DNS usually comes back empty on a home network (the router rarely serves
PTR records for its leases), so this asks the devices themselves, using the two
standard name services they already answer:

  * NBNS node status  - a NetBIOS "adapter status" query to UDP 137. This is
    exactly what `nbtstat -A <ip>` sends, and Windows machines answer it with
    their computer name, workgroup, and MAC.
  * mDNS reverse       - a unicast PTR query for <ip>.in-addr.arpa to UDP 5353.
    Apple, Linux, Android and most IoT gear answer with their <name>.local.

Both are ordinary UDP name lookups - the same requests these hosts field from
the OS every day. Plain sockets, so no scapy and no Administrator needed.

Payload builders and parsers are pure (bytes in, dict out) so they're testable.
"""

import socket
import struct

import lan_monitor

# NetBIOS suffix -> what that name entry represents.
NB_SUFFIX = {
    0x00: "workstation",
    0x03: "messenger",
    0x20: "file server",
    0x1B: "domain master browser",
    0x1C: "domain controllers",
    0x1D: "master browser",
    0x1E: "browser elections",
}


# ---------- NBNS (NetBIOS Name Service) ----------

def _nb_encode(name):
    """First-level NetBIOS encoding: each byte -> two nibble chars offset by 'A'."""
    padded = name.ljust(15)[:15] + "\x00"
    out = bytearray()
    for ch in padded.encode("latin-1", "replace"):
        out.append(0x41 + (ch >> 4))
        out.append(0x41 + (ch & 0x0F))
    return bytes(out)


def nbstat_query(txid=0x4321):
    """Build an NBSTAT (node status) request for the wildcard name '*'."""
    hdr = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    name = bytes([0x20]) + _nb_encode("*") + b"\x00"
    return hdr + name + struct.pack(">HH", 0x0021, 0x0001)   # NBSTAT, IN


def parse_nbstat(data):
    """Parse an NBSTAT response -> {'name', 'workgroup', 'names', 'mac'}."""
    out = {"name": "", "workgroup": "", "names": [], "mac": ""}
    data = bytes(data)
    if len(data) < 57 or data[12] != 0x20:
        return out
    # header(12) + encoded name(1+32+1) + type(2) + class(2) + ttl(4) + rdlen(2)
    off = 12 + 34 + 2 + 2 + 4 + 2
    if off >= len(data):
        return out
    count = data[off]
    off += 1
    for _ in range(min(count, 64)):
        if off + 18 > len(data):
            break
        raw = data[off:off + 15]
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        off += 18
        nm = raw.decode("latin-1", "replace").strip()
        nm = "".join(c for c in nm if 32 <= ord(c) < 127).strip()
        group = bool(flags & 0x8000)
        if not nm:
            continue
        out["names"].append({"name": nm, "suffix": suffix, "group": group,
                             "kind": NB_SUFFIX.get(suffix, f"0x{suffix:02x}")})
        if suffix == 0x00 and not group and not out["name"]:
            out["name"] = nm            # unique workstation name = the computer
        if suffix == 0x00 and group and not out["workgroup"]:
            out["workgroup"] = nm       # group name = the workgroup/domain
    if off + 6 <= len(data):
        out["mac"] = ":".join(f"{b:02x}" for b in data[off:off + 6])
    return out


def query_nbns(ip, timeout=1.0):
    """Ask a host for its NetBIOS name table. {} if it doesn't answer."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(nbstat_query(), (ip, 137))
        data, _ = sock.recvfrom(2048)
        return parse_nbstat(data)
    except Exception:
        return {}
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ---------- mDNS reverse lookup ----------

def mdns_reverse_query(ip, txid=0x0000):
    """Build a PTR query for <reversed ip>.in-addr.arpa."""
    labels = ip.split(".")[::-1] + ["in-addr", "arpa"]
    qname = b""
    for label in labels:
        raw = label.encode("latin-1", "replace")[:63]
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    hdr = struct.pack(">HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    return hdr + qname + struct.pack(">HH", 12, 1)           # PTR, IN


def query_mdns(ip, timeout=1.0):
    """Unicast mDNS reverse lookup -> '<name>.local' or ''."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(mdns_reverse_query(ip), (ip, 5353))
        data, _ = sock.recvfrom(2048)
        hosts, _services = lan_monitor.parse_mdns(data)
        for h in hosts:
            if h:
                return h
        return ""
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


# ---------- combined ----------

def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def resolve(ip, timeout=1.0):
    """Best-effort hostname for a LAN device, cheapest method first.
    Returns {'hostname', 'source', 'workgroup', 'mac'} - hostname '' if unknown."""
    out = {"hostname": "", "source": "", "workgroup": "", "mac": ""}

    name = reverse_dns(ip)
    if name:
        out.update(hostname=name, source="reverse DNS")
        return out

    nb = query_nbns(ip, timeout=timeout)
    if nb.get("name"):
        out.update(hostname=nb["name"], source="NetBIOS",
                   workgroup=nb.get("workgroup", ""), mac=nb.get("mac", ""))
        return out

    name = query_mdns(ip, timeout=timeout)
    if name:
        out.update(hostname=name, source="mDNS")
        return out

    return out
