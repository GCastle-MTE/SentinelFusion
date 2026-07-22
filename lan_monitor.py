"""LAN survey - build and maintain an inventory of the devices on your own
network, and passively fingerprint them from the broadcast/multicast chatter
they already emit (mDNS, SSDP/UPnP, DHCP, NetBIOS). No man-in-the-middle: this
only reads traffic that is already broadcast to the whole segment, plus the
results of an active ARP sweep.

The parsers are pure (fed raw payload bytes) so they're easy to test. scapy is
kept out of this module - the capture engine extracts packet fields and calls
observe()/note_arp(); the ARP sweep lives in network_discovery.
"""

import threading
import time

import events

# --- device-type inference tables ---
# mDNS service type prefix -> friendly device kind.
SERVICE_KINDS = {
    "_googlecast": "Chromecast / Google TV",
    "_androidtvremote": "Android TV",
    "_airplay": "Apple AirPlay",
    "_raop": "AirPlay speaker",
    "_spotify-connect": "Speaker (Spotify)",
    "_sonos": "Sonos speaker",
    "_printer": "Printer",
    "_ipp": "Printer",
    "_ipps": "Printer",
    "_pdl-datastream": "Printer",
    "_scanner": "Scanner",
    "_uscan": "Scanner",
    "_homekit": "HomeKit device",
    "_hap": "HomeKit device",
    "_hue": "Philips Hue bridge",
    "_apple-mobdev2": "Apple device",
    "_companion-link": "Apple device",
    "_smb": "File share (SMB)",
    "_afpovertcp": "Apple file share",
    "_ssh": "SSH host",
    "_sftp-ssh": "SSH host",
    "_daap": "iTunes library",
    "_touch-able": "Apple Remote target",
    "_amzn-wplay": "Amazon device",
    "_amzn-alexa": "Amazon Echo",
    "_nvstream": "NVIDIA Shield",
    "_workstation": "Workstation",
    "_http": "Web service",
    "_https": "Web service",
    "_ewbe": "Smart device",
    "_miio": "Xiaomi device",
    "_googlezone": "Google device",
}

# SSDP/UPnP urn fragment -> device kind.
SSDP_KINDS = {
    "internetgatewaydevice": "Router / gateway",
    "wandevice": "Router / gateway",
    "mediarenderer": "Media renderer",
    "mediaserver": "Media server",
    "dial": "Smart TV / casting",
    "printer": "Printer",
    "basic:1": "UPnP device",
}

_hosts = {}
_lock = threading.Lock()
_self_ip = None
_baseline_ready = False


def mark_baseline():
    """Call once the initial inventory has settled; after this, a genuinely new
    host raises a 'device' alert."""
    global _baseline_ready
    _baseline_ready = True


# ---------- pure parsers ----------

def _decode_name(data, off, depth=0):
    """Decode a DNS name at offset, following compression pointers. Returns
    (name, offset_after)."""
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
        if (length & 0xC0) == 0xC0:               # compression pointer
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
        try:
            labels.append(data[off:off + length].decode("latin-1"))
        except Exception:
            labels.append("")
        off += length
    if not jumped:
        after = off
    return ".".join(labels), after


def parse_mdns(payload):
    """Return (hostnames, service_types) seen in an mDNS message."""
    data = bytes(payload)
    if len(data) < 12:
        return [], []
    qd = (data[4] << 8) | data[5]
    an = (data[6] << 8) | data[7]
    names = []
    off = 12
    for _ in range(min(qd, 50)):
        name, off = _decode_name(data, off)
        names.append(name)
        off += 4
        if off > len(data):
            break
    for _ in range(min(an, 50)):
        name, off = _decode_name(data, off)
        names.append(name)
        if off + 10 > len(data):
            break
        rtype = (data[off] << 8) | data[off + 1]
        off += 8                                   # type(2)+class(2)+ttl(4)
        rdlen = (data[off] << 8) | data[off + 1]
        off += 2
        rdstart = off
        if rtype in (12, 33):                      # PTR / SRV carry a name
            noff = rdstart + (6 if rtype == 33 else 0)
            tgt, _ = _decode_name(data, noff)
            names.append(tgt)
        off = rdstart + rdlen
        if off > len(data):
            break
    services, hosts = [], []
    for nm in names:
        if not nm:
            continue
        low = nm.lower()
        if low.startswith("_") or "._tcp" in low or "._udp" in low:
            services.append(nm)
        elif low.endswith(".local"):
            hosts.append(nm)
    return hosts, services


def parse_ssdp(payload):
    """Parse an SSDP/UPnP message into {server, kinds, location, usn}."""
    try:
        text = bytes(payload).decode("latin-1", "replace")
    except Exception:
        return {}
    info = {"server": "", "kinds": [], "location": "", "usn": ""}
    for line in text.split("\r\n"):
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "server":
            info["server"] = val
        elif key == "location":
            info["location"] = val
        elif key == "usn":
            info["usn"] = val
        elif key in ("st", "nt") and val:
            info["kinds"].append(val)
    return info


def parse_dhcp(payload):
    """Pull the hostname (option 12) and vendor class (option 60) from a
    BOOTP/DHCP payload."""
    data = bytes(payload)
    out = {"hostname": "", "vendor_class": ""}
    idx = data.find(b"\x63\x82\x53\x63")           # DHCP magic cookie
    if idx < 0:
        return out
    i = idx + 4
    n = len(data)
    steps = 0
    while i < n and steps < 256:
        steps += 1
        opt = data[i]
        i += 1
        if opt == 0:
            continue
        if opt == 255 or i >= n:
            break
        ln = data[i]
        i += 1
        if i + ln > n:
            break
        val = data[i:i + ln]
        i += ln
        if opt == 12:
            out["hostname"] = val.decode("latin-1", "replace").strip("\x00").strip()
        elif opt == 60:
            out["vendor_class"] = val.decode("latin-1", "replace").strip("\x00").strip()
    return out


def parse_netbios(payload):
    """Decode the queried NetBIOS name (first-level encoding) from an NBNS
    packet on UDP 137."""
    data = bytes(payload)
    if len(data) < 13 or data[12] != 0x20:
        return ""
    enc = data[13:45]
    if len(enc) < 32:
        return ""
    chars = []
    for j in range(0, 32, 2):
        hi = enc[j] - 0x41
        lo = enc[j + 1] - 0x41
        if not (0 <= hi < 16 and 0 <= lo < 16):
            break
        chars.append(chr((hi << 4) | lo))
    name = "".join(c for c in "".join(chars) if 32 <= ord(c) < 127).strip()
    return name


def kind_from(services, vendor="", ssdp=None):
    """Best-effort device type from services / SSDP / vendor."""
    for svc in services:
        low = svc.lower()
        for prefix, kind in SERVICE_KINDS.items():
            if prefix in low and kind:
                return kind
    if ssdp:
        blob = (" ".join(ssdp.get("kinds", [])) + " " + ssdp.get("server", "")).lower()
        for frag, kind in SSDP_KINDS.items():
            if frag in blob:
                return kind
    return ""


# ---------- registry ----------

def _rec(ip):
    r = _hosts.get(ip)
    if r is None:
        now = time.time()
        r = {"ip": ip, "mac": "", "vendor": "", "hostname": "", "kind": "",
             "workgroup": "", "name_source": "", "findings": [],
             "services": set(), "ports": set(), "first": now, "last": now,
             "active": False, "passive": False}
        _hosts[ip] = r
        if _baseline_ready and ip != _self_ip:
            try:
                events.log_event("WARNING", "device", ip,
                                 f"New device appeared on the network ({ip})")
            except Exception:
                pass
    return r


def _looks_ipv4(ip):
    """True only for addresses that can be a real host on the segment.

    Filters the addresses that legitimately appear as a packet source but are
    not devices: 0.0.0.0 (DHCP DISCOVER and ARP probes both use it), the
    broadcast address, multicast (mDNS/SSDP live at 224.0.0.251 / 239.255.255.250),
    and loopback. Without this they register as phantom hosts and fire false
    new-device alerts. Link-local 169.254.x is kept - a device that failed DHCP
    is still a real device worth seeing.
    """
    parts = str(ip).split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    if not all(p.isdigit() for p in parts):
        return False
    first = octets[0]
    if first == 0 or first == 127:                 # unspecified / loopback
        return False
    if 224 <= first <= 239:                        # multicast
        return False
    if first >= 240:                               # reserved / broadcast
        return False
    if octets == [255, 255, 255, 255]:
        return False
    return True


def set_self(ip):
    global _self_ip
    _self_ip = ip


def note_arp(ip, mac, vendor=""):
    if not _looks_ipv4(ip):
        return
    with _lock:
        r = _rec(ip)
        if mac:
            r["mac"] = mac
        if vendor and not r["vendor"]:
            r["vendor"] = vendor
        r["last"] = time.time()


def observe(src_ip, src_mac, sport, dport, payload):
    """Route a broadcast/multicast service packet to the right parser and
    enrich the source host. Pure w.r.t. scapy - fields are pre-extracted."""
    if not _looks_ipv4(src_ip) or not payload:
        return
    ports = (sport, dport)
    with _lock:
        r = _rec(src_ip)
        if src_mac and not r["mac"]:
            r["mac"] = src_mac
        r["last"] = time.time()
        r["passive"] = True
        try:
            if 5353 in ports:
                hosts, services = parse_mdns(payload)
                for h in hosts:
                    if not r["hostname"] or r["hostname"].endswith(".local"):
                        r["hostname"] = h
                r["services"].update(services)
                k = kind_from(services, r["vendor"])
                if k:
                    r["kind"] = k
            elif 1900 in ports:
                info = parse_ssdp(payload)
                k = kind_from((), r["vendor"], info)
                if k:
                    r["kind"] = k
                if info.get("server") and not r["kind"]:
                    r["kind"] = info["server"][:40]
            elif 67 in ports or 68 in ports:
                info = parse_dhcp(payload)
                if info.get("hostname") and not r["hostname"]:
                    r["hostname"] = info["hostname"]
                if info.get("vendor_class") and not r["vendor"]:
                    r["vendor"] = info["vendor_class"]
            elif 137 in ports:
                nm = parse_netbios(payload)
                if nm and not r["hostname"]:
                    r["hostname"] = nm
        except Exception:
            pass


def ingest_scan(devices):
    """Merge active ARP-scan results. Returns the list of IPs seen for the
    first time (for new-device alerting)."""
    new = []
    with _lock:
        for d in devices:
            ip = d.get("ip")
            if not _looks_ipv4(ip):
                continue
            fresh = ip not in _hosts
            r = _rec(ip)
            if d.get("mac"):
                r["mac"] = d["mac"]
            if d.get("vendor"):
                r["vendor"] = d["vendor"]
            if d.get("hostname") and not r["hostname"]:
                r["hostname"] = d["hostname"]
            r["active"] = True
            r["last"] = time.time()
            if fresh:
                new.append(ip)
    return new


def note_hostname(ip, hostname, source="", workgroup="", mac=""):
    """Record an actively-resolved name (reverse DNS / NetBIOS / mDNS)."""
    if not _looks_ipv4(ip):
        return
    with _lock:
        r = _rec(ip)
        if hostname:
            r["hostname"] = hostname
            r["name_source"] = source
        if workgroup:
            r["workgroup"] = workgroup
        if mac and not r["mac"]:
            r["mac"] = mac
        r["last"] = time.time()


def note_findings(ip, findings):
    """Store port-scan findings for a host."""
    if not _looks_ipv4(ip):
        return
    with _lock:
        r = _rec(ip)
        r["findings"] = list(findings)
        r["ports"].update(int(f["port"]) for f in findings)


def mark_ports(ip, ports):
    with _lock:
        r = _rec(ip)
        r["ports"].update(int(p) for p in ports)


def get(ip):
    with _lock:
        r = _hosts.get(ip)
        return _snapshot(r) if r else None


def hosts():
    with _lock:
        out = [_snapshot(r) for r in _hosts.values()]
    out.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")) if _looks_ipv4(d["ip"]) else (0,))
    return out


def count():
    with _lock:
        return len(_hosts)


def _snapshot(r):
    d = dict(r)
    d["services"] = sorted(r["services"])
    d["ports"] = sorted(r["ports"])
    d["findings"] = list(r["findings"])
    d["is_self"] = (r["ip"] == _self_ip)
    return d
