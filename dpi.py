# dpi.py
#
# Deep packet inspection helpers.
#
# inspect(packet) -> dict of application-layer findings (DNS, TLS SNI, HTTP,
#   a printable payload preview). Most modern traffic is encrypted, so the
#   useful signal is usually DNS query names and the TLS server name (SNI).
#
# dump(packet) -> a tcpdump/Wireshark-style text breakdown of one packet:
#   a one-line summary, the full layer decode, and a hex/ASCII dump.
import math

from scapy.all import hexdump

# HTTP layer (registers dissection for plaintext HTTP when importable).
try:
    from scapy.layers.http import HTTPRequest
    _HAVE_HTTP = True
except Exception:
    HTTPRequest = None
    _HAVE_HTTP = False

def enable_tls():
    # No-op. scapy's TLS layer clashes with newer cryptography builds (it
    # imports a path that recent cryptography removed), so we parse the TLS
    # ClientHello directly from packet bytes instead - see _parse_client_hello.
    return


def _decode(value):
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def _printable(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def _tls_client_hello_bytes(packet):
    # Raw bytes of a TLS record iff this packet starts a ClientHello.
    try:
        if not packet.haslayer("Raw"):
            return None
        data = bytes(packet["Raw"].load)
    except Exception:
        return None
    # record: type 0x16 (handshake), version 0x03xx; handshake msg 0x01 = ClientHello
    if len(data) < 6 or data[0] != 0x16 or data[1] != 0x03 or data[5] != 0x01:
        return None
    return data


def _parse_client_hello(data):
    # Manual TLS ClientHello parse -> {sni, ja3, ja3_string}. Bytes only, so it
    # works regardless of scapy/cryptography versions.
    try:
        pos = 9  # skip record hdr(5) + hs type(1) + hs len(3)
        client_version = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        pos += 32                       # random
        pos += 1 + data[pos]            # session id
        cs_len = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            c = int.from_bytes(data[pos + i:pos + i + 2], "big")
            if c not in _GREASE:
                ciphers.append(c)
        pos += cs_len
        pos += 1 + data[pos]            # compression methods

        sni, exts, curves, ecpf = None, [], [], []
        if pos + 2 <= len(data):
            ext_total = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            end = min(pos + ext_total, len(data))
            while pos + 4 <= end:
                etype = int.from_bytes(data[pos:pos + 2], "big")
                elen = int.from_bytes(data[pos + 2:pos + 4], "big")
                pos += 4
                edata = data[pos:pos + elen]
                pos += elen
                if etype not in _GREASE:
                    exts.append(etype)
                if etype == 0x0000 and len(edata) >= 5:        # server name
                    nlen = int.from_bytes(edata[3:5], "big")
                    sni = edata[5:5 + nlen].decode(errors="replace")
                elif etype == 0x000a and len(edata) >= 2:      # supported groups
                    glen = int.from_bytes(edata[0:2], "big")
                    for i in range(0, glen, 2):
                        g = int.from_bytes(edata[2 + i:2 + i + 2], "big")
                        if g not in _GREASE:
                            curves.append(g)
                elif etype == 0x000b and len(edata) >= 1:      # EC point formats
                    for i in range(edata[0]):
                        ecpf.append(edata[1 + i])

        join = lambda xs: "-".join(str(x) for x in xs)
        ja3_str = f"{client_version},{join(ciphers)},{join(exts)},{join(curves)},{join(ecpf)}"
        import hashlib
        return {"sni": sni, "ja3": hashlib.md5(ja3_str.encode()).hexdigest(),
                "ja3_string": ja3_str}
    except Exception:
        return {}


def _extract_sni(packet):
    data = _tls_client_hello_bytes(packet)
    if not data:
        return None
    return _parse_client_hello(data).get("sni")


def tls_info(packet):
    # Cheap ClientHello check + single parse -> {"sni", "ja3"} or None.
    # Safe to call on every packet: returns immediately for non-ClientHellos.
    data = _tls_client_hello_bytes(packet)
    if not data:
        return None
    parsed = _parse_client_hello(data)
    sni, ja3 = parsed.get("sni"), parsed.get("ja3")
    if not sni and not ja3:
        return None
    return {"sni": sni, "ja3": ja3}


def inspect(packet):
    findings = {}

    # DNS query name (plaintext, very informative).
    if packet.haslayer("DNS"):
        try:
            dns = packet["DNS"]
            if dns.qd is not None:
                findings["dns_query"] = _decode(dns.qd.qname).rstrip(".")
        except Exception:
            pass

    # Plaintext HTTP request.
    if _HAVE_HTTP and packet.haslayer(HTTPRequest):
        try:
            h = packet[HTTPRequest]
            method = _decode(h.Method) if h.Method else ""
            host = _decode(h.Host) if h.Host else ""
            path = _decode(h.Path) if h.Path else ""
            findings["http"] = f"{method} {host}{path}".strip()
        except Exception:
            pass

    # TLS server name from the handshake.
    sni = _extract_sni(packet)
    if sni:
        findings["tls_sni"] = sni

    # Printable preview of any raw payload.
    if packet.haslayer("Raw"):
        try:
            preview = _printable(bytes(packet["Raw"].load))[:80]
            if preview.strip("."):
                findings["payload_preview"] = preview
        except Exception:
            pass

    return findings


def summarize(findings_list):
    # Condense per-packet findings into a short, de-duplicated summary string.
    names = []
    for f in findings_list:
        for key in ("dns_query", "tls_sni", "http"):
            v = f.get(key)
            if v and v not in names:
                names.append(v)
    return "; ".join(names[:20])


def dump(packet):
    # tcpdump-style breakdown of a single packet.
    parts = [packet.summary(), ""]
    try:
        shown = packet.show(dump=True)
        if shown:
            parts.append(shown)
    except Exception:
        pass
    parts.append("")
    try:
        hd = hexdump(packet, dump=True)
        if hd:
            parts.append(hd)
    except Exception:
        pass
    return "\n".join(p for p in parts if p is not None)


# ===========================================================================
# Full single-packet analysis: pull every useful field out of one packet
# across all layers, plus the derived intelligence a specialist wants.
# full_analysis(packet) -> ordered list of (section_title, [(field, value)..]).
# ===========================================================================

COMMON_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    514: "Syslog", 587: "SMTP", 636: "LDAPS", 853: "DoT", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5060: "SIP", 5222: "XMPP", 5353: "mDNS",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9001: "Tor", 9050: "Tor", 27017: "MongoDB",
}
_IPPROTO = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
            50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
_ICMP = {0: "echo reply", 3: "destination unreachable", 5: "redirect",
         8: "echo request", 11: "time exceeded", 13: "timestamp",
         14: "timestamp reply", 30: "traceroute"}
_DNSTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
            16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS", 65: "HTTPS",
            251: "IXFR", 252: "AXFR", 255: "ANY"}
_FLAG_BITS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
              (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
_GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
           0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa}


def _service_name(port):
    try:
        return COMMON_PORTS.get(int(port), "")
    except Exception:
        return ""


def _ipproto(p):
    try:
        return _IPPROTO.get(int(p), "")
    except Exception:
        return ""


def _icmp_type(t):
    try:
        return _ICMP.get(int(t), "")
    except Exception:
        return ""


def _dnstype(t):
    try:
        return _DNSTYPE.get(int(t), str(t))
    except Exception:
        return str(t)


def _ttl_os_hint(ttl):
    # Initial TTLs: 64 (Linux/macOS/Unix), 128 (Windows), 255 (network gear).
    try:
        ttl = int(ttl)
    except Exception:
        return ""
    if ttl > 128:
        base, name = 255, "network device (Cisco/Solaris)"
    elif ttl > 64:
        base, name = 128, "Windows"
    elif ttl > 32:
        base, name = 64, "Linux / macOS / Unix"
    else:
        return f"unusual (TTL {ttl})"
    return f"{name} (~{base - ttl} hops away)"


def _tcp_flags_str(flags):
    try:
        flags = int(flags)
    except Exception:
        return str(flags)
    names = [n for bit, n in _FLAG_BITS if flags & bit]
    return ", ".join(names) if names else "none"


def _parse_tcp_options(tcp):
    out = []
    try:
        for opt in getattr(tcp, "options", []) or []:
            if isinstance(opt, (tuple, list)):
                k = opt[0]
                v = opt[1] if len(opt) > 1 else None
                out.append(f"{k}={v}" if v not in (None, b"", ()) else str(k))
            else:
                out.append(str(opt))
    except Exception:
        pass
    return ", ".join(out)


def _entropy(data):
    if not data:
        return 0.0
    from collections import Counter
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _strings(data, minlen=4, limit=14):
    out, cur = [], []
    for b in data:
        if 32 <= b < 127:
            cur.append(chr(b))
        else:
            if len(cur) >= minlen:
                out.append("".join(cur))
            cur = []
            if len(out) >= limit:
                break
    if len(cur) >= minlen and len(out) < limit:
        out.append("".join(cur))
    return out


def _mac_vendor(mac):
    try:
        from scapy.all import conf
        m = conf.manufdb
        for attr in ("_get_manuf", "_get_short_manuf"):
            fn = getattr(m, attr, None)
            if fn:
                v = fn(mac)
                if v and v != mac:
                    return v
        lk = getattr(m, "lookup", None)
        if lk:
            res = lk(mac)
            if res:
                return getattr(res, "manuf", None) or (
                    res[0] if isinstance(res, (list, tuple)) else str(res))
    except Exception:
        pass
    return ""


def _ja3(packet):
    # Best-effort JA3 client fingerprint, parsed from the ClientHello bytes.
    data = _tls_client_hello_bytes(packet)
    if not data:
        return None
    parsed = _parse_client_hello(data)
    if parsed.get("ja3"):
        return {"ja3": parsed["ja3"], "ja3_string": parsed["ja3_string"]}
    return None


def _anomalies(packet):
    notes = []
    try:
        if packet.haslayer("IP"):
            ip = packet["IP"]
            if int(getattr(ip, "frag", 0)) > 0 or (int(getattr(ip, "flags", 0)) & 1):
                notes.append("fragmented IP packet")
            ttl = int(getattr(ip, "ttl", 64))
            if ttl < 10:
                notes.append(f"very low TTL ({ttl})")
        if packet.haslayer("TCP"):
            f = int(packet["TCP"].flags)
            if f == 0:
                notes.append("NULL scan (no flags set)")
            elif (f & 0x01) and (f & 0x02):
                notes.append("SYN+FIN (illegal flag combo)")
            elif (f & 0x29) == 0x29:
                notes.append("XMAS scan (FIN/PSH/URG)")
            dport = int(packet["TCP"].dport)
            if dport in (21, 23, 80, 110, 143):
                notes.append(f"plaintext service on port {dport} (credentials at risk)")
    except Exception:
        pass
    return notes


def full_analysis(packet):
    enable_tls()  # so TLS handshake fields dissect when present
    sections = []

    frame = []
    try:
        frame.append(("Captured length", f"{len(packet)} bytes"))
    except Exception:
        pass
    ts = getattr(packet, "time", None)
    if ts:
        import time as _t
        frame.append(("Timestamp", _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(float(ts)))))
    if frame:
        sections.append(("Frame", frame))

    if packet.haslayer("Ether"):
        e = packet["Ether"]
        sm, dm = str(getattr(e, "src", "")), str(getattr(e, "dst", ""))
        sv, dv = _mac_vendor(sm), _mac_vendor(dm)
        sections.append(("Ethernet", [
            ("Source MAC", sm + (f"  ({sv})" if sv else "")),
            ("Dest MAC", dm + (f"  ({dv})" if dv else "")),
            ("EtherType", hex(int(getattr(e, "type", 0) or 0))),
        ]))

    if packet.haslayer("ARP"):
        a = packet["ARP"]
        op = int(getattr(a, "op", 0))
        opname = {1: "request (who-has)", 2: "reply (is-at)"}.get(op, str(op))
        sections.append(("ARP", [
            ("Operation", opname),
            ("Sender", f"{getattr(a, 'psrc', '')} @ {getattr(a, 'hwsrc', '')}"),
            ("Target", f"{getattr(a, 'pdst', '')} @ {getattr(a, 'hwdst', '')}"),
        ]))

    if packet.haslayer("IP"):
        ip = packet["IP"]
        ttl = getattr(ip, "ttl", None)
        hint = _ttl_os_hint(ttl)
        proto = int(getattr(ip, "proto", 0))
        sections.append(("IP", [
            ("Version", str(getattr(ip, "version", 4))),
            ("Source", str(ip.src)),
            ("Destination", str(ip.dst)),
            ("TTL", f"{ttl}" + (f"   ->  {hint}" if hint else "")),
            ("Protocol", f"{proto}" + (f" ({_ipproto(proto)})" if _ipproto(proto) else "")),
            ("Total length", str(getattr(ip, "len", ""))),
            ("Identification", str(getattr(ip, "id", ""))),
            ("Flags", str(getattr(ip, "flags", ""))),
            ("Fragment offset", str(getattr(ip, "frag", 0))),
            ("TOS / DSCP", str(getattr(ip, "tos", 0))),
            ("Header checksum", hex(int(getattr(ip, "chksum", 0) or 0))),
        ]))

    if packet.haslayer("TCP"):
        t = packet["TCP"]
        sp, dp = int(t.sport), int(t.dport)
        sections.append(("TCP", [
            ("Source port", f"{sp}" + (f"  ({_service_name(sp)})" if _service_name(sp) else "")),
            ("Dest port", f"{dp}" + (f"  ({_service_name(dp)})" if _service_name(dp) else "")),
            ("Sequence", str(getattr(t, "seq", ""))),
            ("Acknowledgment", str(getattr(t, "ack", ""))),
            ("Flags", _tcp_flags_str(getattr(t, "flags", 0))),
            ("Window size", str(getattr(t, "window", ""))),
            ("Options", _parse_tcp_options(t) or "(none)"),
        ]))
    elif packet.haslayer("UDP"):
        u = packet["UDP"]
        sp, dp = int(u.sport), int(u.dport)
        sections.append(("UDP", [
            ("Source port", f"{sp}" + (f"  ({_service_name(sp)})" if _service_name(sp) else "")),
            ("Dest port", f"{dp}" + (f"  ({_service_name(dp)})" if _service_name(dp) else "")),
            ("Length", str(getattr(u, "len", ""))),
            ("Checksum", hex(int(getattr(u, "chksum", 0) or 0))),
        ]))

    if packet.haslayer("ICMP"):
        ic = packet["ICMP"]
        ty = int(getattr(ic, "type", -1))
        sections.append(("ICMP", [
            ("Type", f"{ty}" + (f" ({_icmp_type(ty)})" if _icmp_type(ty) else "")),
            ("Code", str(getattr(ic, "code", 0))),
            ("ID", str(getattr(ic, "id", ""))),
            ("Sequence", str(getattr(ic, "seq", ""))),
        ]))

    if packet.haslayer("DNS"):
        d = packet["DNS"]
        rows = [("Type", "response" if int(getattr(d, "qr", 0)) else "query")]
        try:
            if d.qd is not None:
                qt = int(getattr(d.qd, "qtype", 0))
                rows.append(("Question", f"{_decode(d.qd.qname).rstrip('.')}  ({_dnstype(qt)})"))
        except Exception:
            pass
        try:
            ans = []
            for k in range(int(getattr(d, "ancount", 0) or 0)):
                ans.append(_decode(d.an[k].rdata))
            if ans:
                rows.append(("Answers", ", ".join(ans[:8])))
        except Exception:
            pass
        sections.append(("DNS", rows))

    if _HAVE_HTTP and packet.haslayer(HTTPRequest):
        h = packet[HTTPRequest]
        rows = []
        for label, attr in (("Method", "Method"), ("Host", "Host"), ("Path", "Path"),
                            ("User-Agent", "User_Agent"), ("Referer", "Referer")):
            val = getattr(h, attr, None)
            if val:
                rows.append((label, _decode(val)))
        if rows:
            sections.append(("HTTP request", rows))

    sni = _extract_sni(packet)
    ja3 = _ja3(packet)
    tls_rows = []
    if sni:
        tls_rows.append(("SNI (server name)", sni))
    if ja3:
        tls_rows.append(("JA3 (best-effort)", ja3["ja3"]))
    if tls_rows:
        sections.append(("TLS", tls_rows))

    if packet.haslayer("Raw"):
        try:
            data = bytes(packet["Raw"].load)
            ent = _entropy(data)
            rows = [
                ("Length", f"{len(data)} bytes"),
                ("Entropy", f"{ent:.2f} bits/byte"
                 + ("   (high - likely encrypted/compressed)" if ent > 7.2 else "")),
            ]
            strs = _strings(data)
            if strs:
                rows.append(("Strings", "  |  ".join(strs)))
            rows.append(("ASCII preview", _printable(data)[:96]))
            sections.append(("Payload", rows))
        except Exception:
            pass

    sec = []
    if packet.haslayer("TCP") or packet.haslayer("UDP"):
        l4 = packet["TCP"] if packet.haslayer("TCP") else packet["UDP"]
        svc = _service_name(getattr(l4, "dport", 0)) or _service_name(getattr(l4, "sport", 0))
        if svc:
            sec.append(("Likely service", svc))
    if packet.haslayer("IP"):
        hint = _ttl_os_hint(getattr(packet["IP"], "ttl", None))
        if hint:
            sec.append(("OS hint (TTL)", hint))
    if ja3:
        sec.append(("TLS JA3", ja3["ja3"]))
    notes = _anomalies(packet)
    if notes:
        sec.append(("Notes", "; ".join(notes)))
    if sec:
        sections.append(("Security", sec))

    return sections
