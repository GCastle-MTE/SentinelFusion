"""Port-independent protocol identification.

A port number is a hint, not an answer. Real DPI asks what a stream *is* from its
bytes, then compares that to the port it arrived on. That comparison is the whole
point defensively:

  * SSH on 443, or a raw tunnel on 53, is someone routing around egress filtering.
  * A service on a non-standard port is inventory you didn't know you had.
  * High-entropy traffic that isn't TLS is either a custom encrypted tunnel or
    something compressed - both worth a look on a port that should be plaintext.

`classify()` matches payload signatures and never trusts the port. `assess()`
turns a classification into a defensive judgement. Both are pure (bytes in, dict
out) so they're fully testable without scapy.
"""

import math

# Where each protocol is *supposed* to live. Used only to spot mismatches -
# never to identify anything.
STANDARD_PORTS = {
    "HTTP": {80, 8000, 8008, 8080, 8888, 591, 3128, 8081},
    "TLS": {443, 465, 563, 636, 853, 989, 990, 993, 995, 5061, 8443},
    "SSH": {22},
    "FTP": {21},
    "SMTP": {25, 587, 2525},
    "POP3": {110},
    "IMAP": {143},
    "Telnet": {23},
    "DNS": {53, 5353, 5355},
    "SMB": {445, 139},
    "RDP": {3389},
    "VNC": {5900, 5901, 5902},
    "MySQL": {3306},
    "PostgreSQL": {5432},
    "Redis": {6379},
    "MQTT": {1883, 8883},
    "SIP": {5060, 5061},
    "NTP": {123},
    "SNMP": {161, 162},
    "QUIC": {443, 80},
    "BitTorrent": {6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889},
    "WireGuard": {51820},
    "OpenVPN": {1194},
    "IRC": {6667, 6697},
}

# Ports almost always allowed outbound - so a foreign protocol showing up on one
# is the classic way to tunnel past a firewall.
EVASION_PORTS = {53: "DNS", 80: "HTTP", 443: "HTTPS", 123: "NTP", 25: "SMTP"}

TLS_VERSIONS = {0x00: "SSL 3.0", 0x01: "TLS 1.0", 0x02: "TLS 1.1",
                0x03: "TLS 1.2", 0x04: "TLS 1.3"}

_HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"TRACE ", b"CONNECT ", b"PROPFIND ", b"MKCOL ")

def entropy_threshold(n):
    """The entropy bar for a payload of n bytes, or None if it's too short to judge.

    Entropy is capped by sample count, not just randomness: 400 random bytes only
    reach ~7.46 because you cannot fill 256 bins uniformly with 400 draws. These
    are measured ceilings for random data:

        64B -> 5.77    256B -> 7.17    512B -> 7.59    2048B -> 7.91
        128B -> 6.54   400B -> 7.46    1024B -> 7.81   4096B -> 7.96

    A single fixed bar (say 7.5) therefore misses every short encrypted payload.
    Plaintext, by contrast, measures ~4.4 at *every* length - so these bars sit
    just under the random minimum for each size and far above text.
    """
    if n >= 1024:
        return 7.5
    if n >= 512:
        return 7.2
    if n >= 256:
        return 6.8
    if n >= 128:
        return 6.2
    return None


def entropy(data):
    """Shannon entropy in bits per byte. ~8.0 = random/encrypted, ~4-5 = text."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    out = 0.0
    for c in counts:
        if c:
            p = c / n
            out -= p * math.log2(p)
    return round(out, 2)


def _line(data, limit=70):
    text = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0][:limit]
    return text.decode("latin-1", "replace").strip()


# ---------- signature detectors: return a detail string, or None ----------

def _http(d):
    for method in _HTTP_METHODS:
        if d.startswith(method):
            return _line(d)
    if d.startswith(b"HTTP/1."):
        return _line(d)
    return None


def _tls(d):
    if len(d) < 6 or d[0] not in (0x14, 0x15, 0x16, 0x17) or d[1] != 0x03:
        return None
    if d[2] > 0x04:
        return None
    ver = TLS_VERSIONS.get(d[2], f"0x03{d[2]:02x}")
    kinds = {0x14: "ChangeCipherSpec", 0x15: "Alert", 0x16: "Handshake",
             0x17: "ApplicationData"}
    if d[0] == 0x16 and len(d) > 5:
        hs = {1: "ClientHello", 2: "ServerHello", 11: "Certificate",
              12: "ServerKeyExchange", 14: "ServerHelloDone",
              16: "ClientKeyExchange"}.get(d[5])
        if hs:
            return f"{ver} {hs}"
    return f"{ver} {kinds[d[0]]}"


def _ssh(d):
    return _line(d, 60) if d.startswith(b"SSH-") else None


def _smb(d):
    if len(d) > 8 and d[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "SMB2/3" if d[4] == 0xFE else "SMB1"
    if len(d) > 4 and d[0:4] in (b"\xffSMB", b"\xfeSMB"):
        return "SMB2/3" if d[0] == 0xFE else "SMB1"
    return None


def _rdp(d):
    # TPKT: version 3, reserved 0, then a 16-bit length that should match.
    if len(d) >= 5 and d[0] == 0x03 and d[1] == 0x00:
        ln = (d[2] << 8) | d[3]
        if 4 <= ln <= 65535 and abs(ln - len(d)) <= 4:
            return "RDP / TPKT"
    return None


def _bittorrent(d):
    if d.startswith(b"\x13BitTorrent protocol"):
        return "BitTorrent handshake"
    if d[:4] in (b"d1:a", b"d1:q", b"d1:r") or d.startswith(b"d1:ad2:id"):
        return "BitTorrent DHT"
    return None


def _ftp(d):
    up = d[:80].upper()
    if d.startswith(b"220") and b"FTP" in up:
        return _line(d, 60)
    for cmd in (b"USER ", b"PASS ", b"RETR ", b"STOR ", b"LIST", b"PASV", b"EPSV"):
        if up.startswith(cmd):
            return "FTP command"
    return None


def _smtp(d):
    up = d[:80].upper()
    if d.startswith(b"220") and (b"SMTP" in up or b"ESMTP" in up):
        return _line(d, 60)
    for cmd in (b"EHLO ", b"HELO ", b"MAIL FROM", b"RCPT TO", b"STARTTLS"):
        if up.startswith(cmd):
            return "SMTP command"
    return None


def _pop3(d):
    if d.startswith(b"+OK") and b"\r\n" in d[:80]:
        return _line(d, 60)
    return None


def _imap(d):
    if d.startswith(b"* OK") and b"IMAP" in d[:90].upper():
        return _line(d, 60)
    return None


def _telnet(d):
    # IAC + command is only a 2-byte magic (~1 in 16k of random data). Real
    # negotiation arrives as a run of IAC triplets with valid option codes, so
    # check the option and demand a second triplet when there's room for one.
    if len(d) < 3 or d[0] != 0xFF or d[1] not in (0xFB, 0xFC, 0xFD, 0xFE):
        return None
    if d[2] > 49 and d[2] != 255:                     # valid Telnet options
        return None
    if len(d) >= 6 and (d[3] != 0xFF or d[4] not in (0xFB, 0xFC, 0xFD, 0xFE)):
        return None
    return "Telnet negotiation"


def _vnc(d):
    if d.startswith(b"RFB "):
        return _line(d, 12)
    return None


def _mysql(d):
    # Greeting: 3-byte little-endian payload length, sequence 0, protocol
    # version 10. Validating the length against the real packet size is what
    # stops two magic bytes matching random data.
    if len(d) < 6 or d[3] != 0x00 or d[4] != 0x0A:
        return None
    plen = d[0] | (d[1] << 8) | (d[2] << 16)
    if not 10 <= plen <= 4096 or abs((plen + 4) - len(d)) > 4:
        return None
    if b"\x00" not in d[5:60]:
        return None
    return "MySQL greeting"


def _postgres(d):
    # StartupMessage: int32 length, then protocol 3.0 (0x00030000).
    if len(d) >= 8 and d[4:8] == b"\x00\x03\x00\x00":
        return "PostgreSQL startup"
    return None


def _redis(d):
    if d.startswith(b"*") and b"\r\n" in d[:32] and d[1:2].isdigit():
        return "Redis RESP"
    if d.startswith(b"+PONG") or d.startswith(b"+OK\r\n") or d.startswith(b"-NOAUTH"):
        return "Redis"
    return None


def _irc(d):
    up = d[:32].upper()
    for cmd in (b"NICK ", b"USER ", b"PASS ", b"JOIN ", b"PRIVMSG "):
        if up.startswith(cmd):
            return "IRC command"
    if d.startswith(b":") and b" 001 " in d[:64]:
        return "IRC welcome"
    return None


def _dns(d):
    # Header sanity: opcode 0, sane counts, and a decodable first label.
    if len(d) < 12:
        return None
    flags = (d[2] << 8) | d[3]
    opcode = (flags >> 11) & 0xF
    qd = (d[4] << 8) | d[5]
    if opcode != 0 or qd < 1 or qd > 4:
        return None
    if ((d[6] << 8) | d[7]) > 60:
        return None
    ln = d[12]
    if ln == 0 or ln > 63 or 13 + ln > len(d):
        return None
    return "DNS query" if not (flags >> 15) & 1 else "DNS response"


def _ntp(d):
    # Mode+version alone match ~15% of random 48-byte blobs (measured), so the
    # rest of the header has to be sane too: stratum <= 16, and poll/precision
    # inside the ranges RFC 5905 actually uses.
    if len(d) not in (48, 68):
        return None
    mode = d[0] & 0x07
    ver = (d[0] >> 3) & 0x07
    if mode not in (1, 2, 3, 4, 5) or ver not in (3, 4):
        return None
    if d[1] > 16:                                     # stratum
        return None
    poll = d[2] - 256 if d[2] > 127 else d[2]
    if not 0 <= poll <= 17:
        return None
    precision = d[3] - 256 if d[3] > 127 else d[3]
    if not -32 <= precision <= 0:
        return None
    return f"NTP v{ver} mode {mode}"


def _snmp(d):
    if len(d) > 6 and d[0] == 0x30 and d[2] == 0x02 and d[3] == 0x01:
        ver = {0: "v1", 1: "v2c", 3: "v3"}.get(d[4])
        if ver:
            return f"SNMP {ver}"
    return None


def _quic(d):
    if len(d) >= 5 and (d[0] & 0x80) and (d[0] & 0x40):
        ver = int.from_bytes(d[1:5], "big")
        if ver == 1:
            return "QUIC v1"
        if ver == 0:
            return "QUIC version negotiation"
        if 0xFF000000 <= ver <= 0xFF0000FF:
            return f"QUIC draft-{ver & 0xFF}"
    return None


def _wireguard(d):
    if len(d) >= 4 and d[0] in (1, 2, 3, 4) and d[1] == 0 and d[2] == 0 and d[3] == 0:
        sizes = {1: 148, 2: 92, 3: 64}
        if d[0] in sizes and len(d) != sizes[d[0]]:
            return None
        return {1: "WireGuard handshake init", 2: "WireGuard handshake response",
                3: "WireGuard cookie reply", 4: "WireGuard transport data"}[d[0]]
    return None


def _sip(d):
    up = d[:16].upper()
    for m in (b"INVITE ", b"REGISTER ", b"OPTIONS ", b"BYE ", b"ACK ", b"SIP/2.0"):
        if up.startswith(m):
            return _line(d, 60)
    return None


def _mqtt(d):
    if len(d) >= 8 and (d[0] >> 4) == 1 and b"MQTT" in d[:12]:
        return "MQTT CONNECT"
    return None


# Deliberately NOT here: RTP. Its header is only two version bits plus a
# payload-type range, so a single packet matches random data roughly 3% of the
# time - measured, not guessed. Real RTP identification needs flow context
# (a stable SSRC and incrementing sequence numbers across packets), so it
# belongs in flow-level classification, not here. Saying "unknown" beats lying.

# Ordered most-specific first: the first match wins.
_DETECTORS = [
    ("SSH", _ssh), ("HTTP", _http), ("TLS", _tls), ("SMB", _smb),
    ("BitTorrent", _bittorrent), ("VNC", _vnc), ("WireGuard", _wireguard),
    ("QUIC", _quic), ("MQTT", _mqtt), ("SIP", _sip), ("PostgreSQL", _postgres),
    ("MySQL", _mysql), ("Redis", _redis), ("Telnet", _telnet), ("SNMP", _snmp),
    ("NTP", _ntp), ("RDP", _rdp), ("FTP", _ftp), ("SMTP", _smtp),
    ("IMAP", _imap), ("POP3", _pop3), ("IRC", _irc), ("DNS", _dns),
]


def classify(payload, sport=None, dport=None, proto="TCP"):
    """Identify the application protocol from its bytes.

    The port is never used to decide *what* the protocol is - only to report
    whether it turned up somewhere unexpected.
    """
    data = bytes(payload or b"")
    ent = entropy(data[:1024])
    out = {"protocol": "", "detail": "", "method": "", "confidence": "",
           "entropy": ent, "encrypted": False, "port_mismatch": False,
           "standard_ports": [], "port": None, "transport": proto}

    ports = [p for p in (sport, dport) if p]
    # The server port is the interesting one; ephemeral ports are >= 32768.
    known = [p for p in ports if p < 32768]
    out["port"] = min(known) if known else (min(ports) if ports else None)

    if not data:
        return out

    for name, detector in _DETECTORS:
        try:
            detail = detector(data)
        except Exception:
            detail = None
        if detail:
            out.update(protocol=name, detail=detail, method="signature",
                       confidence="high")
            break

    if not out["protocol"]:
        # No signature. Entropy is the only honest thing left to say - measured
        # against a bar scaled to the payload length (see entropy_threshold).
        bar = entropy_threshold(len(data))
        if bar is not None and ent >= bar:
            out.update(protocol="encrypted/compressed", method="entropy",
                       confidence="low",
                       detail=f"no known signature, {ent} bits/byte over {len(data)} bytes")
            out["encrypted"] = True
        else:
            out.update(protocol="unknown", method="", confidence="")
        return out

    if out["protocol"] in ("TLS", "QUIC", "WireGuard"):
        out["encrypted"] = True

    std = STANDARD_PORTS.get(out["protocol"])
    if std:
        out["standard_ports"] = sorted(std)
        if ports and not (set(ports) & std):
            out["port_mismatch"] = True
    return out


def assess(result):
    """Turn a classification into a defensive judgement.

    Returns (severity, message) or None when there's nothing to say.
    """
    if not result or not result.get("protocol"):
        return None
    proto = result["protocol"]
    port = result.get("port")

    if result.get("port_mismatch") and port:
        expected = EVASION_PORTS.get(port)
        std = ", ".join(str(p) for p in result.get("standard_ports", [])[:4])
        if expected and proto != expected:
            return ("ALERT",
                    f"{proto} is running on port {port}, which is normally {expected}. "
                    f"{proto} belongs on {std}. Carrying one protocol over another's "
                    "port is how traffic is tunnelled past egress filtering.")
        return ("WARNING",
                f"{proto} found on port {port}, but it normally uses {std}. "
                "Either an unexpected service or something avoiding the usual port.")

    if proto == "encrypted/compressed" and port and port not in (443, 8443, 22, 51820):
        return ("WARNING",
                f"Traffic on port {port} has no recognisable protocol and "
                f"{result['entropy']} bits/byte of entropy - it looks encrypted or "
                "compressed. On a port that should be plaintext, that suggests a "
                "tunnel or custom C2.")

    if proto == "Telnet":
        return ("WARNING", "Telnet is fully unencrypted - everything including "
                           "credentials crosses the network in the clear.")
    return None


def describe(result):
    """Ordered (label, value) rows for a UI panel."""
    if not result or not result.get("protocol"):
        return []
    rows = [("Protocol", result["protocol"])]
    if result.get("detail"):
        rows.append(("Identified by", result["detail"]))
    if result.get("method"):
        rows.append(("Method", f"{result['method']} ({result['confidence']} confidence)"))
    note = "   (looks encrypted)" if result.get("encrypted") else (
        "   (looks like plaintext)" if result["entropy"] < 5.5 else "")
    rows.append(("Entropy", f"{result['entropy']} bits/byte{note}"))
    if result.get("standard_ports"):
        rows.append(("Normally on", ", ".join(str(p) for p in result["standard_ports"][:6])))
    if result.get("port_mismatch"):
        rows.append(("[!] Port mismatch", f"seen on port {result['port']}"))
    return rows
