"""JARM - active TLS server fingerprinting.

JA3 fingerprints the *client's* TLS hello; certificate inspection reads what the
server presents. JARM fills the third corner: it fingerprints the *server's* TLS
stack by how it responds to ten deliberately varied ClientHellos (different TLS
versions, cipher orderings, extension sets). Two servers running the same stack
and config produce the same JARM hash - which is why it's good at spotting C2
infrastructure: malware C2 servers built from the same tooling share a JARM even
behind different domains and valid certificates.

This is an *active* probe - it connects to the target and sends hellos - so it's
for servers you're already investigating on your own authority, not blanket
scanning. It's invoked on demand (right-click an IP -> fingerprint), never
automatically against every address.

Implementation notes:
  * Pure stdlib sockets. We hand-build the ten ClientHello packets and parse just
    enough of the ServerHello (selected cipher, version, extensions) to form the
    JARM fingerprint, following the published JARM construction.
  * Fully offline-testable: the packet *builders* and the fingerprint *assembler*
    are pure functions, so we validate them without a network.
"""

import socket
import hashlib
import struct


# The ten JARM probes: (tls_version_max, ciphers, cipher_order, grease, alpn, ext_order)
# Encoded compactly; each entry drives one ClientHello variant.
_PROBES = [
    ("TLS_1.3", "ALL", "FORWARD", True, True, "REVERSE"),
    ("TLS_1.2", "ALL", "FORWARD", True, True, "FORWARD"),
    ("TLS_1.2", "ALL", "REVERSE", True, True, "FORWARD"),
    ("TLS_1.2", "ALL", "FORWARD", False, False, "FORWARD"),
    ("TLS_1.3", "ALL", "REVERSE", True, True, "REVERSE"),
    ("TLS_1.3", "ALL", "FORWARD", True, True, "FORWARD"),
    ("TLS_1.3", "NO1.3", "FORWARD", True, True, "FORWARD"),
    ("TLS_1.2", "ALL", "REVERSE", True, True, "REVERSE"),
    ("TLS_1.2", "NO1.3", "FORWARD", True, True, "FORWARD"),
    ("TLS_1.1", "ALL", "FORWARD", True, True, "FORWARD"),
]

# A representative cipher list (subset of the JARM standard set).
_CIPHERS = [
    0x0016, 0x0033, 0x0067, 0x00a3, 0x00c009, 0xc02b, 0xc02f, 0xc030,
    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a, 0x1301,
    0x1302, 0x1303,
]

_TLS_VER = {"TLS_1.1": 0x0302, "TLS_1.2": 0x0303, "TLS_1.3": 0x0304}
_GREASE = 0x0a0a


def _cipher_bytes(mode, order):
    ciphers = [c for c in _CIPHERS if c <= 0xffff]
    if mode == "NO1.3":
        ciphers = [c for c in ciphers if c not in (0x1301, 0x1302, 0x1303)]
    if order == "REVERSE":
        ciphers = list(reversed(ciphers))
    out = b""
    for c in ciphers:
        out += struct.pack(">H", c)
    return out


def build_client_hello(host, probe):
    """Build one JARM ClientHello record for the given probe tuple."""
    ver_max, cmode, corder, grease, alpn, ext_order = probe
    version = _TLS_VER.get(ver_max, 0x0303)

    # Handshake body -----------------------------------------------------
    body = b"\x03\x03"                              # legacy_version = TLS1.2
    body += _rand(32)                               # client random
    body += b"\x00"                                 # session id length 0
    ciphers = _cipher_bytes(cmode, corder)
    if grease:
        ciphers = struct.pack(">H", _GREASE) + ciphers
    body += struct.pack(">H", len(ciphers)) + ciphers
    body += b"\x01\x00"                             # compression: null

    exts = _extensions(host, version, ver_max, grease, alpn, ext_order)
    body += struct.pack(">H", len(exts)) + exts

    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body   # ClientHello
    record = b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs
    return record


def _extensions(host, version, ver_max, grease, alpn, ext_order):
    ext = []
    # SNI
    server_name = host.encode("idna") if host else b""
    sni = struct.pack(">H", len(server_name) + 3) + b"\x00" + \
        struct.pack(">H", len(server_name)) + server_name
    ext.append((0x0000, sni))
    # supported_groups
    ext.append((0x000a, b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19"))
    # ec_point_formats
    ext.append((0x000b, b"\x02\x01\x00"))
    # signature_algorithms
    ext.append((0x000d, b"\x00\x0a\x04\x03\x05\x03\x06\x03\x08\x04\x08\x05"))
    if alpn:
        alpn_list = b"\x08http/1.1\x02h2"
        ext.append((0x0010, struct.pack(">H", len(alpn_list)) + alpn_list))
    if ver_max == "TLS_1.3":
        # supported_versions
        ext.append((0x002b, b"\x03\x03\x04\x02\x03\x03"))
        # key_share (grease + x25519 placeholder)
        ks = b"\x00\x1d\x00\x20" + _rand(32)
        ext.append((0x0033, struct.pack(">H", len(ks)) + ks))
    packed = b""
    items = ext
    if ext_order == "REVERSE":
        items = list(reversed(ext))
    if grease:
        packed += struct.pack(">H", _GREASE) + b"\x00\x00"
    for etype, edata in items:
        packed += struct.pack(">H", etype) + struct.pack(">H", len(edata)) + edata
    return packed


def _rand(n):
    import os
    return os.urandom(n)


def parse_server_hello(data):
    """Extract (version, cipher, extensions-digest) from a ServerHello, or None."""
    if not data or len(data) < 5 or data[0] != 0x16:
        return None
    try:
        # record header
        rec_len = struct.unpack(">H", data[3:5])[0]
        hs = data[5:5 + rec_len]
        if not hs or hs[0] != 0x02:                 # ServerHello
            return None
        # skip handshake header (1 type + 3 len)
        p = 4
        legacy_ver = struct.unpack(">H", hs[p:p + 2])[0]
        p += 2
        p += 32                                     # server random
        sid_len = hs[p]
        p += 1 + sid_len
        cipher = struct.unpack(">H", hs[p:p + 2])[0]
        p += 2
        p += 1                                      # compression
        ext_digest = "000000"
        chosen_ver = legacy_ver
        if p + 2 <= len(hs):
            ext_total = struct.unpack(">H", hs[p:p + 2])[0]
            p += 2
            ext_block = hs[p:p + ext_total]
            ext_types = []
            q = 0
            while q + 4 <= len(ext_block):
                et = struct.unpack(">H", ext_block[q:q + 2])[0]
                el = struct.unpack(">H", ext_block[q + 2:q + 4])[0]
                ext_types.append(et)
                if et == 0x002b and el >= 2:        # supported_versions -> real ver
                    chosen_ver = struct.unpack(">H", ext_block[q + 4:q + 6])[0]
                q += 4 + el
            ext_digest = hashlib.sha256(
                bytes(struct.pack(">H", e) for e in ext_types if True)
                if False else b"".join(struct.pack(">H", e) for e in ext_types)
            ).hexdigest()[:6]
        return {"version": chosen_ver, "cipher": cipher, "ext": ext_digest}
    except Exception:
        return None


def _probe_component(resp):
    """Turn one ServerHello into the JARM per-probe component string."""
    if not resp:
        return "|" + "|" + ""
    return f"{resp['cipher']:04x}|{resp['version']:04x}|{resp['ext']}"


def assemble(components):
    """Assemble the final JARM fingerprint from ten probe components.

    The published JARM is a 62-char hash (30 chars cipher/version + 32 char
    truncated sha256 of the extension components). We follow that shape.
    """
    if len(components) != 10:
        return ""
    # first part: cipher+version per probe, compacted
    part1 = ""
    ext_parts = []
    for comp in components:
        if not comp or comp == "||":
            part1 += "000000"
            ext_parts.append("")
        else:
            cipher, version, ext = (comp.split("|") + ["", "", ""])[:3]
            part1 += (cipher[-2:] if cipher else "00") + (version[-2:] if version else "00") + "0"
            ext_parts.append(ext)
    ext_hash = hashlib.sha256("|".join(ext_parts).encode()).hexdigest()[:32]
    return part1[:30] + ext_hash


def fingerprint(host, port=443, timeout=3.0):
    """Actively fingerprint a TLS server. Returns {'jarm','host','port','alive'}."""
    components = []
    alive = False
    for probe in _PROBES:
        resp = _send_probe(host, port, probe, timeout)
        if resp:
            alive = True
            components.append(_probe_component(resp))
        else:
            components.append("||")
    jarm = assemble(components) if alive else ""
    return {"host": host, "port": port, "alive": alive, "jarm": jarm}


def _send_probe(host, port, probe, timeout):
    try:
        hello = build_client_hello(host, probe)
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(hello)
            data = s.recv(4096)
            return parse_server_hello(data)
    except Exception:
        return None


# A tiny built-in note table: JARMs commonly associated with tooling. Users can
# extend this; we ship it empty of specific hashes to avoid false attribution.
_KNOWN = {}


def describe(result):
    if not result or not result.get("alive"):
        return "No TLS response - server unreachable or not speaking TLS."
    jarm = result.get("jarm", "")
    note = _KNOWN.get(jarm)
    line = f"JARM: {jarm}"
    if note:
        line += f"   ({note})"
    return line
