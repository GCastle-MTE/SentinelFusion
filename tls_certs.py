"""TLS certificate inspection.

JA3 tells you what a client looks like; the certificate tells you what the server
claims to be. Together they cover both ends of a handshake. This pulls a
certificate apart and flags the things that actually matter defensively:
self-signed certs, expired or not-yet-valid certs, hostnames that don't match,
weak keys, and dead signature algorithms - the signatures of TLS interception,
sketchy infrastructure, and forgotten IoT kit.

Two ways to get a certificate:

  * Passively, from a captured handshake (`certs_from_records`). IMPORTANT: this
    only works for TLS 1.2 and below. TLS 1.3 encrypts the Certificate message,
    so a captured 1.3 handshake reveals nothing here - that is the protocol
    working as designed, not a bug.
  * Actively, by connecting and asking (`fetch_certificate`). Because we are the
    client, this works on TLS 1.3 too. Use it for hosts on your own network.

The parser is hand-written DER: no cryptography/pyOpenSSL dependency (which also
keeps it clear of the scapy/cryptography version clash), and pure bytes-in /
dict-out so it is fully testable.
"""

import calendar
import socket
import ssl
import time

# --- OID tables ---
NAME_OIDS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "email", "0.9.2342.19200300.100.1.25": "DC",
}

SIG_ALGS = {
    "1.2.840.113549.1.1.4": "md5WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.3.101.112": "Ed25519",
}

# Signature algorithms nobody should still be signing with.
WEAK_SIGS = {"md5WithRSA", "sha1WithRSA", "ecdsa-with-SHA1", "md2WithRSA"}

KEY_ALGS = {
    "1.2.840.113549.1.1.1": "RSA",
    "1.2.840.10045.2.1": "EC",
    "1.3.101.112": "Ed25519",
}

CURVES = {
    "1.2.840.10045.3.1.7": "P-256",
    "1.3.132.0.34": "P-384",
    "1.3.132.0.35": "P-521",
}

OID_SAN = "2.5.29.17"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_EKU = "2.5.29.37"


# ---------- minimal DER reader ----------

def _tlv(data, off):
    """Read one DER TLV. Returns (tag, value_start, value_end, next_offset)."""
    if off + 2 > len(data):
        raise ValueError("truncated TLV")
    tag = data[off]
    off += 1
    length = data[off]
    off += 1
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or off + n > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[off:off + n], "big")
        off += n
    end = off + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, off, end, end


def _oid(data, start, end):
    raw = data[start:end]
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for byte in raw[1:]:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _parse_name(data, start, end):
    """RDNSequence -> {'CN': ..., 'O': ...}."""
    out = {}
    off = start
    while off < end:
        try:
            _t, sv, se, off = _tlv(data, off)            # RDN SET
        except ValueError:
            break
        p = sv
        while p < se:
            try:
                _t2, av, ae, p = _tlv(data, p)           # AttributeTypeAndValue
                q = av
                _t3, ov, oe, q = _tlv(data, q)           # type OID
                _t4, vv, ve, _ = _tlv(data, q)           # value
            except ValueError:
                break
            key = NAME_OIDS.get(_oid(data, ov, oe), _oid(data, ov, oe))
            val = data[vv:ve].decode("utf-8", "replace")
            if key not in out:
                out[key] = val
    return out


def _parse_time(data, start, end, tag):
    """UTCTime (YYMMDDHHMMSSZ) / GeneralizedTime (YYYYMMDDHHMMSSZ) -> epoch."""
    text = data[start:end].decode("latin-1", "replace").strip()
    try:
        if tag == 0x17:                                   # UTCTime
            yy = int(text[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = text[2:]
        else:                                             # GeneralizedTime
            year = int(text[0:4])
            rest = text[4:]
        mon, day = int(rest[0:2]), int(rest[2:4])
        hh, mm = int(rest[4:6]), int(rest[6:8])
        ss = int(rest[8:10]) if len(rest) >= 10 and rest[8:10].isdigit() else 0
        return calendar.timegm((year, mon, day, hh, mm, ss, 0, 0, 0))
    except Exception:
        return 0


def _parse_san(data, start, end):
    names = []
    try:
        _t, sv, se, _ = _tlv(data, start)                 # GeneralNames SEQUENCE
        p = sv
        while p < se:
            tag, vv, ve, p = _tlv(data, p)
            if tag == 0x82:                               # dNSName
                names.append(data[vv:ve].decode("latin-1", "replace"))
            elif tag == 0x81:                             # rfc822Name
                names.append(data[vv:ve].decode("latin-1", "replace"))
            elif tag == 0x86:                             # URI
                names.append(data[vv:ve].decode("latin-1", "replace"))
            elif tag == 0x87:                             # iPAddress
                raw = data[vv:ve]
                if len(raw) == 4:
                    names.append(".".join(str(b) for b in raw))
    except ValueError:
        pass
    return names


def _parse_extensions(data, start, end):
    out = {"san": [], "is_ca": False}
    try:
        _t, sv, se, _ = _tlv(data, start)                 # Extensions SEQUENCE
    except ValueError:
        return out
    p = sv
    while p < se:
        try:
            _t, ev, ee, p = _tlv(data, p)                 # Extension SEQUENCE
            q = ev
            _t2, ov, oe, q = _tlv(data, q)                # extnID
            oid = _oid(data, ov, oe)
            tag, vv, ve, q = _tlv(data, q)
            if tag == 0x01:                               # critical BOOLEAN
                tag, vv, ve, q = _tlv(data, q)
        except ValueError:
            break
        if oid == OID_SAN:
            out["san"] = _parse_san(data, vv, ve)
        elif oid == OID_BASIC_CONSTRAINTS:
            try:
                _tb, bv, be, _ = _tlv(data, vv)
                if bv < be:
                    tc, cv, ce, _ = _tlv(data, bv)
                    if tc == 0x01:
                        out["is_ca"] = data[cv:ce] != b"\x00"
            except ValueError:
                pass
    return out


def _parse_spki(data, start, end):
    out = {"key_type": "", "key_bits": 0, "curve": ""}
    try:
        _t, av, ae, p = _tlv(data, start)                 # AlgorithmIdentifier
        q = av
        _t2, ov, oe, q = _tlv(data, q)                    # algorithm OID
        oid = _oid(data, ov, oe)
        out["key_type"] = KEY_ALGS.get(oid, oid)
        if oid == "1.2.840.10045.2.1" and q < ae:         # EC named curve
            _t3, cv, ce, _ = _tlv(data, q)
            out["curve"] = CURVES.get(_oid(data, cv, ce), _oid(data, cv, ce))
        _t4, kv, ke, _ = _tlv(data, p)                    # subjectPublicKey BIT STRING
        if oid == "1.2.840.113549.1.1.1" and ke > kv + 1:
            inner = data[kv + 1:ke]                       # skip unused-bits byte
            _t5, mv, _me, _ = _tlv(inner, 0)              # RSAPublicKey SEQUENCE
            _t6, iv, ie, _ = _tlv(inner, mv)              # modulus INTEGER
            out["key_bits"] = len(inner[iv:ie].lstrip(b"\x00")) * 8
        elif out["curve"]:
            out["key_bits"] = {"P-256": 256, "P-384": 384, "P-521": 521}.get(out["curve"], 0)
        elif out["key_type"] == "Ed25519":
            out["key_bits"] = 256
    except ValueError:
        pass
    return out


def parse_certificate(der):
    """Parse a DER X.509 certificate into a dict. Returns {} on garbage."""
    out = {"version": 1, "serial": "", "sig_alg": "", "issuer": {}, "subject": {},
           "not_before": 0, "not_after": 0, "san": [], "is_ca": False,
           "key_type": "", "key_bits": 0, "curve": "", "self_signed": False}
    try:
        _t, cv, _ce, _ = _tlv(der, 0)                     # Certificate SEQUENCE
        _t, tv, te, after_tbs = _tlv(der, cv)             # tbsCertificate
        # signatureAlgorithm sits after the TBS block.
        try:
            _t, sv, _se, _ = _tlv(der, after_tbs)
            _t, ov, oe, _ = _tlv(der, sv)
            raw = _oid(der, ov, oe)
            out["sig_alg"] = SIG_ALGS.get(raw, raw)
        except ValueError:
            pass

        p = tv
        tag, vv, ve, nxt = _tlv(der, p)
        if tag == 0xA0:                                   # [0] EXPLICIT version
            _t, iv, ie, _ = _tlv(der, vv)
            out["version"] = int.from_bytes(der[iv:ie], "big") + 1
            p = nxt
        _t, vv, ve, p = _tlv(der, p)                      # serialNumber
        out["serial"] = der[vv:ve].hex()
        _t, vv, ve, p = _tlv(der, p)                      # signature AlgId (skip)
        _t, vv, ve, p = _tlv(der, p)                      # issuer
        out["issuer"] = _parse_name(der, vv, ve)
        _t, vv, ve, p = _tlv(der, p)                      # validity
        q = vv
        tag1, a1, b1, q = _tlv(der, q)
        out["not_before"] = _parse_time(der, a1, b1, tag1)
        tag2, a2, b2, q = _tlv(der, q)
        out["not_after"] = _parse_time(der, a2, b2, tag2)
        _t, vv, ve, p = _tlv(der, p)                      # subject
        out["subject"] = _parse_name(der, vv, ve)
        _t, vv, ve, p = _tlv(der, p)                      # subjectPublicKeyInfo
        out.update(_parse_spki(der, vv, ve))
        while p < te:                                     # optional trailing fields
            tag, vv, ve, p = _tlv(der, p)
            if tag == 0xA3:                               # [3] EXPLICIT extensions
                out.update(_parse_extensions(der, vv, ve))
        out["self_signed"] = bool(out["issuer"]) and out["issuer"] == out["subject"]
    except (ValueError, IndexError):
        return {}
    return out


# ---------- TLS handshake extraction (TLS 1.2 and below) ----------

def _certs_from_handshake(body):
    out = []
    p = 0
    while p + 4 <= len(body):
        htype = body[p]
        hlen = int.from_bytes(body[p + 1:p + 4], "big")
        msg = body[p + 4:p + 4 + hlen]
        p += 4 + hlen
        if htype != 11 or len(msg) < 3:                   # 11 = Certificate
            continue
        total = int.from_bytes(msg[0:3], "big")
        q = 3
        end = min(3 + total, len(msg))
        while q + 3 <= end:
            clen = int.from_bytes(msg[q:q + 3], "big")
            q += 3
            der = msg[q:q + clen]
            q += clen
            if der:
                out.append(bytes(der))
    return out


def certs_from_records(data):
    """Extract DER certificates from raw TLS record bytes.

    Reassembles handshake records first, so a Certificate message split across
    records still parses. Returns [] for TLS 1.3 (certificates are encrypted).
    """
    data = bytes(data)
    handshake = b""
    off = 0
    while off + 5 <= len(data):
        ctype = data[off]
        if data[off + 1] != 0x03:                         # not a TLS record
            break
        rlen = int.from_bytes(data[off + 3:off + 5], "big")
        if ctype == 0x16:
            handshake += data[off + 5:off + 5 + rlen]
        off += 5 + rlen
    return _certs_from_handshake(handshake) if handshake else []


def has_certificate(data):
    """Cheap check: does this look like a TLS handshake carrying a Certificate?"""
    data = bytes(data)
    return len(data) > 5 and data[0] == 0x16 and data[1] == 0x03


# ---------- analysis ----------

def host_matches(hostname, cert):
    """RFC-6125-style match of a hostname against SAN (falling back to CN)."""
    if not hostname or not cert:
        return True
    names = list(cert.get("san") or [])
    cn = (cert.get("subject") or {}).get("CN")
    if cn and cn not in names:
        names.append(cn)
    if not names:
        return True
    host = hostname.lower().rstrip(".")
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*."):
            # A wildcard covers exactly one label, so the dot counts must match.
            if host.endswith(name[1:]) and host.count(".") == name.count("."):
                return True
    return False


def analyze(cert, hostname=None, now=None):
    """Return [(severity, label, detail)] for anything worth flagging."""
    if not cert:
        return []
    now = now or time.time()
    out = []
    subject = cert.get("subject") or {}

    if cert.get("self_signed"):
        who = subject.get("CN") or subject.get("O") or "unknown"
        out.append(("WARNING", "self-signed",
                    f"Signed by itself ({who}) - no certificate authority vouches for it. "
                    "Normal for IoT/lab kit; suspicious for a public site."))

    na = cert.get("not_after") or 0
    nb = cert.get("not_before") or 0
    if na and now > na:
        days = int((now - na) / 86400)
        out.append(("WARNING", "expired",
                    f"Expired {days} day(s) ago ({_fmt(na)})."))
    elif na and na - now < 14 * 86400:
        days = int((na - now) / 86400)
        out.append(("INFO", "expiring soon", f"Expires in {days} day(s) ({_fmt(na)})."))
    if nb and now < nb:
        out.append(("WARNING", "not yet valid", f"Not valid until {_fmt(nb)}."))

    if hostname and not host_matches(hostname, cert):
        names = ", ".join((cert.get("san") or [subject.get("CN", "?")])[:4])
        out.append(("ALERT", "hostname mismatch",
                    f"Presented for [{names}] but the connection asked for {hostname}. "
                    "This is what TLS interception looks like."))

    sig = cert.get("sig_alg") or ""
    if sig in WEAK_SIGS:
        out.append(("WARNING", "weak signature",
                    f"Signed with {sig}, which is considered broken."))

    bits = cert.get("key_bits") or 0
    ktype = cert.get("key_type") or ""
    if ktype == "RSA" and 0 < bits < 2048:
        out.append(("WARNING", "weak key", f"{bits}-bit RSA key is below the 2048-bit minimum."))

    if nb and na and (na - nb) > 825 * 86400 and not cert.get("is_ca"):
        years = round((na - nb) / 31536000, 1)
        out.append(("INFO", "long validity",
                    f"Valid for {years} years - public CAs cap leaf certs near 1 year."))
    return out


def _fmt(ts):
    try:
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    except Exception:
        return "?"


def describe(cert):
    """Ordered (label, value) rows for a UI panel."""
    if not cert:
        return []
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    rows = [("Subject", subject.get("CN") or subject.get("O") or "-")]
    if subject.get("O"):
        rows.append(("Organisation", subject["O"]))
    rows.append(("Issuer", issuer.get("CN") or issuer.get("O") or "-"))
    rows.append(("Valid", f"{_fmt(cert.get('not_before'))}  ->  {_fmt(cert.get('not_after'))}"))
    key = cert.get("key_type") or "?"
    if cert.get("curve"):
        key += f" {cert['curve']}"
    elif cert.get("key_bits"):
        key += f" {cert['key_bits']}-bit"
    rows.append(("Key", key))
    rows.append(("Signature", cert.get("sig_alg") or "-"))
    if cert.get("san"):
        rows.append(("Names (SAN)", ", ".join(cert["san"][:8])
                     + (f"  (+{len(cert['san']) - 8} more)" if len(cert["san"]) > 8 else "")))
    if cert.get("serial"):
        rows.append(("Serial", cert["serial"][:40]))
    if cert.get("is_ca"):
        rows.append(("Type", "Certificate Authority"))
    return rows


# ---------- active fetch (works on TLS 1.3 too) ----------

def _is_ip(host):
    parts = str(host).split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)


def fetch_certificate(host, port=443, timeout=3.0):
    """Connect and ask the server for its certificate.

    We're the client, so this works regardless of TLS version - unlike passive
    capture, which TLS 1.3 hides. Verification is deliberately off: the whole
    point is to inspect certificates that would fail validation.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    server_name = None if _is_ip(host) else host
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return None
                info = parse_certificate(der)
                if info:
                    info["tls_version"] = tls.version() or ""
                    cipher = tls.cipher()
                    info["cipher"] = cipher[0] if cipher else ""
                return info or None
    except Exception:
        return None
