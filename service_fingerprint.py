"""Service fingerprinting - turn a banner into a structured product identity.

Knowing "port 22 is open" is not enough to say anything about risk. Knowing it
runs *OpenSSH 8.2p1* is, because that maps to a specific entry in the CVE
databases. This module does that translation: it reads the banner strings the
port scanner already grabs and parses out vendor, product, and version, then
builds a CPE 2.3 identifier - the naming scheme NIST's NVD uses.

Why CPE and not a keyword search: searching a CVE database for "apache" returns
every CVE that ever mentioned Apache, hundreds of them, nearly all irrelevant to
the version actually running. A CPE like

    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

lets the database answer the question that actually matters - which CVEs cover
*this* version - because the version-range logic lives on their side. The
difference is a handful of real findings versus a wall of noise.

Honest limits, which the output records rather than hides:
  * Plenty of services give no version away (SMB, RDP, most printers and IoT).
    Those come back with a product guess and confidence "low", or nothing at all.
  * A banner can be spoofed or stripped, and distributions backport security
    fixes without bumping the version string - so a version match means "worth
    checking", not "definitely vulnerable".
Nothing here touches the network; it is pure parsing over strings already
collected, and so is fully testable offline.
"""

import re

# part codes in CPE: 'a' application, 'o' operating system, 'h' hardware
APPLICATION = "a"
OPERATING_SYSTEM = "o"

# Each rule: compiled pattern, CPE vendor, CPE product, and a human label.
# The first capture group, where present, is the version.
# Vendor/product strings are the ones NVD actually uses - these matter, because
# a wrong vendor means zero matches rather than wrong matches.
_RULES = [
    # --- SSH ---
    # The version can be preceded by a build/platform tag: real banners include
    # both "OpenSSH_8.2p1" and "OpenSSH_for_Windows_9.5". Allow an optional word
    # prefix, then anchor the capture on a digit so the tag isn't mistaken for
    # the version.
    (re.compile(r"SSH-[\d.]+-OpenSSH[_-](?:[A-Za-z_]+_)?(\d[\w.]*)", re.I),
     "openbsd", "openssh", "OpenSSH"),
    (re.compile(r"SSH-[\d.]+-dropbear[_-]([\w.]+)", re.I),
     "dropbear_ssh_project", "dropbear_ssh", "Dropbear SSH"),

    # --- Web servers (banner here is usually the Server: header value) ---
    (re.compile(r"\bApache[/-](\d[\w.]*)", re.I),
     "apache", "http_server", "Apache httpd"),
    (re.compile(r"\bnginx[/-](\d[\w.]*)", re.I),
     "nginx", "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS[/-](\d[\w.]*)", re.I),
     "microsoft", "internet_information_services", "Microsoft IIS"),
    (re.compile(r"\blighttpd[/-](\d[\w.]*)", re.I),
     "lighttpd", "lighttpd", "lighttpd"),
    (re.compile(r"\bJetty[/(]+(\d[\w.]*)", re.I),
     "eclipse", "jetty", "Eclipse Jetty"),
    (re.compile(r"Apache[- ]?Tomcat[/-](\d[\w.]*)", re.I),
     "apache", "tomcat", "Apache Tomcat"),
    (re.compile(r"\bWerkzeug[/-](\d[\w.]*)", re.I),
     "palletsprojects", "werkzeug", "Werkzeug"),
    (re.compile(r"\bgunicorn[/-](\d[\w.]*)", re.I),
     "gunicorn", "gunicorn", "Gunicorn"),

    # --- Libraries that ride along in a Server header ---
    (re.compile(r"OpenSSL[/-](\d[\w.]*)", re.I),
     "openssl", "openssl", "OpenSSL"),
    (re.compile(r"\bPHP[/-](\d[\w.]*)", re.I),
     "php", "php", "PHP"),

    # --- FTP ---
    (re.compile(r"\bProFTPD\s+(\d[\w.]*)", re.I),
     "proftpd", "proftpd", "ProFTPD"),
    (re.compile(r"\bvsFTPd\s+(\d[\w.]*)", re.I),
     "beasts", "vsftpd", "vsftpd"),
    (re.compile(r"\bFileZilla Server\s+(\d[\w.]*)", re.I),
     "filezilla-project", "filezilla_server", "FileZilla Server"),

    # --- Mail ---
    (re.compile(r"\bExim\s+(\d[\w.]*)", re.I),
     "exim", "exim", "Exim"),
    (re.compile(r"\bDovecot\s+(\d[\w.]*)", re.I),
     "dovecot", "dovecot", "Dovecot"),

    # --- Databases ---
    (re.compile(r"(\d+\.\d[\w.]*)-MariaDB", re.I),
     "mariadb", "mariadb", "MariaDB"),
    (re.compile(r"\bMySQL\D{0,12}(\d+\.\d[\w.]*)", re.I),
     "oracle", "mysql", "MySQL"),
    (re.compile(r"\bPostgreSQL\s+(\d[\w.]*)", re.I),
     "postgresql", "postgresql", "PostgreSQL"),
    (re.compile(r"\bRedis(?:\s+server)?\D{0,10}v?=?(\d[\w.]*)", re.I),
     "redis", "redis", "Redis"),
    (re.compile(r"\bMongoDB\D{0,10}(\d[\w.]*)", re.I),
     "mongodb", "mongodb", "MongoDB"),

    # --- File sharing / remote access ---
    (re.compile(r"\bSamba\s+(\d[\w.]*)", re.I),
     "samba", "samba", "Samba"),
    (re.compile(r"\bVNC\b.{0,20}?(\d+\.\d[\w.]*)", re.I),
     "realvnc", "vnc", "VNC"),
]

# Bare-product fallbacks: the banner names a product but reveals no version.
# Worth recording (it identifies the service) but it cannot drive a version
# match, so these land at confidence "low".
_PRODUCT_ONLY = [
    (re.compile(r"\bOpenSSH\b", re.I), "openbsd", "openssh", "OpenSSH"),
    (re.compile(r"\bApache\b", re.I), "apache", "http_server", "Apache httpd"),
    (re.compile(r"\bnginx\b", re.I), "nginx", "nginx", "nginx"),
    (re.compile(r"Microsoft-IIS", re.I), "microsoft",
     "internet_information_services", "Microsoft IIS"),
    (re.compile(r"\bProFTPD\b", re.I), "proftpd", "proftpd", "ProFTPD"),
    (re.compile(r"\bvsFTPd\b", re.I), "beasts", "vsftpd", "vsftpd"),
    (re.compile(r"\bPure-FTPd\b", re.I), "pureftpd", "pure-ftpd", "Pure-FTPd"),
    (re.compile(r"\bExim\b", re.I), "exim", "exim", "Exim"),
    # These commonly announce themselves with no version at all.
    (re.compile(r"\bPostfix\b", re.I), "postfix", "postfix", "Postfix"),
    (re.compile(r"\bDovecot\b", re.I), "dovecot", "dovecot", "Dovecot"),
    (re.compile(r"\bsendmail\b", re.I), "proofpoint", "sendmail", "Sendmail"),
    (re.compile(r"\bMySQL\b", re.I), "oracle", "mysql", "MySQL"),
    # A VNC server greets with the RFB *protocol* version ("RFB 003.008"), which
    # says nothing about which implementation it is - TigerVNC, RealVNC, UltraVNC
    # and TightVNC all speak RFB 3.8. So we can name the service but must not
    # treat 003.008 as a product version; doing so would query NVD for a version
    # that does not exist and return confident nonsense.
    (re.compile(r"^RFB \d{3}\.\d{3}", re.I), "", "vnc", "VNC server"),
]

# Some services lead with the bare version and never name themselves - a MySQL
# handshake is just "5.7.33-0ubuntu0.18.04.1". Keyed by port so a naked version
# string is only trusted where that port makes the product unambiguous.
_PORT_VERSION_RULES = {
    3306: (re.compile(r"(?:^|[^\w.])(\d+\.\d+\.\d+[\w.]*)"),
           "oracle", "mysql", "MySQL"),
    5432: (re.compile(r"(?:^|[^\w.])(\d+\.\d+(?:\.\d+)?)"),
           "postgresql", "postgresql", "PostgreSQL"),
}

# Ports whose service is well known even when nothing is said on the wire.
# These give a service label only - never a version, and never a CVE query.
_PORT_HINTS = {
    445: "SMB / Windows file sharing",
    139: "NetBIOS session",
    3389: "RDP (Remote Desktop)",
    135: "MSRPC endpoint mapper",
    1900: "UPnP",
    5353: "mDNS",
    161: "SNMP",
    623: "IPMI",
}


def _series_epoch(vendor, product, version):
    """Approximate date the version's major series began, or None.

    Used solely to flag CVEs that predate the running software - an advisory from
    2008 cannot describe a flaw in a 2023 release, so it signals an over-broad
    version range in the CVE record rather than real exposure.

    Deliberately the START of each major series, and deliberately sparse. An
    epoch that is too early makes the flag under-fire, which is the safe
    direction: it stays quiet rather than dismissing a finding that matters.
    """
    series = {
        ("openbsd", "openssh"): {
            10: "2025-01-01", 9: "2022-04-01", 8: "2019-04-01",
            7: "2015-08-01", 6: "2012-01-01",
        },
    }.get((vendor, product))
    if not series:
        return None
    try:
        major = int(str(version).split(".")[0])
    except Exception:
        return None
    return series.get(major)


def identify_from_cert(cert):
    """Identify a device from its TLS certificate.

    A TLS port sends no plaintext banner, but the certificate it presents during
    the handshake is already fetched by the scanner and usually names the vendor
    or product - embedded devices overwhelmingly ship self-signed certs whose
    subject or issuer says what they are.

    This yields *identification*, never a version: certificates carry no software
    version, so every result is low confidence with no CPE. Naming a camera as a
    camera is still worth having when the alternative is "443/tcp open".
    """
    if not isinstance(cert, dict) or not cert:
        return []
    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    fields = [subject.get("CN", ""), subject.get("O", ""),
              subject.get("OU", ""), issuer.get("O", ""), issuer.get("CN", "")]
    haystack = " ".join(f for f in fields if f).lower()
    if not haystack.strip():
        return []

    for needle, label in _CERT_VENDORS:
        if needle in haystack:
            return [{
                "vendor": "", "product": needle.replace(" ", "_"), "label": label,
                "version": "", "cpe": "", "confidence": "low",
                "had_banner": True,
                "evidence": f"TLS certificate: {_cert_evidence(subject, issuer)}",
            }]

    # No known vendor, but the certificate still names something. Report it
    # verbatim rather than discarding - an operator recognises their own kit.
    named = subject.get("O") or subject.get("CN") or issuer.get("O") or ""
    if named and not _looks_like_hostname(named):
        return [{
            "vendor": "", "product": "", "label": f"TLS service ({named[:40]})",
            "version": "", "cpe": "", "confidence": "low", "had_banner": True,
            "evidence": f"TLS certificate: {_cert_evidence(subject, issuer)}",
        }]
    return []


# Vendor strings that commonly appear in embedded-device certificates.
_CERT_VENDORS = [
    ("ubiquiti", "Ubiquiti device"), ("unifi", "UniFi device"),
    ("hikvision", "Hikvision camera/NVR"), ("dahua", "Dahua camera/NVR"),
    # Model-line designations that show up as the issuer CN on factory certs.
    # HCVR is Dahua's Hybrid CVR range; XVR/NVR appear on their recorders too.
    ("hcvr", "Dahua HCVR (hybrid video recorder)"),
    ("axis communications", "Axis camera"), ("amcrest", "Amcrest camera"),
    ("reolink", "Reolink camera"), ("synology", "Synology NAS"),
    ("qnap", "QNAP NAS"), ("western digital", "WD storage device"),
    ("netgear", "Netgear device"), ("tp-link", "TP-Link device"),
    ("d-link", "D-Link device"), ("asustek", "ASUS device"),
    ("mikrotik", "MikroTik router"), ("pfsense", "pfSense firewall"),
    ("openwrt", "OpenWrt router"), ("vmware", "VMware host"),
    ("plex", "Plex Media Server"), ("sonos", "Sonos device"),
    ("philips hue", "Philips Hue bridge"), ("raspberry", "Raspberry Pi"),
]


def _cert_evidence(subject, issuer):
    bits = []
    if subject.get("CN"):
        bits.append(f"CN={subject['CN'][:32]}")
    if subject.get("O"):
        bits.append(f"O={subject['O'][:32]}")
    if not bits and issuer.get("O"):
        bits.append(f"issuer O={issuer['O'][:32]}")
    return ", ".join(bits)[:70]


def _looks_like_hostname(value):
    """True for values that identify the machine rather than the product.

    Also covers the placeholder text embedded devices ship in factory
    certificates - "unknown", "default", "N/A". Those name nothing, and echoing
    them back as `TLS service (unknown)` is worse than saying nothing at all.
    """
    v = (value or "").strip().lower()
    if not v:
        return True
    if v in _CERT_PLACEHOLDERS:
        return True
    if all(c.isdigit() or c == "." for c in v):
        return True
    return " " not in v and "." in v and len(v.split(".")) >= 2


_CERT_PLACEHOLDERS = frozenset({
    "unknown", "none", "n/a", "na", "default", "localhost", "test",
    "changeme", "example", "self-signed", "certificate", "-",
})


def identify(banner, port=None, service=""):
    """Parse one banner into a list of product identities.

    A single banner can name more than one product - "Apache/2.4.49 (Unix)
    OpenSSL/1.1.1k" is both - and each gets its own entry, because each carries
    its own CVEs.

    Returns a list of dicts:
        {vendor, product, label, version, cpe, confidence, evidence}
    confidence is "high" (product + version parsed), "low" (product only, no
    version) or "none" (nothing identifiable). An empty list means nothing was
    recognised.
    """
    banner = (banner or "").strip()
    found = []
    seen = set()

    if banner:
        for pattern, vendor, product, label in _RULES:
            m = pattern.search(banner)
            if not m:
                continue
            key = (vendor, product)
            if key in seen:
                continue
            version = m.group(1) if m.groups() else ""
            version = _clean_version(version)
            if not version:
                continue
            seen.add(key)
            ver, update = _split_update(version, product)
            entry = {
                "vendor": vendor,
                "product": product,
                "label": label,
                "version": version,
                "cpe": build_cpe(vendor, product, ver, update),
                "confidence": "high",
                "evidence": m.group(0)[:60],
            }
            # NVD tracks one CPE for OpenSSH regardless of platform, so a Windows
            # build inherits every Unix-only advisory - setuid/setgid handling,
            # glibc signal races, Linux distribution packaging. Worth saying so
            # rather than letting the analyst assume all of them apply.
            if product == "openssh" and "windows" in banner.lower():
                entry["platform_note"] = (
                    "OpenSSH for Windows: NVD uses one CPE for all platforms, so "
                    "some results will be Unix-only issues (setuid, glibc, distro "
                    "packaging) that do not apply here.")
            epoch = _series_epoch(vendor, product, version)
            if epoch:
                entry["released"] = epoch
            found.append(entry)

        # Version-first banners that never name the product (e.g. MySQL's
        # handshake). Only trusted on a port that pins down what it must be.
        rule = _PORT_VERSION_RULES.get(port)
        if rule and not any(p["confidence"] == "high" for p in found):
            pattern, vendor, product, label = rule
            m = pattern.search(banner)
            if m and (vendor, product) not in seen:
                version = _clean_version(m.group(1))
                if version:
                    seen.add((vendor, product))
                    found.append({
                        "vendor": vendor, "product": product, "label": label,
                        "version": version,
                        "cpe": build_cpe(vendor, product, version),
                        "confidence": "high",
                        "evidence": m.group(0).strip()[:60],
                    })

        # Product recognised but no version anywhere in the banner.
        for pattern, vendor, product, label in _PRODUCT_ONLY:
            if (vendor, product) in seen:
                continue
            m = pattern.search(banner)
            if not m:
                continue
            seen.add((vendor, product))
            found.append({
                "vendor": vendor,
                "product": product,
                "label": label,
                "version": "",
                "cpe": "",          # no version -> no useful CPE query
                "confidence": "low",
                "evidence": m.group(0)[:60],
            })

    if not found:
        hint = _PORT_HINTS.get(port) or service
        if hint:
            # Record *why* nothing was identified. "No banner at all" and "a
            # banner arrived that no rule matched" are different problems - the
            # first is the service being quiet, the second is a gap in our rules
            # - and collapsing them hides which one you actually have.
            found.append({
                "vendor": "", "product": "", "label": hint, "version": "",
                "cpe": "", "confidence": "none",
                "had_banner": bool(banner),
                "evidence": (f"banner not recognised: {banner[:60]}" if banner
                             else "no banner - identified by port"),
            })
    return found


def identify_findings(findings, ip=None, probe_smb=True):
    """Run identify() across a list of port_scanner findings.

    Each finding is {port, service, banner, risk}; the returned list mirrors it
    with an added 'products' key.

    Two sources beyond the banner are consulted when the banner is empty, because
    the ports that stay silent are exactly the ones worth identifying:
      * the TLS certificate the scanner already fetched (f['cert'])
      * an SMB2 negotiate exchange on 139/445, which is the only way to get a
        version out of Windows file sharing
    Pass probe_smb=False to keep the pass entirely offline.
    """
    out = []
    for f in findings or []:
        row = dict(f)
        products = identify(f.get("banner", ""), f.get("port"),
                            f.get("service", ""))

        # A TLS port has no plaintext banner, but its certificate is already in
        # hand from the handshake the scanner performed.
        if f.get("cert") and not [p for p in products if p["confidence"] != "none"]:
            from_cert = identify_from_cert(f["cert"])
            if from_cert:
                products = from_cert

        if (probe_smb and ip and f.get("port") in (139, 445)
                and not [p for p in products if p["confidence"] == "high"]):
            smb = _smb_products(ip, f["port"])
            if smb:
                products = smb

        row["products"] = products
        out.append(row)
    return out


def _smb_products(ip, port):
    """Ask an SMB service what Windows build it is. Returns [] if unavailable."""
    try:
        import smb_fingerprint
    except Exception:
        return []
    try:
        res = smb_fingerprint.fingerprint(ip, port)
    except Exception:
        return []
    if not res.get("ok"):
        return []
    os_info = res.get("os")
    if os_info and os_info.get("cpe"):
        rel = f" {os_info['release']}" if os_info.get("release") else ""
        return [{
            "vendor": "microsoft", "product": "windows",
            "label": f"{os_info['product']}{rel}",
            "version": os_info["version"], "cpe": os_info["cpe"],
            "cpe_broad": os_info.get("cpe_broad", True),
            "released": os_info.get("epoch") or os_info.get("released"),
            "precision": os_info.get("precision", "release"),
            "confidence": "high", "had_banner": True,
            "evidence": f"SMB2 negotiate, build {os_info['build']}",
        }]
    # Dialect only: brackets the era but gives no version to query.
    return [{
        "vendor": "", "product": "smb",
        "label": f"SMB server ({res.get('dialect_name', '?')})",
        "version": "", "cpe": "", "confidence": "low", "had_banner": True,
        "evidence": res.get("era", "") or "dialect negotiated, version withheld",
    }]


def build_cpe(vendor, product, version="*", update="*", part=APPLICATION):
    """Assemble a CPE 2.3 formatted string.

    Format: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:
            target_sw:target_hw:other
    """
    fields = [_esc(vendor), _esc(product), _esc(version or "*"),
              _esc(update or "*"), "*", "*", "*", "*", "*", "*"]
    return "cpe:2.3:" + part + ":" + ":".join(fields)


def versioned(products):
    """Filter to the identities that carry a version - the only ones worth
    sending to a CVE database."""
    return [p for p in products if p.get("confidence") == "high" and p.get("cpe")]


def describe(products):
    """Plain-language lines summarising what a service was identified as."""
    if not products:
        return ["Service not identified."]
    lines = []
    for p in products:
        if p["confidence"] == "high":
            lines.append(f"{p['label']} {p['version']}  ({p['cpe']})")
        elif p["confidence"] == "low":
            lines.append(f"{p['label']} - version not disclosed, "
                         "cannot check for known vulnerabilities")
        elif p.get("had_banner"):
            lines.append(f"{p['label']} - sent a banner we could not parse "
                         "(rule gap, not a silent service)")
        else:
            lines.append(f"{p['label']} - no banner, identified by port only")
    return lines


def _clean_version(v):
    """Trim trailing punctuation and reject values that aren't versions."""
    v = (v or "").strip().rstrip(".,;:)-_")
    if not v or not v[0].isdigit():
        return ""
    return v[:24]


def _split_update(version, product):
    """Separate an OpenSSH-style portable suffix into CPE's `update` field.

    NVD records OpenSSH 8.2p1 as version 8.2 with update p1, so matching fails
    if the whole string is jammed into the version field.
    """
    if product == "openssh":
        m = re.match(r"^(\d+(?:\.\d+)*)(p\d+)$", version)
        if m:
            return m.group(1), m.group(2)
    return version, "*"


def _esc(s):
    """Escape the characters CPE 2.3 treats specially."""
    s = (s or "*").strip().lower()
    if s == "*":
        return s
    for ch in (":", "/", "?", "#", "[", "]", "@"):
        s = s.replace(ch, "\\" + ch)
    return s.replace(" ", "_")
