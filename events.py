# events.py
#
# Central event / log bus. Every detector and module reports here, so the
# Logs tab (and the database, and a log file) all see one stream.
#
#   events.log_event("ALERT", "scan", "1.2.3.4", "Port scan detected ...")
import os
import threading
import time
from collections import deque

import db_manager

SEVERITIES = ("INFO", "WARNING", "ALERT")

_LOCK = threading.Lock()
_BUFFER = deque(maxlen=3000)
_LOG_FILE = os.path.join(os.path.dirname(__file__), "sentinelfusion.log")


def log_event(severity, category, source, message):
    now = time.time()
    sev = severity if severity in SEVERITIES else "INFO"
    # Honour the detection-rules catalog: a disabled rule's category is suppressed
    # at the source. Informational/system categories are never suppressed.
    try:
        import detection_rules
        if not detection_rules.is_enabled(str(category)):
            return None
    except Exception:
        pass
    # Honour the allowlist: destinations the analyst has already judged benign
    # stop raising the same finding. Scoped per category, and categories in
    # allowlist.NEVER_SUPPRESS (threat-intel hits, cleartext credentials, known
    # CVEs, certificate problems) always get through regardless.
    try:
        import allowlist
        if allowlist.suppresses(str(category), ip=str(source)):
            return None
    except Exception:
        pass
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    event = {
        "ts": now,
        "stamp": stamp,
        "severity": sev,
        "category": str(category),
        "source": str(source),
        "message": str(message),
    }

    with _LOCK:
        _BUFFER.append(event)

    # Fold into the correlation engine so related alerts group into incidents.
    try:
        import correlation
        correlation.ingest(event)
    except Exception:
        pass

    # Persist to the database (best effort).
    try:
        db_manager.insert_event(sev, str(category), str(source), str(message), stamp)
    except Exception:
        pass

    # Append to the log file (best effort).
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{stamp} [{sev}] {category}/{source}: {message}\n")
    except Exception:
        pass


def recent(limit=300, severity=None, category=None):
    with _LOCK:
        items = list(_BUFFER)
    if severity and severity != "ALL":
        items = [e for e in items if e["severity"] == severity]
    if category and category != "ALL":
        items = [e for e in items if e["category"] == category]
    return items[-limit:]


# Plain-English meaning of each alert category (shown in the UI so a reader
# knows *why* something fired, not just that it did).
CATEGORY_INFO = {
    "scan": "Port scan - one host probed many ports on another, hunting for open services.",
    "sweep": "Ping sweep - a host pinged many addresses to find out which are alive.",
    "flood": "SYN flood - a burst of half-open TCP connections, often a denial-of-service attempt.",
    "arp": "ARP anomaly - an IP-to-MAC mapping changed, which can mean ARP spoofing / man-in-the-middle.",
    "dns": "DNS anomaly - e.g. a zone-transfer (AXFR/IXFR) attempt to dump every record in a domain.",
    "tunnel": "DNS tunneling - data smuggled inside DNS query names (many long/random subdomains under one domain).",
    "dga": "DGA activity - a burst of random-looking domains returning NXDOMAIN, typical of malware hunting for its C2 server.",
    "intel": "Threat-intel hit - traffic touched an IP listed on a known-bad reputation feed.",
    "ja3": "Malicious TLS fingerprint - a handshake's JA3 matches a known-bad fingerprint (malware/tooling).",
    "protocol": "Protocol on the wrong port - deep inspection identified a protocol that does not match the port it arrived on. Carrying one protocol over another's port (SSH over 443, a tunnel over 53) is how traffic is routed past egress filtering. Also covers unrecognised high-entropy traffic on a port that should be plaintext.",
    "http": "HTTP transaction of note - a cleartext HTTP request worth attention: credentials in the URL or a Basic-auth header, a download of an executable, or a non-browser (tooling/automation) client. Everything here crossed the network unencrypted.",
    "cert": "TLS certificate problem - the server's certificate is self-signed, expired, weak, or issued for a different hostname. A hostname mismatch in particular is what TLS interception looks like.",
    "creds": "Cleartext credentials - a username/password was sent unencrypted (HTTP Basic, FTP, POP3, IMAP, SMTP); move that service to TLS.",
    "rogue": "Rogue DHCP server - a second, unexpected DHCP server is answering on your network. It can hand out its own address as your gateway or DNS and put itself in the middle of your traffic.",
    "service": "Exposed service - a device on your network is offering a service that is unencrypted, unauthenticated, or a known attack target. Review whether it needs to be reachable.",
    "exfil": "Possible data exfiltration - a large, mostly-outbound transfer to a single endpoint.",
    "beacon": "Beaconing - evenly-timed callouts to one endpoint, a classic command-and-control pattern.",
    "watch": "Watchlist match - traffic touched an IP/CIDR, country, or ASN you flagged to watch.",
    "device": "Device discovery event.",
    "endpoint": "Endpoint event.",
    "wifi": "Wireless (802.11) event - deauth flood, rogue AP, or evil twin detected in the air.",
    "soar": "SOAR automation - a playbook ran, or a case was opened/updated.",
    "vuln": "Known vulnerability - a service version on a device you own matches "
            "a published CVE. An asset/patching finding, not an attack in progress.",
    "system": "System / monitoring status.",
}


def explain(category):
    return CATEGORY_INFO.get(category, "")


# --- alert triage: acknowledge / dismiss ---
# Session-scoped (the ring buffer is rebuilt fresh each run, so acks needn't
# persist). Keyed by stable event content so a key survives buffer churn.
_acked = set()


def event_key(e):
    return f"{e.get('stamp', '')}|{e.get('source', '')}|{e.get('message', '')}"


def acknowledge(key):
    with _LOCK:
        _acked.add(key)


def unacknowledge(key):
    with _LOCK:
        _acked.discard(key)


def is_acked(key):
    with _LOCK:
        return key in _acked


def clear_acks():
    with _LOCK:
        _acked.clear()


def unacked_count(severity=None):
    return sum(1 for e in recent(limit=3000, severity=severity)
               if not is_acked(event_key(e)))
