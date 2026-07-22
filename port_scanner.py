"""Map the services a device on your own network is exposing.

A plain TCP connect scan: it opens an ordinary connection to each port, notes
which ones accept, and reads a short banner where the service offers one. No raw
sockets, no scapy, no Administrator needed.

This is asset-surface auditing - the defensive half of knowing your network. The
useful output isn't "port 3389 is open", it's "this box is exposing RDP and a
telnet server you forgot about". Findings carry a plain-English risk note so you
can act on them.

Only scan hosts you own or are explicitly authorised to test.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

import tls_certs

# Curated common-port list: fast to sweep, covers what actually turns up on a LAN.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "rpcbind", 135: "MSRPC", 139: "NetBIOS-SSN", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 515: "printer (LPD)", 548: "AFP", 554: "RTSP",
    587: "SMTP (submission)", 631: "IPP (printing)", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS proxy", 1433: "MSSQL", 1723: "PPTP VPN", 1883: "MQTT",
    1900: "UPnP", 2049: "NFS", 3128: "HTTP proxy", 3306: "MySQL", 3389: "RDP",
    5000: "UPnP / HTTP", 5060: "SIP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 7547: "TR-069 (ISP mgmt)", 8080: "HTTP (alt)",
    8443: "HTTPS (alt)", 8888: "HTTP (alt)", 9100: "printer (raw JetDirect)",
    27017: "MongoDB", 32400: "Plex",
}

# Ports worth a second look when they answer, and why.
RISKY_PORTS = {
    21: "FTP sends credentials and data in cleartext - use SFTP/FTPS.",
    23: "Telnet is fully unencrypted - it should not be running at all.",
    25: "An open SMTP server can be abused as a relay.",
    110: "POP3 without TLS exposes mail credentials in cleartext.",
    143: "IMAP without TLS exposes mail credentials in cleartext.",
    135: "MSRPC exposed - a common Windows lateral-movement path.",
    139: "Legacy NetBIOS session service - disable if unused.",
    445: "SMB exposed - the classic ransomware/lateral-movement target.",
    515: "Legacy print service, usually unauthenticated.",
    1080: "Open SOCKS proxy - can be abused to relay traffic.",
    1433: "MSSQL exposed to the network - should not be reachable broadly.",
    1723: "PPTP is cryptographically broken - migrate off it.",
    2049: "NFS export exposed - check its access rules.",
    3128: "Open HTTP proxy - can be abused to relay traffic.",
    3306: "MySQL exposed to the network - bind it to localhost if you can.",
    3389: "RDP exposed - a heavily brute-forced service.",
    5900: "VNC exposed - often weak or no authentication.",
    6379: "Redis is unauthenticated by default - a known easy compromise.",
    7547: "TR-069 ISP management port - historically a router exploit vector.",
    9100: "Raw printing port - unauthenticated by design.",
    27017: "MongoDB exposed - unauthenticated in older defaults.",
}

# Services worth nudging with a plaintext HTTP request.
_HTTPISH = {80, 631, 5000, 8080, 8888, 3128, 7547, 32400}
# TLS ports stay silent until you send a ClientHello, so don't wait on them -
# they get an actual TLS handshake instead (see scan_host's cert fetch).
TLS_PORTS = {443, 465, 636, 993, 995, 8443}
_TLS_PORTS = TLS_PORTS


def _banner(sock, port):
    if port in _TLS_PORTS:
        return ""
    try:
        sock.settimeout(0.6)
        if port in _HTTPISH:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                return ""
            data = sock.recv(240)
        else:
            # SSH, FTP, SMTP, telnet and the database engines all greet first -
            # and plenty of them run on non-standard ports, so just listen
            # rather than keying off the port number.
            data = sock.recv(160)
        text = data.decode("latin-1", "replace")
        return " ".join(text.split())[:90]
    except Exception:
        return ""


def _server_header(banner):
    # Pull just the Server: line out of an HTTP response, if present.
    low = banner.lower()
    idx = low.find("server:")
    if idx < 0:
        return ""
    return banner[idx + 7:].split(" HTTP/")[0].strip()[:60]


def probe_port(ip, port, timeout=0.5, grab=True):
    """Return a finding dict if the port accepts a connection, else None."""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            return None
        banner = _banner(sock, port) if grab else ""
    except Exception:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    if banner.startswith("HTTP/"):
        srv = _server_header(banner)
        banner = srv or banner.split("\r")[0][:60]
    return {
        "port": port,
        "service": COMMON_PORTS.get(port, ""),
        "banner": banner,
        "risk": RISKY_PORTS.get(port, ""),
    }


def scan_host(ip, ports=None, timeout=0.5, workers=64, grab=True, should_stop=None,
              fetch_certs=True):
    """TCP-connect scan `ip`. Returns findings sorted by port.

    For TLS services we run a real handshake and attach the server certificate
    under f['cert'] - which works on TLS 1.3, unlike passive capture.
    """
    targets = sorted(ports) if ports else sorted(COMMON_PORTS)
    findings = []

    def work(port):
        if should_stop and should_stop():
            return None
        return probe_port(ip, port, timeout=timeout, grab=grab)

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(targets)))) as pool:
        for res in pool.map(work, targets):
            if res:
                findings.append(res)
    findings.sort(key=lambda f: f["port"])

    if fetch_certs:
        for f in findings:
            if f["port"] not in TLS_PORTS:
                continue
            if should_stop and should_stop():
                break
            cert = tls_certs.fetch_certificate(ip, f["port"], timeout=max(2.0, timeout * 4))
            if cert:
                f["cert"] = cert
                issues = [x for x in tls_certs.analyze(cert, hostname=ip) if x[0] != "INFO"]
                # A cert issued for a hostname won't match the IP we dialled; that
                # is expected here and not worth flagging on a LAN scan.
                f["cert_issues"] = [x for x in issues if x[1] != "hostname mismatch"]
    return findings


def risky(findings):
    """Just the findings that carry a risk note."""
    return [f for f in findings if f.get("risk")]


def summarize(findings):
    """One-line summary of a scan result."""
    if not findings:
        return "no open ports found"
    bits = []
    for f in findings:
        label = f["service"] or "?"
        bits.append(f"{f['port']}/{label}")
    n_risk = len(risky(findings))
    line = f"{len(findings)} open: " + ", ".join(bits)
    if n_risk:
        line += f"   ({n_risk} worth review)"
    return line
