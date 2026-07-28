"""Banner diagnostic - find out why version detection came back empty.

A 0% version-disclosure rate is suspicious rather than informative, because some
protocols announce themselves whether you ask or not. An SSH server sends
"SSH-2.0-..." the moment you connect - that is in the protocol. If port 22 gave
us nothing, the problem is on our side.

This deliberately does NOT use port_scanner, so it isolates the variable: it
opens its own sockets and prints the raw bytes each service returns, at several
timeouts. Compare the results and the cause becomes obvious:

  * bytes at 3.0s but nothing at 0.6s  -> the scanner's timeout is too short
  * nothing at any timeout             -> the service genuinely stays silent
  * bytes returned but "no match"      -> the parser needs a rule for it

Usage:
    python diag_banners.py 192.168.1.6
    python diag_banners.py 192.168.1.6 22 80 445
"""

import sys
import socket

TIMEOUTS = (0.6, 1.5, 3.0)

# Ports where the client is expected to speak first; we send a nudge.
HTTP_PORTS = {80, 631, 5000, 8080, 8888, 3128, 7547, 32400}
TLS_PORTS = {443, 465, 636, 993, 995, 8443}

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 554,
                 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]


def grab(ip, port, timeout, send_probe=None):
    """Open a connection and read whatever the service says. Returns
    (connected, raw_bytes, error)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        if sock.connect_ex((ip, port)) != 0:
            return (False, b"", "connect refused/filtered")
    except Exception as exc:
        return (False, b"", f"connect error: {exc}")
    try:
        if send_probe:
            try:
                sock.sendall(send_probe)
            except Exception as exc:
                return (True, b"", f"send failed: {exc}")
        data = sock.recv(512)
        return (True, data, "")
    except socket.timeout:
        return (True, b"", f"no data within {timeout}s")
    except Exception as exc:
        return (True, b"", f"recv error: {exc}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _http_probes(ip):
    """The requests to try on an HTTP port, best first.

    Must mirror what port_scanner actually sends, or this tool reports on code
    that isn't running. Both forms are tried because the difference is itself
    diagnostic: a server that answers 1.1 but not 1.0 is enforcing the mandatory
    Host header, which reads as "silent service" to a bare 1.0 probe.
    """
    return [
        ("HTTP/1.1 with Host",
         (f"HEAD / HTTP/1.1\r\nHost: {ip}\r\n"
          "User-Agent: SentinelFusion/1.0 (network inventory)\r\n"
          "Accept: */*\r\nConnection: close\r\n\r\n").encode()),
        ("HTTP/1.0 bare", b"HEAD / HTTP/1.0\r\n\r\n"),
    ]


def probe_port(ip, port):
    print(f"\n  {port}/tcp")
    if port in TLS_PORTS:
        _probe_tls(ip, port)
        return
    if port in HTTP_PORTS:
        for label, probe in _http_probes(ip):
            print(f"     -- {label} --")
            if _try_timeouts(ip, port, probe):
                return
        print("     -> silent to both request forms: not an HTTP service, or it "
              "needs a full GET.")
        return
    _try_timeouts(ip, port, None)


def _probe_tls(ip, port):
    """A TLS port sends no plaintext banner, but its certificate is an identity.

    Embedded devices ship self-signed certificates whose subject or issuer names
    the vendor - often the only thing a hardened device discloses about itself.
    """
    print("     TLS port - no plaintext banner by design; reading the certificate.")
    try:
        import tls_certs
    except Exception as exc:
        print(f"     (tls_certs unavailable: {exc})")
        return
    try:
        detail = tls_certs.fetch_certificate_detail(ip, port, timeout=6.0)
    except Exception as exc:
        print(f"     handshake failed: {exc}")
        return
    cert = detail.get("cert")
    if not cert:
        print(f"     no certificate: {detail.get('error')}")
        print("     -> if this mentions protocol or cipher, the device is running "
              "TLS too old for a modern client to negotiate at all.")
        return
    if detail.get("mode") and detail["mode"] != "default":
        print(f"     negotiated only via {detail['mode']}")
    if cert.get("tls_version") or cert.get("cipher"):
        print(f"     {cert.get('tls_version', '?')}  {cert.get('cipher', '')}")
    # Use the same analyzer the GUI scan uses. A private copy here drifted from
    # the scanner three times already; sharing the check means the diagnostic
    # and the tool can no longer disagree.
    issues = [i for i in tls_certs.analyze(cert, hostname=ip) if i[0] != "INFO"]
    for sev, label, detail in issues:
        print(f"     [{sev}] {label}: {detail[:88]}")
    if any(l in ("no forward secrecy", "weak key", "weak signature",
                 "obsolete cipher") for _s, l, _d in issues):
        print("     -> this, not the protocol version, is why a default client "
              "refuses the handshake.")

    subject = cert.get("subject") or {}
    issuer = cert.get("issuer") or {}
    print("     certificate:")
    for label, field in (("subject", subject), ("issuer", issuer)):
        parts = ", ".join(f"{k}={v}" for k, v in field.items() if v)
        print(f"       {label:8}: {parts[:100] or '(empty)'}")
    san = cert.get("san") or []
    if san:
        print(f"       SAN     : {', '.join(str(s) for s in san[:4])[:100]}")
    key = cert.get("key_type") or "?"
    if cert.get("key_bits"):
        key += f" {cert['key_bits']}-bit"
    if cert.get("curve"):
        key += f" ({cert['curve']})"
    print(f"       key     : {key}")
    if cert.get("sig_alg"):
        print(f"       signed  : {cert['sig_alg']}")
    if cert.get("self_signed"):
        print("       self-signed (normal for embedded devices)")

    try:
        import service_fingerprint
        prods = service_fingerprint.identify_from_cert(cert)
        if prods:
            print(f"       IDENTIFIED: {prods[0]['label']}")
        else:
            print("       -> certificate names no vendor or product; it only "
                  "identifies the host, which we already know.")
    except Exception as exc:
        print(f"       (parser unavailable: {exc})")


def _try_timeouts(ip, port, probe):
    """Try each timeout in turn. Returns True once data is obtained."""
    for t in TIMEOUTS:
        connected, data, err = grab(ip, port, t, probe)
        if not connected:
            print(f"     {t}s: {err}")
            return False
        if data:
            text = data.decode("latin-1", "replace")
            print(f"     {t}s: {len(data)} bytes")
            if text.startswith("HTTP/"):
                # Mirror the scanner: it extracts Server: from the full head and
                # identifies on that alone. Parsing the whole flattened response
                # instead reports digits from Date and Content-Length as if they
                # were a version.
                server = ""
                for line in text.split("\n"):
                    if line[:7].lower() == "server:":
                        server = line.split(":", 1)[1].strip()
                        break
                print("           status: " + text.split("\n")[0].strip())
                if server:
                    print(f"           Server: {server}")
                    _report_parse(server, port)
                else:
                    print("           Server: (header absent)")
                    print("           -> nothing to identify: this server does "
                          "not name itself. Not a parser gap.")
                    print("           full head:")
                    for line in text.split("\n")[1:8]:
                        if line.strip():
                            print(f"             {line.strip()[:90]}")
            else:
                flat = " ".join(text.split())[:160]
                print(f"           raw   : {data[:80]!r}")
                print(f"           text  : {flat}")
                _report_parse(flat, port)
            return True
        print(f"     {t}s: {err or 'no data'}")
    return False


def _report_parse(value, port):
    """Show what service_fingerprint makes of a candidate identity string."""
    try:
        import service_fingerprint
    except Exception as exc:
        print(f"           (parser unavailable: {exc})")
        return
    prods = service_fingerprint.identify(value, port)
    hi = [p for p in prods if p["confidence"] == "high"]
    if hi:
        for p in hi:
            print(f"           PARSED: {p['label']} {p['version']}")
    elif any(c.isdigit() for c in value):
        print("           PARSED: not matched, but this string has digits - "
              "a rule may be worth adding")
    else:
        print("           PARSED: no version present in this string")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    ip = sys.argv[1]
    ports = [int(a) for a in sys.argv[2:]] if len(sys.argv) > 2 else DEFAULT_PORTS
    print(f"Banner diagnostic for {ip}")
    print(f"Trying {len(ports)} port(s) at timeouts {TIMEOUTS}")
    print("=" * 68)
    for port in ports:
        try:
            probe_port(ip, port)
        except KeyboardInterrupt:
            print("\ninterrupted")
            return
        except Exception as exc:
            print(f"  {port}/tcp  error: {exc}")
    print("\n" + "=" * 68)
    print("How to read this:")
    print("  bytes at 3.0s but not 0.6s -> raise the scanner's banner timeout")
    print("  bytes but 'nothing matched' -> service_fingerprint needs a rule")
    print("  silent everywhere           -> genuinely no version disclosed")


if __name__ == "__main__":
    main()
