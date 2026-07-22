"""Detect credentials sent in cleartext - defensively, so you can see what's
exposed on your own network and fix it (move it to TLS).

Fed a payload (bytes) plus the server port, this recognises the common
plaintext auth patterns: HTTP Basic auth, FTP / POP3 USER+PASS, IMAP LOGIN,
SMTP AUTH PLAIN, and best-effort HTTP form logins.

It MASKS the password before returning it. The point is to flag exposure, not
to hoard secrets - and these findings get written to the event log / database,
so storing full plaintext passwords there would just create a new place for them
to leak. Usernames are shown so you can tell which account is affected.
"""

import base64
import re
import urllib.parse

# Well-known cleartext service ports -> protocol label.
PLAINTEXT_PORTS = {
    21: "FTP", 23: "telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 389: "LDAP", 8000: "HTTP", 8080: "HTTP", 8888: "HTTP",
}


def _mask(secret):
    s = str(secret)
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def find_credentials(payload, server_port=None):
    """Return (kind, detail) if cleartext credentials are found, else None.
    `detail` shows the username and a MASKED password."""
    if not payload:
        return None
    proto = PLAINTEXT_PORTS.get(server_port)
    text = bytes(payload)[:4096].decode("latin-1", "replace")

    # HTTP Basic auth: "Authorization: Basic base64(user:pass)"
    m = re.search(r"[Aa]uthorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
    if m:
        try:
            dec = base64.b64decode(m.group(1)).decode("latin-1", "replace")
            if ":" in dec:
                user, pw = dec.split(":", 1)
                return ("HTTP Basic auth", f"user '{user}'  pass '{_mask(pw)}'")
        except Exception:
            pass

    # SMTP AUTH PLAIN: base64("\0user\0pass")
    m = re.search(r"AUTH\s+PLAIN\s+([A-Za-z0-9+/=]{4,})", text, re.I)
    if m:
        try:
            dec = base64.b64decode(m.group(1)).decode("latin-1", "replace")
            fields = dec.split("\x00")
            if len(fields) >= 3 and fields[2]:
                return ("SMTP AUTH PLAIN", f"user '{fields[1]}'  pass '{_mask(fields[2])}'")
        except Exception:
            pass

    # IMAP: "<tag> LOGIN user pass"
    m = re.search(r'^\S*\s*LOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', text, re.I | re.M)
    if m:
        return ("IMAP login", f"user '{m.group(1)}'  pass '{_mask(m.group(2))}'")

    # FTP / POP3 line-based USER + PASS
    um = re.search(r"^USER\s+(\S+)", text, re.I | re.M)
    pm = re.search(r"^PASS\s+(\S+)", text, re.I | re.M)
    if um or pm:
        parts = []
        if um:
            parts.append(f"user '{um.group(1)}'")
        if pm:
            parts.append(f"pass '{_mask(pm.group(1))}'")
        return (f"{proto or 'plaintext'} login", "  ".join(parts))

    # HTTP form login (best-effort): common field names in a POST body / query.
    if proto == "HTTP" or "password" in text.lower():
        pm = re.search(r"(?:pass(?:word|wd)?|pwd)=([^&\s]+)", text, re.I)
        if pm:
            um = re.search(r"(?:user(?:name)?|email|login|user_login)=([^&\s]+)", text, re.I)
            parts = []
            if um:
                parts.append(f"user '{urllib.parse.unquote_plus(um.group(1))}'")
            parts.append(f"pass '{_mask(urllib.parse.unquote_plus(pm.group(1)))}'")
            return ("HTTP form login", "  ".join(parts))

    return None
