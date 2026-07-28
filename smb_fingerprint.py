"""SMB fingerprinting - get a Windows version out of a service that sends no banner.

Port 445 is the most common open port on a Windows network and it volunteers
nothing: connect and it waits silently for you to speak SMB. That silence is why
banner-based scanning reports 0% on a Windows estate even though those hosts are
the ones most worth knowing the patch level of.

Two exchanges get us there, both of which happen *before* any authentication:

  1. **SMB2 NEGOTIATE** - the client offers a list of dialects, the server picks
     one. The chosen dialect alone brackets the OS generation (3.1.1 means
     Windows 10 / Server 2016 or newer, 2.1 means Windows 7 / Server 2008 R2).

  2. **SESSION_SETUP carrying an NTLMSSP NEGOTIATE token** - the server answers
     with STATUS_MORE_PROCESSING_REQUIRED and an NTLMSSP CHALLENGE. That
     challenge contains an 8-byte Version field: major, minor and build number.
     Build numbers are precise - 19045 is Windows 10 22H2, 26100 is Windows 11
     24H2 - and map straight onto CPEs.

**This is not an authentication attempt.** Every SMB client sends exactly these
two messages before it can authenticate; the server publishes its version in the
reply as part of normal protocol operation. We read the challenge and disconnect.
No credentials are sent, no NTLMSSP AUTHENTICATE is constructed, and nothing is
guessed or replayed. The exchange is read-only and is what any file-manager does
when you type \\\\host into it.

Binary construction is kept explicit and offset-commented, because silent
misalignment is the failure mode here - a wrong offset yields plausible garbage
rather than an error.
"""

import socket
import struct

# SMB2 dialects we offer. 0x0311 (3.1.1) is deliberately omitted: it requires
# negotiate contexts in the request, and every Windows release that speaks 3.1.1
# also accepts 3.0.2, so we learn what we need without the extra complexity.
_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)

DIALECT_NAMES = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1",
}

# Dialect -> the earliest Windows release that introduced it. Useful on its own
# when NTLMSSP is unavailable (Samba, hardened hosts, non-Windows SMB).
DIALECT_ERA = {
    0x0202: "Windows Vista / Server 2008 or newer",
    0x0210: "Windows 7 / Server 2008 R2 or newer",
    0x0300: "Windows 8 / Server 2012 or newer",
    0x0302: "Windows 8.1 / Server 2012 R2 or newer",
    0x0311: "Windows 10 / Server 2016 or newer",
}

# Build number -> (release name, NVD product slug, release date).
# NVD indexes Windows by *release* - the product is "windows_11_24h2", not
# "windows_11" - and versions carry a fourth revision component
# (10.0.26100.1742). We only learn major.minor.build from NTLMSSP, so we query
# at product level and say so, rather than fabricating a revision.
_BUILDS = {
    10240: ("Windows 10", "1507", "windows_10_1507", "2015-07-29"),
    10586: ("Windows 10", "1511", "windows_10_1511", "2015-11-10"),
    14393: ("Windows 10", "1607", "windows_10_1607", "2016-08-02"),
    15063: ("Windows 10", "1703", "windows_10_1703", "2017-04-05"),
    16299: ("Windows 10", "1709", "windows_10_1709", "2017-10-17"),
    17134: ("Windows 10", "1803", "windows_10_1803", "2018-04-30"),
    17763: ("Windows 10", "1809", "windows_10_1809", "2018-11-13"),
    18362: ("Windows 10", "1903", "windows_10_1903", "2019-05-21"),
    18363: ("Windows 10", "1909", "windows_10_1909", "2019-11-12"),
    19041: ("Windows 10", "2004", "windows_10_2004", "2020-05-27"),
    19042: ("Windows 10", "20H2", "windows_10_20h2", "2020-10-20"),
    19043: ("Windows 10", "21H1", "windows_10_21h1", "2021-05-18"),
    19044: ("Windows 10", "21H2", "windows_10_21h2", "2021-11-16"),
    19045: ("Windows 10", "22H2", "windows_10_22h2", "2022-10-18"),
    20348: ("Windows Server 2022", "", "windows_server_2022", "2021-08-18"),
    22000: ("Windows 11", "21H2", "windows_11_21h2", "2021-10-05"),
    22621: ("Windows 11", "22H2", "windows_11_22h2", "2022-09-20"),
    22631: ("Windows 11", "23H2", "windows_11_23h2", "2023-10-31"),
    26100: ("Windows 11", "24H2", "windows_11_24h2", "2024-10-01"),
    26200: ("Windows 11", "25H2", "windows_11_25h2", "2025-09-30"),
}

# major.minor -> (product, NVD slug), for releases before the 10.0 era.
_LEGACY = {
    (6, 3): ("Windows 8.1 / Server 2012 R2", "windows_8.1"),
    (6, 2): ("Windows 8 / Server 2012", "windows_8"),
    (6, 1): ("Windows 7 / Server 2008 R2", "windows_7"),
    (6, 0): ("Windows Vista / Server 2008", "windows_vista"),
    (5, 2): ("Windows Server 2003", "windows_server_2003"),
    (5, 1): ("Windows XP", "windows_xp"),
}

# When each product family first shipped. A CVE older than this cannot describe
# the product at all; anything after it plausibly can, because releases inherit
# code from their predecessors.
_FAMILY_EPOCH = {
    "Windows 11": "2021-10-05",
    "Windows 10": "2015-07-29",
    "Windows Server 2022": "2021-08-18",
    "Windows 8.1 / Server 2012 R2": "2013-10-17",
    "Windows 7 / Server 2008 R2": "2009-10-22",
}

_SMB2_MAGIC = b"\xfeSMB"
_NTLMSSP_SIG = b"NTLMSSP\x00"


def _transport(payload):
    """Direct TCP transport header: one zero byte then a 3-byte big-endian length."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_header(command, message_id, session_id=0):
    """64-byte SMB2 header."""
    return b"".join((
        _SMB2_MAGIC,                        # 0  ProtocolId
        struct.pack("<H", 64),              # 4  StructureSize
        struct.pack("<H", 0),               # 6  CreditCharge
        struct.pack("<I", 0),               # 8  Status
        struct.pack("<H", command),         # 12 Command
        struct.pack("<H", 31),              # 14 CreditRequest
        struct.pack("<I", 0),               # 16 Flags
        struct.pack("<I", 0),               # 20 NextCommand
        struct.pack("<Q", message_id),      # 24 MessageId
        struct.pack("<I", 0),               # 32 Reserved
        struct.pack("<I", 0),               # 36 TreeId
        struct.pack("<Q", session_id),      # 40 SessionId
        b"\x00" * 16,                       # 48 Signature
    ))


def _negotiate_request():
    body = b"".join((
        struct.pack("<H", 36),                      # StructureSize
        struct.pack("<H", len(_DIALECTS)),          # DialectCount
        struct.pack("<H", 1),                       # SecurityMode: signing enabled
        struct.pack("<H", 0),                       # Reserved
        struct.pack("<I", 0),                       # Capabilities
        b"\x00" * 16,                               # ClientGuid
        struct.pack("<Q", 0),                       # ClientStartTime
    )) + b"".join(struct.pack("<H", d) for d in _DIALECTS)
    return _transport(_smb2_header(0x0000, 0) + body)


def _ntlmssp_negotiate():
    """An NTLMSSP NEGOTIATE token - the opening message of the handshake.

    It carries no identity: no username, no domain, no credential material. Its
    only role here is to prompt the server for its CHALLENGE, which is where the
    version lives.
    """
    flags = (0x00000001 |    # UNICODE
             0x00000004 |    # REQUEST_TARGET
             0x00000200 |    # NTLM
             0x00008000 |    # ALWAYS_SIGN
             0x00080000 |    # EXTENDED_SESSIONSECURITY
             0x02000000)     # VERSION - asks the server to include its build
    return b"".join((
        _NTLMSSP_SIG,
        struct.pack("<I", 1),               # MessageType: NEGOTIATE
        struct.pack("<I", flags),
        struct.pack("<HHI", 0, 0, 0),       # DomainName: empty
        struct.pack("<HHI", 0, 0, 0),       # Workstation: empty
        b"\x00" * 8,                        # Version (ours; ignored by server)
    ))


def _session_setup_request(message_id=1):
    token = _ntlmssp_negotiate()
    # Security buffer starts right after the 64-byte header + 24-byte fixed body.
    offset = 64 + 24
    body = b"".join((
        struct.pack("<H", 25),                  # StructureSize
        struct.pack("<B", 0),                   # Flags
        struct.pack("<B", 1),                   # SecurityMode
        struct.pack("<I", 0),                   # Capabilities
        struct.pack("<I", 0),                   # Channel
        struct.pack("<H", offset),              # SecurityBufferOffset
        struct.pack("<H", len(token)),          # SecurityBufferLength
        struct.pack("<Q", 0),                   # PreviousSessionId
    ))
    return _transport(_smb2_header(0x0001, message_id) + body + token)


def _read_message(sock):
    """Read one transport-framed SMB2 message."""
    head = _recv_exact(sock, 4)
    if len(head) < 4:
        return b""
    length = int.from_bytes(head[1:4], "big")
    if not (0 < length <= 1 << 20):
        return b""
    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            part = sock.recv(n - len(buf))
        except Exception:
            break
        if not part:
            break
        buf += part
    return buf


def parse_negotiate_response(data):
    """Return the negotiated dialect from a NEGOTIATE response, or None."""
    if len(data) < 72 or not data.startswith(_SMB2_MAGIC):
        return None
    # 64-byte header, then StructureSize(2) SecurityMode(2) DialectRevision(2)
    return struct.unpack_from("<H", data, 64 + 4)[0]


def parse_ntlm_version(data):
    """Pull the OS version out of an NTLMSSP CHALLENGE embedded in `data`.

    Located by searching for the NTLMSSP signature rather than by fixed offset,
    so it works whether or not the token is wrapped in SPNEGO.
    Returns {major, minor, build} or None.
    """
    idx = data.find(_NTLMSSP_SIG)
    if idx < 0:
        return None
    if len(data) < idx + 56:
        return None
    if struct.unpack_from("<I", data, idx + 8)[0] != 2:      # MessageType CHALLENGE
        return None
    # CHALLENGE layout: sig(8) type(4) target(8) flags(4) challenge(8)
    # reserved(8) targetinfo(8) version(8)  -> version at +48
    major, minor = data[idx + 48], data[idx + 49]
    build = struct.unpack_from("<H", data, idx + 50)[0]
    if major == 0 and minor == 0 and build == 0:
        return None
    return {"major": major, "minor": minor, "build": build}


def describe_version(ver):
    """Turn {major, minor, build} into a product, release, and NVD-shaped CPE."""
    if not ver:
        return None
    major, minor, build = ver["major"], ver["minor"], ver["build"]
    version_str = f"{major}.{minor}.{build}"
    released = None
    if (major, minor) == (10, 0):
        entry = _BUILDS.get(build)
        if entry:
            product, release, slug, released = entry
        else:
            product, release, slug = "Windows 10 / 11 family", "", ""
    else:
        product = _LEGACY.get((major, minor), ("Windows", ""))[0]
        release = ""
        slug = _LEGACY.get((major, minor), ("", ""))[1]
    return {
        "product": product,
        "release": release,
        "version": version_str,
        "build": build,
        "released": released,
        # Epoch for plausibility flagging is the *product family's* launch, not
        # this release's ship date. An OS release inherits code from everything
        # before it, so a CVE published months before 24H2 shipped can still
        # describe a flaw it carries. Using the release date flagged genuine
        # findings as implausible - the family launch is the defensible floor.
        "epoch": _FAMILY_EPOCH.get(product, released),
        # Product-level CPE with a wildcard version. NVD stores a separate CPE
        # per patch revision (…26100.1742) and SMB never reveals the revision, so
        # an exact query is impossible. Matching at product level returns the
        # CVEs known for this *release* - honest, and genuinely useful for
        # inventory - as long as it is not presented as a patch-status verdict.
        "cpe": f"cpe:2.3:o:microsoft:{slug}:*:*:*:*:*:*:*:*" if slug else "",
        "cpe_broad": True,
        "precision": "release",
    }


def fingerprint(ip, port=445, timeout=3.0):
    """Negotiate with an SMB server and report what it discloses.

    Returns {ok, dialect, dialect_name, era, os, error}. Never raises - a host
    that refuses, times out, or speaks something else yields ok=False.
    """
    result = {"ok": False, "dialect": None, "dialect_name": "", "era": "",
              "os": None, "error": None}
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((ip, port)) != 0:
            result["error"] = "connect failed"
            return result

        sock.sendall(_negotiate_request())
        data = _read_message(sock)
        dialect = parse_negotiate_response(data)
        if dialect is None:
            result["error"] = "no SMB2 negotiate response (SMB1-only host?)"
            return result
        result.update(ok=True, dialect=dialect,
                      dialect_name=DIALECT_NAMES.get(dialect, hex(dialect)),
                      era=DIALECT_ERA.get(dialect, ""))

        # Second exchange: prompt for the NTLMSSP challenge that carries the build.
        sock.sendall(_session_setup_request())
        data = _read_message(sock)
        ver = parse_ntlm_version(data)
        if ver:
            result["os"] = describe_version(ver)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def summarize(res):
    """Plain-language lines for a scan panel."""
    if not res or not res.get("ok"):
        return [f"SMB: {(res or {}).get('error') or 'no response'}"]
    lines = [f"SMB dialect: {res['dialect_name']}"]
    if res.get("era"):
        lines.append(f"   implies {res['era']}")
    os_info = res.get("os")
    if os_info:
        rel = f" {os_info['release']}" if os_info["release"] else ""
        lines.append(f"OS: {os_info['product']}{rel}  (build {os_info['build']}, "
                     f"{os_info['version']})")
        if os_info["cpe"]:
            lines.append(f"   {os_info['cpe']}")
            lines.append("   Release-level only: SMB discloses the build but not "
                         "the patch revision, so CVEs found are those affecting "
                         "this release, not proof this host is unpatched.")
    else:
        lines.append("OS version not disclosed (server withheld the NTLM version "
                     "field - common on Samba and hardened hosts)")
    return lines
