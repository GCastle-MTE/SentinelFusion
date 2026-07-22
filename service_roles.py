"""Service role classification - what is each connection *for*?

When a process like a game talks to a dozen servers, they're not all the same
thing: one is the real-time game server, one is matchmaking / the platform API,
one is voice chat, one is anti-cheat, others are CDN downloads or telemetry. This
module looks at what we've observed about each remote endpoint - hostname, ports,
protocol, packet shape, byte volume, ASN/ISP, whether it looks like an RTP media
stream - and assigns a role with a confidence and the evidence behind it.

It's deliberately explainable: every verdict comes with human-readable reasons so
the analyst can see *why* something was called "voice chat" rather than being
asked to trust a black box. Pure functions over plain dicts - no I/O, no imports
of the engine - so it's easy to test and reuse.
"""

# Roles we recognise, roughly ordered from most to least "interactive".
ROLE_GAME = "Game server"
ROLE_VOICE = "Voice chat"
ROLE_MATCH = "Matchmaking / platform"
ROLE_ANTICHEAT = "Anti-cheat"
ROLE_AUTH = "Auth / login"
ROLE_CDN = "CDN / content / update"
ROLE_TELEMETRY = "Telemetry / analytics"
ROLE_WEB = "Web / API"
ROLE_P2P = "Peer-to-peer"
ROLE_UNKNOWN = "Unknown"

# Hostname keyword -> role. Checked against SNI and reverse-DNS names.
_HOST_HINTS = [
    (ROLE_VOICE, ("vivox", "voice", "voip", "mumble", "teamspeak", "ts3",
                  "discord.gg", "discord.media", "rtc", "webrtc", "opus")),
    (ROLE_ANTICHEAT, ("battleye", "easyanticheat", "eac-", "anticheat",
                      "punkbuster", "vanguard")),
    (ROLE_MATCH, ("matchmaking", "matchmaker", "mmr", "lobby", "party",
                  "session", "gamelift", "playfab", "multiplay")),
    (ROLE_AUTH, ("auth", "login", "account", "sso", "oauth", "token",
                 "identity", "signin")),
    (ROLE_TELEMETRY, ("telemetry", "analytics", "metrics", "datadog",
                      "crashlytics", "sentry.io", "amplitude", "mixpanel",
                      "stats", "tracking")),
    (ROLE_CDN, ("akamai", "cloudfront", "fastly", "cloudflare", "cdn",
                "content", "download", "patch", "update", "assets", "steamcontent")),
    (ROLE_GAME, ("gameserver", "game-", "-gs", "gs-", "gameplay", "realtime")),
]

# ASN / ISP keyword -> hint. Cloud-hosting orgs commonly back game/voice infra.
_ASN_HINTS = {
    "game": ("i3d", "multiplay", "gameservers", "nitrado", "gportal"),
    "cloud": ("amazon", "aws", "google", "microsoft", "azure", "ovh", "hetzner",
              "digitalocean", "linode"),
    "cdn": ("akamai", "cloudflare", "fastly", "cloudfront", "limelight", "edgecast"),
    "voice": ("vivox", "twilio", "agora"),
}

# Well-known port hints (weak signal, used only as a tie-breaker).
_PORT_HINTS = {
    443: ROLE_WEB, 80: ROLE_WEB, 3478: ROLE_VOICE, 5349: ROLE_VOICE,
    27015: ROLE_GAME, 3074: ROLE_GAME,
}


def classify(ep):
    """Classify one endpoint. `ep` is a dict with any of:

        host        reverse-DNS / SNI string (or list of names)
        sni         list of TLS server names
        ports       list of (port, count) or list of ints
        protos      list of (proto, count) or list of strings
        app_proto   DPI-identified application protocol (e.g. "TLS", "QUIC")
        in_bytes, out_bytes, packets, rate
        udp_steady  bool - flow looked like a steady small-packet UDP stream
        is_rtp      bool - flow_analytics flagged an RTP media stream
        asn, isp    strings
        mean_len    mean packet length if known

    Returns {"role", "confidence", "reasons": [...]}.
    """
    names = _names(ep)
    scores = {}
    reasons = {}

    def add(role, weight, why):
        scores[role] = scores.get(role, 0) + weight
        reasons.setdefault(role, []).append(why)

    # 1) Hostname keywords - the strongest signal when present.
    for name in names:
        low = name.lower()
        for role, keys in _HOST_HINTS:
            for k in keys:
                if k in low:
                    add(role, 5, f"hostname '{name}' contains '{k}'")
                    break

    # 2) RTP media stream => voice (or in-game voice), very strong.
    if ep.get("is_rtp"):
        add(ROLE_VOICE, 5, "traffic matches an RTP media stream (small, steady, two-way)")

    # 3) Packet shape: steady small UDP both ways at a decent rate = real-time.
    protos = _flatten(ep.get("protos"))
    udp = any("udp" in str(p).lower() for p in protos)
    tcp = any("tcp" in str(p).lower() for p in protos)
    mean_len = ep.get("mean_len")
    rate = ep.get("rate") or 0
    if ep.get("udp_steady") or (udp and mean_len and mean_len <= 400 and rate >= 10):
        # Real-time UDP: could be game or voice. Voice tends to be lower-rate.
        if rate >= 30:
            add(ROLE_GAME, 3, f"high-rate small-packet UDP ({rate:.0f} pkt/s) - real-time game traffic")
        else:
            add(ROLE_GAME, 2, "steady small-packet UDP - real-time session")
            add(ROLE_VOICE, 1, "steady small-packet UDP could also be voice")

    # 4) Large inbound download over TCP/TLS => CDN/content.
    inb = ep.get("in_bytes", 0)
    outb = ep.get("out_bytes", 0)
    if tcp and inb > 20 * 1024 * 1024 and inb > outb * 5:
        add(ROLE_CDN, 3, f"large inbound download ({_mb(inb)}) - content/update server")

    # 5) ASN / ISP hints.
    org = f"{ep.get('asn', '')} {ep.get('isp', '')}".lower()
    for hint, keys in _ASN_HINTS.items():
        if any(k in org for k in keys):
            if hint == "game":
                add(ROLE_GAME, 3, f"hosted on a game-server network ({ep.get('isp') or ep.get('asn')})")
            elif hint == "cdn":
                add(ROLE_CDN, 2, f"hosted on a CDN ({ep.get('isp') or ep.get('asn')})")
            elif hint == "voice":
                add(ROLE_VOICE, 3, f"hosted on a voice provider ({ep.get('isp') or ep.get('asn')})")
            elif hint == "cloud":
                add(ROLE_MATCH, 1, f"hosted on cloud infrastructure ({ep.get('isp') or ep.get('asn')})")

    # 6) TLS/HTTPS request-response to a publisher domain => platform/API.
    app_proto = str(ep.get("app_proto", "")).upper()
    if app_proto in ("TLS", "HTTPS", "HTTP", "QUIC") or 443 in _ports(ep):
        # Only a weak nudge unless a hostname keyword already pointed somewhere.
        if not scores:
            add(ROLE_WEB, 2, f"{app_proto or 'HTTPS'} to a web/API endpoint")
        else:
            add(ROLE_MATCH, 1, "encrypted request/response to a platform endpoint")

    # 7) Port tie-breakers (weak).
    for port in _ports(ep):
        role = _PORT_HINTS.get(port)
        if role:
            add(role, 1, f"port {port} is commonly {role.lower()}")

    if not scores:
        return {"role": ROLE_UNKNOWN, "confidence": 0,
                "reasons": ["no distinguishing signals yet - needs more traffic"]}

    role = max(scores, key=scores.get)
    top = scores[role]
    total = sum(scores.values())
    confidence = int(round(100 * top / total)) if total else 0
    # De-duplicate reasons while preserving order.
    seen = set()
    uniq = []
    for r in reasons[role]:
        if r not in seen:
            seen.add(r)
            uniq.append(r)
    return {"role": role, "confidence": confidence, "reasons": uniq}


def summarize_process(app, endpoints):
    """Given a process name and its classified endpoints, produce a short
    plain-language account of what the process is doing on the network."""
    if not endpoints:
        return [f"{app}: no external connections observed."]
    by_role = {}
    for ep in endpoints:
        by_role.setdefault(ep.get("role", ROLE_UNKNOWN), []).append(ep)
    lines = [f"{app} is connected to {len(endpoints)} endpoint(s):"]
    for role in (ROLE_GAME, ROLE_VOICE, ROLE_MATCH, ROLE_ANTICHEAT, ROLE_AUTH,
                 ROLE_CDN, ROLE_TELEMETRY, ROLE_WEB, ROLE_P2P, ROLE_UNKNOWN):
        group = by_role.get(role)
        if group:
            hosts = ", ".join((e.get("host") or e.get("ip", "?")) for e in group[:3])
            more = f" (+{len(group) - 3} more)" if len(group) > 3 else ""
            lines.append(f"  - {role}: {len(group)}  [{hosts}{more}]")
    return lines


# --- helpers ---------------------------------------------------------------

def _names(ep):
    out = []
    h = ep.get("host")
    if isinstance(h, (list, tuple, set)):
        out.extend(str(x) for x in h if x)
    elif h:
        out.append(str(h))
    for s in ep.get("sni") or []:
        if s:
            out.append(str(s))
    return out


def _flatten(seq):
    out = []
    for item in seq or []:
        if isinstance(item, (list, tuple)):
            out.append(item[0])
        else:
            out.append(item)
    return out


def _ports(ep):
    return [int(p) for p in _flatten(ep.get("ports")) if str(p).isdigit()]


def _mb(n):
    return f"{n / (1024 * 1024):.1f} MB"
