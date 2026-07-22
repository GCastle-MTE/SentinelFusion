"""Passive OS fingerprinting - guess a host's OS without touching it.

Every TCP SYN carries accidental tells about the sender's stack: the initial TTL
(each OS family starts it at a characteristic value), the TCP window size, and
the order and presence of TCP options (MSS, window scale, SACK, timestamps).
Together these form a fingerprint - the same idea as p0f. We never send a probe;
we just read what's already on the wire.

This is deliberately conservative: it reports a *family* with a confidence, and
says "unknown" rather than guess wildly. A host whose fingerprint doesn't match
what it claims elsewhere (e.g. a "printer" that fingerprints as Linux) is exactly
the kind of thing a defender wants surfaced.

Pure functions over plain values, so it's testable without scapy.
"""

# Initial TTL by OS family. Observed TTL is <= initial (decremented per hop).
_TTL_BASES = [(64, "Linux/Unix/macOS"), (128, "Windows"), (255, "Network device")]

# Common (initial_TTL, window) signatures. Windows favour specific windows;
# Linux commonly 5840/29200/64240; macOS 65535. These are hints, not gospel.
_WINDOW_HINTS = {
    8192: "Windows (Vista/7 era)",
    64240: "Linux (recent)",
    65535: "macOS / BSD",
    29200: "Linux",
    5840: "Linux (older)",
    16384: "Windows / BSD",
    4128: "Network device / embedded",
}


def _initial_ttl(ttl):
    """Return (base, hops, family) for an observed TTL, or None."""
    try:
        ttl = int(ttl)
    except Exception:
        return None
    for base, family in _TTL_BASES:
        if 0 < ttl <= base and base - ttl <= 32:
            return base, base - ttl, family
    if ttl > 128:
        return 255, 255 - ttl, "Network device"
    return None


def fingerprint(ttl=None, window=None, options=None, df=None):
    """Guess an OS from passive TCP SYN features.

    ttl:     observed IP TTL (int)
    window:  TCP window size (int)
    options: list of option names in order, e.g. ["MSS","SACK","TS","NOP","WS"]
    df:      whether the Don't-Fragment bit is set (bool) - modern stacks set it

    Returns {"os","family","confidence","hops","detail"}.
    """
    options = options or []
    score = {}          # family -> weight

    ttl_info = _initial_ttl(ttl) if ttl is not None else None
    hops = None
    if ttl_info:
        base, hops, family = ttl_info
        score[family] = score.get(family, 0) + 3

    if window in _WINDOW_HINTS:
        wfam = _WINDOW_HINTS[window]
        base_fam = _base_family(wfam)
        score[base_fam] = score.get(base_fam, 0) + 2

    # Option ordering tells families apart. Windows: MSS,NOP,WS,NOP,NOP,SACK.
    # Linux: MSS,SACK,TS,NOP,WS. macOS: MSS,NOP,WS,NOP,NOP,TS,SACK,EOL.
    opt_sig = ",".join(options)
    if opt_sig:
        if opt_sig.startswith("MSS,SACK,TS") or "TS,NOP,WS" in opt_sig:
            score["Linux/Unix/macOS"] = score.get("Linux/Unix/macOS", 0) + 2
        if opt_sig.startswith("MSS,NOP,WS,NOP,NOP,SACK"):
            score["Windows"] = score.get("Windows", 0) + 2
        if "TS" not in options and opt_sig.startswith("MSS,NOP,WS"):
            score["Windows"] = score.get("Windows", 0) + 1

    if not score:
        return {"os": "unknown", "family": "", "confidence": 0,
                "hops": hops, "detail": "no usable TCP fingerprint"}

    # Merge overlapping labels into coarse families for a clean verdict.
    family = max(score, key=score.get)
    top = score[family]
    total = sum(score.values())
    confidence = int(round(100 * top / total)) if total else 0

    detail_bits = []
    if ttl_info:
        detail_bits.append(f"TTL~{ttl_info[0]} ({ttl_info[1]} hops)")
    if window is not None:
        detail_bits.append(f"win {window}")
    if options:
        detail_bits.append("opts " + "/".join(options))

    return {"os": _pretty(family), "family": family, "confidence": confidence,
            "hops": hops, "detail": ", ".join(detail_bits)}


def _base_family(label):
    low = label.lower()
    if "windows" in low:
        return "Windows"
    if "network" in low or "embedded" in low:
        return "Network device"
    return "Linux/Unix/macOS"


def _pretty(family):
    return family


def describe(fp):
    """One-line human summary of a fingerprint result."""
    if not fp or fp.get("os") == "unknown":
        return "OS: unknown (no clear TCP fingerprint)"
    conf = fp.get("confidence", 0)
    hops = fp.get("hops")
    hop_txt = f", ~{hops} hops away" if hops is not None else ""
    return f"OS: {fp['os']} ({conf}% confidence{hop_txt})"
