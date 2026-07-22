"""Follow TCP stream - reassemble a single TCP conversation from captured packets.

The scapy-specific bit (pulling fields off a packet) is isolated in ``extract``
so the reassembly logic in ``follow_records`` is plain-Python and unit-testable
without a live capture.

Reassembly is pragmatic, tuned for the short focused captures the Inspection
tab produces: payload-bearing segments are taken in capture order, exact
retransmissions (same seq+length, per direction) are dropped, and consecutive
same-direction segments are merged into one chunk.  It does not re-sort by
sequence number or stitch partial/overlapping retransmissions, which is fine
for typical request/response flows but worth knowing for pathological captures.
"""

try:
    from scapy.all import IP, IPv6, TCP, Raw
    _SCAPY = True
except Exception:                       # pragma: no cover - sandbox without scapy
    IP = IPv6 = TCP = Raw = None
    _SCAPY = False

SYN = 0x02
ACK = 0x10


def _l3(pkt):
    if IP is not None and IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 is not None and IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


def extract(pkt):
    """Pull the fields we need off a scapy packet, or None if it isn't TCP."""
    if TCP is None or TCP not in pkt:
        return None
    src, dst = _l3(pkt)
    if src is None:
        return None
    t = pkt[TCP]
    payload = bytes(pkt[Raw].load) if (Raw is not None and Raw in pkt) else b""
    return {"src": src, "sport": int(t.sport), "dst": dst, "dport": int(t.dport),
            "flags": int(t.flags), "seq": int(t.seq), "payload": payload}


def _key(r):
    return frozenset(((r["src"], r["sport"]), (r["dst"], r["dport"])))


def follow_records(records, anchor):
    """Reassemble the conversation `anchor` belongs to, from `records`.

    Returns a dict (client, server, chunks, bytes_c2s, bytes_s2c, packets) or
    None.  `chunks` is a time-ordered list of (direction, bytes) where direction
    is 'c2s' (client->server) or 's2c'.
    """
    if not anchor:
        return None
    key = _key(anchor)
    convo = [r for r in records if r and _key(r) == key]
    if not convo:
        return None

    # Client = the side that sent a SYN without ACK; otherwise the first talker.
    client = None
    for r in convo:
        if (r["flags"] & SYN) and not (r["flags"] & ACK):
            client = (r["src"], r["sport"])
            break
    if client is None:
        client = (convo[0]["src"], convo[0]["sport"])
    server = next((ep for ep in key if ep != client), client)

    chunks = []
    seen = {"c2s": set(), "s2c": set()}
    nbytes = {"c2s": 0, "s2c": 0}
    for r in convo:
        raw = r["payload"]
        if not raw:
            continue
        direction = "c2s" if (r["src"], r["sport"]) == client else "s2c"
        sig = (r["seq"], len(raw))
        if sig in seen[direction]:
            continue                      # exact retransmission
        seen[direction].add(sig)
        nbytes[direction] += len(raw)
        if chunks and chunks[-1][0] == direction:
            chunks[-1] = (direction, chunks[-1][1] + raw)
        else:
            chunks.append((direction, raw))

    return {"client": client, "server": server, "chunks": chunks,
            "bytes_c2s": nbytes["c2s"], "bytes_s2c": nbytes["s2c"],
            "packets": len(convo)}


def follow(packets, anchor):
    """Convenience wrapper: reassemble the conversation of `anchor` from `packets`."""
    a = extract(anchor)
    if a is None:
        return None
    recs = [extract(p) for p in packets]
    return follow_records(recs, a)


# ---- rendering helpers ----

def to_text(data):
    """Bytes -> printable string, non-printables shown as '.' (keeps tab/newline)."""
    return "".join(
        chr(b) if (32 <= b < 127 or b in (9, 10, 13)) else "." for b in data
    )


def hexdump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexs:<{width * 3}}  {asc}")
    return "\n".join(lines)
