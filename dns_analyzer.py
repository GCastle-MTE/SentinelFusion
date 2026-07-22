"""DNS tunneling and DGA (domain-generation-algorithm) detection.

Fed by anomaly_detectors from live DNS packets, but kept scapy-free and stateful
so the heuristics are unit-testable.

Tunneling signature: a single parent domain receives many *distinct* subdomains
in a short window, and those subdomains are long and/or high-entropy (encoded
data smuggled in the query name).

DGA signature: a burst of NXDOMAIN answers for random-looking domains -- malware
cycling through generated domains hunting for its live C2.
"""

import math
import time
from collections import defaultdict, deque

import events

# --- tunneling thresholds ---
TUNNEL_WINDOW = 60.0
TUNNEL_MIN_SUBDOMAINS = 30     # distinct subdomains under one parent in the window
TUNNEL_MIN_AVGLEN = 20        # avg subdomain length (chars)
TUNNEL_MIN_ENTROPY = 3.2      # avg Shannon entropy (bits/char) of the subdomains

# --- DGA thresholds ---
DGA_WINDOW = 60.0
DGA_MIN_NXDOMAIN = 15        # distinct random-looking domains returning NXDOMAIN
DGA_ENTROPY = 2.8           # entropy of the leftmost label to call it "random"
DGA_MIN_LEN = 10

# Benign high-cardinality parents (CDNs / reverse DNS / telemetry) that legitimately
# generate many subdomains -- excluded from tunneling to cut false positives.
_ALLOW = (
    "in-addr.arpa", "ip6.arpa", "akamaiedge.net", "akamai.net", "akadns.net",
    "cloudfront.net", "googleusercontent.com", "1e100.net", "gvt1.com",
    "amazonaws.com", "azureedge.net", "windowsupdate.com", "cloudflare.net",
    "fastly.net", "edgekey.net", "edgesuite.net", "trafficmanager.net",
    "digicert.com", "root-servers.net",
)

_sub = defaultdict(deque)   # parent -> deque[(ts, subdomain)]
_nx = deque()               # deque[(ts, domain)] high-entropy NXDOMAIN answers
_tunnel_alerted = {}        # parent -> last alert ts
_dga_alerted_ts = 0.0


def reset():
    """Clear all state (used by tests)."""
    global _dga_alerted_ts
    _sub.clear()
    _nx.clear()
    _tunnel_alerted.clear()
    _dga_alerted_ts = 0.0


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _split(qname):
    """(parent, subdomain) using the last two labels as the parent domain."""
    q = qname.rstrip(".").lower()
    if not q or "." not in q:
        return q, ""
    labels = q.split(".")
    return ".".join(labels[-2:]), ".".join(labels[:-2])


def _allowed(qname):
    q = qname.rstrip(".").lower()
    return any(q == a or q.endswith("." + a) for a in _ALLOW)


def observe_query(qname, qtype=None):
    """Feed a DNS *query* name. May raise a tunneling alert."""
    if not qname:
        return
    parent, sub = _split(qname)
    if not sub or _allowed(qname):
        return
    now = time.time()
    dq = _sub[parent]
    dq.append((now, sub))
    cutoff = now - TUNNEL_WINDOW
    while dq and dq[0][0] < cutoff:
        dq.popleft()
    if not dq:
        _sub.pop(parent, None)
        return
    uniq = {s for _, s in dq}
    if len(uniq) < TUNNEL_MIN_SUBDOMAINS:
        return
    lens = [len(s) for s in uniq]
    ents = [_entropy(s.replace(".", "")) for s in uniq]
    avglen = sum(lens) / len(lens)
    avgent = sum(ents) / len(ents)
    if avglen >= TUNNEL_MIN_AVGLEN or avgent >= TUNNEL_MIN_ENTROPY:
        if now - _tunnel_alerted.get(parent, 0.0) > TUNNEL_WINDOW:
            _tunnel_alerted[parent] = now
            events.log_event(
                "ALERT", "tunnel", parent,
                f"Possible DNS tunneling: {len(uniq)} unique subdomains under "
                f"'{parent}' in <= {int(TUNNEL_WINDOW)}s "
                f"(avg len {avglen:.0f}, entropy {avgent:.1f})")


def observe_response(qname, is_nxdomain):
    """Feed a DNS *response*: qname + whether the answer was NXDOMAIN."""
    global _dga_alerted_ts
    if not (qname and is_nxdomain):
        return
    now = time.time()
    q = qname.rstrip(".").lower()
    label = q.split(".")[0] if q else ""
    if len(label) >= DGA_MIN_LEN and _entropy(label) >= DGA_ENTROPY:
        _nx.append((now, q))
    cutoff = now - DGA_WINDOW
    while _nx and _nx[0][0] < cutoff:
        _nx.popleft()
    distinct = {d for _, d in _nx}
    if len(distinct) >= DGA_MIN_NXDOMAIN and now - _dga_alerted_ts > DGA_WINDOW:
        _dga_alerted_ts = now
        events.log_event(
            "ALERT", "dga", "dns",
            f"Possible DGA activity: {len(distinct)} random-looking domains "
            f"returned NXDOMAIN in <= {int(DGA_WINDOW)}s (malware hunting for C2)")
