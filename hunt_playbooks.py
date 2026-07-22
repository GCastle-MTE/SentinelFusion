"""Threat-hunting playbooks - structured procedures that guide a hunt.

These are different from the SOAR response playbooks (playbook_engine.py). Those
run automatically and take investigative actions on one incident. These are
*guided procedures* a human analyst follows proactively: a hypothesis, the steps
to test it, what each step queries against SentinelFusion's own data, and what a
finding looks like. Think of them as the runbook a hunter opens when they ask
"is there C2 I haven't caught yet?" and want a repeatable method rather than
poking around.

Each step can be linked to a live query - a call into the app's existing search
(retro-hunt over stored events, flow/DNS lookups, enrichment) - so a step isn't
just prose, it can actually pull the data. The catalog here is the content; the
`run_step` helper executes a step's query when the UI asks. No heavy deps.
"""


# A playbook: id, name, hypothesis, ATT&CK tactics it hunts, and ordered steps.
# Each step: {title, look_for, query} where query is a (kind, args) the app can
# execute, or None for a manual/observational step.
PLAYBOOKS = [
    {
        "id": "beaconing_c2",
        "name": "Hunt: undetected C2 beaconing",
        "hypothesis": "A host is beaconing to a command-and-control server on an "
                      "interval that slipped under the automatic threshold.",
        "tactics": ["Command and Control"],
        "steps": [
            {"title": "List endpoints contacted at regular intervals",
             "look_for": "Any external IP with evenly-spaced connections, even if "
                         "below the alert threshold. Low jitter between connections "
                         "is the tell.",
             "query": ("search_events", {"category": "beacon"})},
            {"title": "Check for IP-literal destinations (no DNS)",
             "look_for": "Connections to raw IPs with no preceding DNS lookup - "
                         "hard-coded C2 addresses avoid name resolution.",
             "query": ("dns_chainless", {})},
            {"title": "Review new external infrastructure this session",
             "look_for": "Freshly-seen IPs/ASNs. New infrastructure appearing mid-"
                         "session that you're now beaconing to is suspicious.",
             "query": ("novelty_new", {"kind": "ip"})},
            {"title": "Enrich the top candidates",
             "look_for": "Reputation hits, hosting on a bulletproof/obscure ASN, or "
                         "a JARM/JA3 fingerprint matching known tooling.",
             "query": None},
        ],
    },
    {
        "id": "data_exfil",
        "name": "Hunt: slow data exfiltration",
        "hypothesis": "Data is leaving the network in small amounts over time to "
                      "stay under the volume threshold.",
        "tactics": ["Exfiltration"],
        "steps": [
            {"title": "Find flows with a heavy outbound imbalance",
             "look_for": "Sessions where far more data went out than came in - the "
                         "shape of an upload, regardless of total size.",
             "query": ("flows_outbound_heavy", {})},
            {"title": "Check DNS and ICMP volume per host",
             "look_for": "Unusually high DNS query volume or large/frequent ICMP - "
                         "classic covert channels for tunnelling data out.",
             "query": ("search_events", {"category": "tunnel"})},
            {"title": "Rank endpoints by ML anomaly score",
             "look_for": "Endpoints the model flags for an unusual outbound/inbound "
                         "ratio or volume, with the reasons it gives.",
             "query": ("ml_rank", {})},
            {"title": "Correlate against known cloud storage / paste sites",
             "look_for": "Destinations that are file-sharing, paste, or personal "
                         "cloud services not normally used by this host.",
             "query": None},
        ],
    },
    {
        "id": "lateral_movement",
        "name": "Hunt: internal reconnaissance / lateral movement",
        "hypothesis": "A compromised host is scanning or probing other internal "
                      "hosts to move laterally.",
        "tactics": ["Discovery", "Lateral Movement"],
        "steps": [
            {"title": "Look for internal-to-internal scanning",
             "look_for": "A LAN host connecting to many other LAN hosts or ports - "
                         "internal recon, not normal client behaviour.",
             "query": ("search_events", {"category": "scan"})},
            {"title": "Check for new SMB/RDP/WinRM connections",
             "look_for": "Admin-protocol connections between workstations that don't "
                         "usually talk - a hallmark of lateral movement.",
             "query": ("search_events", {"category": "service"})},
            {"title": "Review device inventory for new/unexpected hosts",
             "look_for": "Devices that appeared recently, or hosts exposing services "
                         "they didn't before.",
             "query": ("novelty_new", {"kind": "ip"})},
        ],
    },
    {
        "id": "suspicious_dns",
        "name": "Hunt: malicious DNS activity",
        "hypothesis": "Malware is using DNS for C2 or exfiltration via algorithmic "
                      "domains or tunnelling.",
        "tactics": ["Command and Control", "Exfiltration"],
        "steps": [
            {"title": "Review DGA-style domains",
             "look_for": "Runs of high-entropy domains that mostly fail to resolve - "
                         "a domain-generation algorithm cycling through candidates.",
             "query": ("search_events", {"category": "dga"})},
            {"title": "Check for DNS tunnelling",
             "look_for": "Many long, high-entropy subdomains under one parent domain "
                         "- data encoded into DNS queries.",
             "query": ("search_events", {"category": "tunnel"})},
            {"title": "Find domains resolved but never connected to",
             "look_for": "Lookups with no following traffic can be beacon check-ins "
                         "or staging; the reverse (traffic with no lookup) is also odd.",
             "query": None},
        ],
    },
]


def playbooks():
    """The hunt catalog (without executing anything)."""
    return [dict(p) for p in PLAYBOOKS]


def get(playbook_id):
    return next((dict(p) for p in PLAYBOOKS if p["id"] == playbook_id), None)


def run_step(step, *, registry):
    """Execute a step's linked query via the injected registry of callables.

    `registry` maps a query kind -> callable(**args) -> result (usually a list of
    rows or a summary string). Returns {ran, result, error}. A step with no query
    is a manual/observational step and returns ran=False.
    """
    q = step.get("query")
    if not q:
        return {"ran": False, "result": None, "error": None}
    kind, args = q
    fn = registry.get(kind)
    if fn is None:
        return {"ran": False, "result": None, "error": f"no handler for '{kind}'"}
    try:
        return {"ran": True, "result": fn(**(args or {})), "error": None}
    except Exception as exc:
        return {"ran": True, "result": None, "error": str(exc)}


def summarize(playbook):
    """Plain-text rendering of a playbook for display/print."""
    if not playbook:
        return ["No playbook."]
    lines = [playbook["name"], "",
             f"Hypothesis: {playbook['hypothesis']}",
             f"ATT&CK tactics: {', '.join(playbook.get('tactics', []))}", "",
             "Steps:"]
    for i, s in enumerate(playbook.get("steps", []), 1):
        lines.append(f"  {i}. {s['title']}")
        lines.append(f"     Look for: {s['look_for']}")
        if s.get("query"):
            lines.append(f"     (linked query: {s['query'][0]})")
    return lines
