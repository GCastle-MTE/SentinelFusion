"""MITRE ATT&CK mapping - speak the language of the field.

Every SentinelFusion detector fires on behaviour that corresponds to one or more
MITRE ATT&CK techniques. This module maps our internal event categories to real
ATT&CK technique IDs, names, and tactics, so incidents, cases, and reports can be
described the way every SOC analyst, SIEM, and threat report describes them - by
technique ID. An incident that cites T1071 (Application Layer Protocol) and
T1041 (Exfiltration Over C2 Channel) is instantly legible to anyone in the field.

We map to the network-observable techniques our sensors can actually justify -
we don't over-claim. A category can map to several techniques; an incident's
technique set is the union across its detector categories.

Pure data + lookups, no dependencies, fully testable. Reference:
https://attack.mitre.org/ (technique IDs are stable identifiers).
"""

# Tactic order roughly follows the ATT&CK kill chain, for sorting/report layout.
TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# category -> list of technique dicts {id, name, tactic}
CATEGORY_TECHNIQUES = {
    "scan": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks",
         "tactic": "Reconnaissance"},
    ],
    "sweep": [
        {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
        {"id": "T1595.001", "name": "Active Scanning: Scanning IP Blocks",
         "tactic": "Reconnaissance"},
    ],
    "service": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "device": [
        {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
    ],
    "arp": [
        {"id": "T1557.002", "name": "Adversary-in-the-Middle: ARP Cache Poisoning",
         "tactic": "Credential Access"},
    ],
    "rogue": [
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    ],
    "creds": [
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    ],
    "ja3": [
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
         "tactic": "Command and Control"},
    ],
    "cert": [
        {"id": "T1587.003", "name": "Develop Capabilities: Digital Certificates",
         "tactic": "Resource Development"},
        {"id": "T1573", "name": "Encrypted Channel", "tactic": "Command and Control"},
    ],
    "protocol": [
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    "tunnel": [
        {"id": "T1572", "name": "Protocol Tunneling", "tactic": "Command and Control"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
         "tactic": "Exfiltration"},
    ],
    "dns": [
        {"id": "T1071.004", "name": "Application Layer Protocol: DNS",
         "tactic": "Command and Control"},
    ],
    "dga": [
        {"id": "T1568.002", "name": "Dynamic Resolution: Domain Generation Algorithms",
         "tactic": "Command and Control"},
    ],
    "beacon": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
        {"id": "T1571", "name": "Non-Standard Port", "tactic": "Command and Control"},
    ],
    "intel": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "watch": [
        {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    ],
    "http": [
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
         "tactic": "Command and Control"},
    ],
    "exfil": [
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol",
         "tactic": "Exfiltration"},
    ],
    "flood": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
    ],
    "wifi": [
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        {"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    ],
}


def techniques_for_category(category):
    """Return the technique dicts for one detector category (possibly empty)."""
    return list(CATEGORY_TECHNIQUES.get(category, []))


def techniques_for_categories(categories):
    """Union of techniques across several categories, de-duplicated by id and
    ordered by tactic. `categories` may be a list or a dict (keys used)."""
    if isinstance(categories, dict):
        categories = list(categories.keys())
    seen = {}
    for cat in categories or []:
        for t in CATEGORY_TECHNIQUES.get(cat, []):
            seen[t["id"]] = t
    return sorted(seen.values(), key=lambda t: (_tactic_rank(t["tactic"]), t["id"]))


def techniques_for_incident(incident):
    """Convenience: technique set for a correlation incident snapshot."""
    return techniques_for_categories(incident.get("categories", {}))


def tactics_for_incident(incident):
    """Ordered list of distinct ATT&CK tactics an incident touches."""
    techs = techniques_for_incident(incident)
    seen = []
    for t in techs:
        if t["tactic"] not in seen:
            seen.append(t["tactic"])
    return sorted(seen, key=_tactic_rank)


def describe(technique):
    return f"{technique['id']} {technique['name']} ({technique['tactic']})"


def summary_line(incident):
    """A compact 'ATT&CK: T1046, T1071, T1041' line for an incident."""
    techs = techniques_for_incident(incident)
    if not techs:
        return "ATT&CK: (no mapped techniques)"
    return "ATT&CK: " + ", ".join(t["id"] for t in techs)


def coverage():
    """Every technique this tool can observe, grouped by tactic - for a coverage
    view / report appendix."""
    by_tactic = {}
    for cat, techs in CATEGORY_TECHNIQUES.items():
        for t in techs:
            by_tactic.setdefault(t["tactic"], {})[t["id"]] = t["name"]
    out = []
    for tactic in sorted(by_tactic, key=_tactic_rank):
        items = sorted(by_tactic[tactic].items())
        out.append({"tactic": tactic,
                    "techniques": [{"id": i, "name": n} for i, n in items]})
    return out


def _tactic_rank(tactic):
    try:
        return TACTICS.index(tactic)
    except ValueError:
        return len(TACTICS)
