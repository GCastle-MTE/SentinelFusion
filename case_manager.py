"""SOAR case management - work an incident from open to closed.

The correlation engine produces scored incidents; this turns one into a *case*
that a human works: it has a status (new -> investigating -> contained ->
closed), an assignee, a running timeline of notes, and a list of recommended
actions the analyst can apply. Everything persists to the shared incidents.db so
the record survives restarts - the "document every incident as a case" principle
from SOAR practice.

This layer is deliberately investigative only. It records and recommends; it
never executes a containment action itself. A recommended action is text for a
human to act on (e.g. "block 45.13.66.7 at the perimeter"), never an automated
firewall change.

db_manager is injected so this stays testable without a real database.
"""

import json
import time

STATUSES = ("new", "investigating", "contained", "closed")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def open_case(incident, *, db, title=None, assignee=""):
    """Create a case from a correlation incident snapshot (dict). If a case for
    this incident already exists, returns it instead of duplicating. Returns the
    case row (dict) or None."""
    inc_id = incident.get("id")
    existing = db.case_for_incident(inc_id) if inc_id is not None else None
    if existing:
        return existing

    actor = incident.get("actor", "")
    level = incident.get("level", "")
    title = title or f"{level or 'Incident'} - {actor or 'unknown actor'}"
    summary = incident.get("pattern", "") or "Correlated incident"
    # ATT&CK techniques for this incident, folded into the summary for reports.
    try:
        import mitre_attack
        techs = mitre_attack.techniques_for_incident(incident)
        if techs:
            summary = f"{summary}   [ATT&CK: {', '.join(t['id'] for t in techs)}]"
    except Exception:
        pass
    now = _now()
    row = {
        "title": title, "actor": actor, "severity": level,
        "status": "new", "assignee": assignee,
        "score": str(incident.get("score", "")), "summary": summary,
        "notes": json.dumps([{"ts": now, "text": "Case opened from incident."}]),
        "actions": json.dumps(recommend_actions(incident)),
        "incident_id": str(inc_id) if inc_id is not None else "",
        "created_at": now, "updated_at": now,
    }
    case_id = db.insert_case(row)
    if case_id is None:
        return None
    return db.get_case(case_id)


def set_status(case_id, status, *, db):
    if status not in STATUSES:
        return False
    ok = db.update_case(case_id, status=status, updated_at=_now())
    if ok:
        add_note(case_id, f"Status changed to '{status}'.", db=db)
    return ok


def assign(case_id, assignee, *, db):
    return db.update_case(case_id, assignee=assignee, updated_at=_now())


def add_note(case_id, text, *, db):
    """Append a timestamped note to the case timeline."""
    case = db.get_case(case_id)
    if not case:
        return False
    try:
        notes = json.loads(case.get("notes") or "[]")
    except Exception:
        notes = []
    notes.append({"ts": _now(), "text": text})
    return db.update_case(case_id, notes=json.dumps(notes), updated_at=_now())


def notes(case):
    try:
        return json.loads(case.get("notes") or "[]")
    except Exception:
        return []


def actions(case):
    try:
        return json.loads(case.get("actions") or "[]")
    except Exception:
        return []


def set_actions(case_id, action_list, *, db):
    return db.update_case(case_id, actions=json.dumps(action_list), updated_at=_now())


def recommend_actions(incident):
    """Turn an incident into a list of *recommended* analyst actions.

    These are suggestions a human reviews and applies - never auto-executed.
    Each is {action, detail, applied:false}.
    """
    actor = incident.get("actor", "")
    level = incident.get("level", "")
    cats = incident.get("categories", {}) or {}
    stages = incident.get("stages", []) or []
    recs = []

    def add(action, detail):
        recs.append({"action": action, "detail": detail, "applied": False})

    # Always worth doing on a real incident.
    add("Enrich actor", f"Pull the full profile for {actor} (geo, ASN, reputation, "
                        "flows, resolution chain).")
    add("Capture evidence", f"Export a PCAP of traffic involving {actor} for the record.")

    if level in ("HIGH", "CRITICAL"):
        add("Add to watchlist", f"Flag {actor} so any further contact is highlighted.")
        add("Consider perimeter block",
            f"Review whether {actor} should be blocked at the firewall / router. "
            "(Analyst decision - not applied automatically.)")

    if "exfil" in cats:
        add("Check data egress", f"Inspect what left the network toward {actor}; "
                                 "confirm whether sensitive data was involved.")
    if "beacon" in cats or "dga" in cats:
        add("Hunt for C2 on other hosts", "Search history for the same pattern from "
                                          "other internal hosts (possible spread).")
    if "creds" in cats:
        add("Rotate exposed credentials", "Credentials were seen in cleartext - "
                                          "rotate anything that may have been exposed.")
    if "scan" in cats or "sweep" in cats:
        add("Review exposed services", "A scan touched this host - confirm which "
                                       "ports/services are actually meant to be open.")
    if any(s in ("c2", "exfil", "impact") for s in stages):
        add("Escalate", f"This reached the '{stages[-1] if stages else '?'}' stage - "
                        "consider escalating to a human incident responder.")
    return recs


def summarize(case):
    """Plain-language lines for a case detail panel."""
    if not case:
        return ["No case."]
    lines = [
        f"CASE #{case['id']}  [{case.get('status', '?').upper()}]",
        case.get("title", ""),
        f"Actor: {case.get('actor', '?')}    Severity: {case.get('severity', '?')}"
        f"    Score: {case.get('score', '?')}",
    ]
    if case.get("assignee"):
        lines.append(f"Assignee: {case['assignee']}")
    lines.append(f"Opened: {case.get('created_at', '?')}   Updated: {case.get('updated_at', '?')}")
    lines.append("")
    lines.append(f"Summary: {case.get('summary', '')}")

    acts = actions(case)
    if acts:
        lines.append("")
        lines.append("RECOMMENDED ACTIONS (analyst applies):")
        for a in acts:
            mark = "[x]" if a.get("applied") else "[ ]"
            lines.append(f"  {mark} {a['action']} - {a['detail']}")

    ns = notes(case)
    if ns:
        lines.append("")
        lines.append("TIMELINE:")
        for n in ns[-12:]:
            lines.append(f"  {n['ts']}  {n['text']}")
    return lines


def stats(*, db):
    rows = db.get_cases()
    by_status = {s: 0 for s in STATUSES}
    for r in rows:
        by_status[r.get("status", "new")] = by_status.get(r.get("status", "new"), 0) + 1
    return {"total": len(rows), "by_status": by_status,
            "open": sum(v for k, v in by_status.items() if k != "closed")}
