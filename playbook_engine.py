"""SOAR playbook engine - automate the routine investigation steps.

When an incident fires, an analyst does the same first things every time: pull the
actor's full profile, snapshot the evidence, check the resolution chain, open a
case, tag it. That's routine, tedious, and time-consuming - the three tests the
SOAR literature says mean "automate this". This engine runs those steps
automatically and records what it did.

Crucially, every built-in action is investigative or evidence-gathering. The
engine gathers, correlates, opens cases, and *recommends* containment - it never
executes a containment action (no firewall changes, no killing processes). That
keeps the automation a force-multiplier for the analyst without handing it
control of the network.

A playbook is: a name, a trigger (a predicate over an incident), and an ordered
list of action names. Actions are resolved from an injected `registry` of
callables so the engine has no hard dependency on the rest of the app and stays
testable. Each run yields a step-by-step record persisted via db_manager.
"""

import time


# --- built-in triggers (predicates over an incident snapshot) --------------

def trigger_critical(inc):
    return inc.get("level") in ("HIGH", "CRITICAL")


def trigger_exfil(inc):
    return "exfil" in (inc.get("categories") or {})


def trigger_c2(inc):
    cats = inc.get("categories") or {}
    return any(k in cats for k in ("beacon", "dga")) or "c2" in (inc.get("stages") or [])


def trigger_creds(inc):
    return "creds" in (inc.get("categories") or {})


def trigger_any(inc):
    return True


_TRIGGERS = {
    "critical_or_high": trigger_critical,
    "data_exfil": trigger_exfil,
    "c2_activity": trigger_c2,
    "credential_exposure": trigger_creds,
    "any_incident": trigger_any,
}


# Default playbooks. Action names are resolved against the registry at run time;
# unknown actions are skipped with a recorded note rather than crashing.
DEFAULT_PLAYBOOKS = [
    {
        "name": "Triage new incident",
        "trigger": "any_incident",
        "actions": ["enrich_actor", "resolution_chain", "open_case", "tag_stage"],
        "enabled": True,
    },
    {
        "name": "Critical response",
        "trigger": "critical_or_high",
        "actions": ["enrich_actor", "capture_evidence", "add_watchlist",
                    "open_case", "recommend_actions", "escalate_note"],
        "enabled": True,
    },
    {
        "name": "Suspected C2",
        "trigger": "c2_activity",
        "actions": ["enrich_actor", "resolution_chain", "hunt_similar", "open_case"],
        "enabled": True,
    },
    {
        "name": "Data exfiltration",
        "trigger": "data_exfil",
        "actions": ["enrich_actor", "capture_evidence", "open_case",
                    "recommend_actions", "escalate_note"],
        "enabled": True,
    },
]


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def matching_playbooks(incident, playbooks=None):
    """Return the playbooks whose trigger fires for this incident."""
    pbs = playbooks if playbooks is not None else DEFAULT_PLAYBOOKS
    out = []
    for pb in pbs:
        if not pb.get("enabled", True):
            continue
        trig = _TRIGGERS.get(pb.get("trigger"), trigger_any)
        try:
            if trig(incident):
                out.append(pb)
        except Exception:
            pass
    return out


def run_playbook(playbook, incident, *, registry, db=None):
    """Execute a playbook's actions against an incident.

    `registry` maps action name -> callable(incident, context) -> str result.
    `context` is a shared dict actions can read/write (e.g. an opened case id).
    Returns a run record dict; also persists it via db.insert_playbook_run if db
    is given. Never raises - a failing action is recorded and the run continues.
    """
    context = {"incident": incident}
    steps = []
    for action in playbook.get("actions", []):
        fn = registry.get(action)
        started = _now()
        if fn is None:
            steps.append({"action": action, "result": "skipped (no handler)",
                          "ok": False, "ts": started})
            continue
        try:
            result = fn(incident, context)
            steps.append({"action": action, "result": str(result),
                          "ok": True, "ts": started})
        except Exception as exc:
            steps.append({"action": action, "result": f"error: {exc}",
                          "ok": False, "ts": started})

    record = {
        "playbook": playbook.get("name", "?"),
        "trigger": playbook.get("trigger", "?"),
        "actor": incident.get("actor", ""),
        "case_id": str(context.get("case_id", "")),
        "steps": steps,
        "ran_at": _now(),
    }
    if db is not None:
        try:
            import json
            db.insert_playbook_run({
                "playbook": record["playbook"], "trigger": record["trigger"],
                "actor": record["actor"], "case_id": record["case_id"],
                "steps": json.dumps(steps), "ran_at": record["ran_at"],
            })
        except Exception:
            pass
    return record


def run_for_incident(incident, *, registry, db=None, playbooks=None):
    """Run every matching playbook for an incident. Returns list of run records."""
    return [run_playbook(pb, incident, registry=registry, db=db)
            for pb in matching_playbooks(incident, playbooks)]


def summarize_run(record):
    """Plain-language lines describing a playbook run."""
    lines = [f"{record['ran_at']}  -  {record['playbook']} "
             f"(trigger: {record['trigger']}, actor: {record['actor']})"]
    for s in record.get("steps", []):
        mark = "OK " if s.get("ok") else "!! "
        lines.append(f"   {mark}{s['action']}: {s['result']}")
    return lines
