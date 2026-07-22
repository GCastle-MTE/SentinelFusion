"""External integration - hand incidents off to the wider security stack.

The architecture diagram's "Integration → SOAR platforms" arrow points outward:
SentinelFusion shouldn't be an island. This module pushes notifications and
evidence out to external systems - a Slack/Teams/generic webhook, or a SOAR/SIEM
HTTP endpoint - when a high-severity incident fires or an analyst chooses to
escalate.

It is deliberately one-directional and read-only with respect to your network. It
*sends* structured JSON (incident summary, ATT&CK techniques, IOCs, a link/ref to
the case) so an external platform can ticket, page, or run its own automation. It
never receives commands back, and it never performs containment - consistent with
the rest of SentinelFusion. If an external SOAR wants to block an IP, that happens
in the external SOAR, owned by whoever runs it.

Payload building is pure and testable. The actual HTTP POST uses `requests` if
present and is easy to stub; delivery is best-effort and never blocks the UI.
"""

import json
import time

# Registered outbound destinations: name -> {url, kind, min_severity, enabled}
_targets = {}

_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "INFO": 0, "HIGH": 2, "WARNING": 1,
             "CRITICAL": 3, "ALERT": 2}


def add_target(name, url, kind="generic", min_severity="HIGH", enabled=True):
    """Register an outbound destination.

    kind: 'slack' / 'teams' / 'generic' (bare JSON) / 'siem'. min_severity gates
    which incidents auto-notify. URLs are stored as given (typically a secret
    webhook URL the operator pastes in Settings).
    """
    _targets[name] = {"url": url, "kind": kind,
                      "min_severity": min_severity, "enabled": bool(enabled)}
    return _targets[name]


def remove_target(name):
    _targets.pop(name, None)


def targets():
    return {k: dict(v) for k, v in _targets.items()}


def build_payload(incident, *, kind="generic", techniques=None, iocs=None,
                  case_id=None, note=None):
    """Build the outbound payload for one incident. Returns a dict ready to POST.

    For slack/teams the dict is their message shape; for generic/siem it's a flat
    structured record.
    """
    actor = incident.get("actor", "")
    level = incident.get("level", "")
    score = incident.get("score", "")
    pattern = incident.get("pattern", "") or "correlated incident"
    tech_ids = [t["id"] for t in (techniques or [])]

    if kind in ("slack", "teams"):
        title = f"SentinelFusion: {level} incident - {actor}"
        body = (f"*{pattern}*\n"
                f"Actor: {actor}   Score: {score}\n"
                f"ATT&CK: {', '.join(tech_ids) or 'n/a'}")
        if case_id:
            body += f"\nCase #{case_id}"
        if note:
            body += f"\n{note}"
        if kind == "slack":
            return {"text": f"{title}\n{body}"}
        # teams simple card
        return {"title": title, "text": body.replace("\n", "  \n")}

    # generic / siem: flat structured record
    payload = {
        "source": "SentinelFusion",
        "type": "incident",
        "severity": level,
        "actor": actor,
        "score": score,
        "pattern": pattern,
        "attack_techniques": tech_ids,
        "iocs": iocs or {},
        "case_id": case_id,
        "note": note,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    return payload


def should_notify(incident, target):
    """Does this incident meet a target's severity gate?"""
    lvl = incident.get("level", "")
    return _rank(lvl) >= _rank(target.get("min_severity", "HIGH"))


def send(target_name, payload, *, http=None):
    """POST a payload to a registered target. `http` defaults to `requests`.

    Returns {ok, status, error}. Best-effort - never raises.
    """
    target = _targets.get(target_name)
    if not target:
        return {"ok": False, "status": None, "error": "unknown target"}
    if not target.get("enabled"):
        return {"ok": False, "status": None, "error": "target disabled"}
    if http is None:
        try:
            import requests as http
        except Exception:
            return {"ok": False, "status": None, "error": "requests not available"}
    try:
        resp = http.post(target["url"], json=payload, timeout=6)
        code = getattr(resp, "status_code", None)
        return {"ok": bool(code and 200 <= code < 300), "status": code, "error": None}
    except Exception as exc:
        return {"ok": False, "status": None, "error": str(exc)}


def notify_incident(incident, *, techniques=None, iocs=None, case_id=None,
                    note=None, http=None):
    """Send an incident to every enabled target whose severity gate it meets.
    Returns a per-target result dict. Used both for auto-notify and manual escalate.
    """
    results = {}
    for name, target in _targets.items():
        if not target.get("enabled"):
            continue
        if not should_notify(incident, target):
            results[name] = {"ok": False, "status": None, "error": "below severity gate"}
            continue
        payload = build_payload(incident, kind=target.get("kind", "generic"),
                                techniques=techniques, iocs=iocs,
                                case_id=case_id, note=note)
        results[name] = send(name, payload, http=http)
    return results


def test_target(target_name, *, http=None):
    """Send a harmless test payload so an operator can confirm a webhook works."""
    payload = {"source": "SentinelFusion", "type": "test",
               "message": "SentinelFusion integration test - if you can read this, "
                          "delivery works.",
               "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}
    target = _targets.get(target_name)
    if target and target.get("kind") in ("slack", "teams"):
        payload = {"text": payload["message"]}
    return send(target_name, payload, http=http)


def snapshot():
    """Targets for config export (URLs included - treat the config as a secret)."""
    return {"targets": {k: dict(v) for k, v in _targets.items()}}


def restore(state):
    if not isinstance(state, dict):
        return
    for name, t in (state.get("targets") or {}).items():
        if isinstance(t, dict) and t.get("url"):
            add_target(name, t["url"], t.get("kind", "generic"),
                       t.get("min_severity", "HIGH"), t.get("enabled", True))


def _rank(sev):
    return _SEV_RANK.get(str(sev).upper(), 0)


def _dumps(payload):
    return json.dumps(payload, indent=2)
