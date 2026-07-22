"""Log ingestion - the left-most block of the architecture: aggregate external logs.

Everything else in SentinelFusion is driven by live packet capture. This module
adds the other classic SOC input: logs from the things around you - firewalls,
servers, network devices, the local OS. It accepts three shapes of input and
normalizes them into one record type the rest of the app already understands:

  * syslog (RFC 3164 "BSD" and RFC 5424) - what network gear and Unix hosts emit
  * Windows Event Log entries - security/system/application channels
  * generic lines - JSON objects or key=value / plain text, for app logs

A normalized record is {ts, host, source, severity, facility, category, message,
raw, fields}. Parsing and normalization are pure and fully testable here; the
actual listeners (a UDP syslog socket, the Windows Event Log reader) are thin
wrappers in `sources` that call into this and are exercised on a real machine.

Security-relevant lines (auth failures, firewall denies, account lockouts, etc.)
are recognized and can be forwarded into the events pipeline so they correlate
alongside packet-derived detections.
"""

import re
import json
import time

# --- severity maps ---------------------------------------------------------

# syslog numeric severity (0-7) -> our three-level scale
_SYSLOG_SEV = {
    0: "ALERT", 1: "ALERT", 2: "ALERT", 3: "ALERT",   # emerg/alert/crit/err
    4: "WARNING", 5: "INFO", 6: "INFO", 7: "INFO",     # warn/notice/info/debug
}
_SYSLOG_FACILITY = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}
_WINLOG_SEV = {
    "Critical": "ALERT", "Error": "ALERT", "Warning": "WARNING",
    "Information": "INFO", "Verbose": "INFO", "AuditFailure": "ALERT",
    "AuditSuccess": "INFO",
}

# Signals worth surfacing as security events, matched case-insensitively against
# the message. Each maps to a (category, severity_floor).
_SECURITY_PATTERNS = [
    (re.compile(r"\bfailed password\b|\bauthentication failure\b|\binvalid user\b", re.I),
     ("auth", "WARNING")),
    (re.compile(r"\baccount (?:was )?locked\b|\blockout\b", re.I), ("auth", "ALERT")),
    (re.compile(r"\bfirewall\b.*\b(?:deny|denied|drop|blocked)\b|\bUFW BLOCK\b", re.I),
     ("firewall", "WARNING")),
    (re.compile(r"\bsudo\b.*\bCOMMAND=", re.I), ("privilege", "INFO")),
    (re.compile(r"\bsegfault\b|\bkernel panic\b", re.I), ("system", "WARNING")),
    (re.compile(r"\bmalware\b|\bvirus\b|\bquarantin", re.I), ("intel", "ALERT")),
    (re.compile(r"\bnew external\b|\bport scan\b|\bscan detected\b", re.I), ("scan", "WARNING")),
    (re.compile(r"\b4625\b", re.I), ("auth", "WARNING")),      # Win failed logon
    (re.compile(r"\b4740\b", re.I), ("auth", "ALERT")),        # Win account lockout
    (re.compile(r"\b1102\b", re.I), ("system", "ALERT")),      # Win audit log cleared
]

# RFC 3164: <PRI>Mmm dd hh:mm:ss host tag: msg
_RE_3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<tag>[^:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$")
# RFC 5424: <PRI>1 ISOTIME host app procid msgid [sd] msg
_RE_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<rest>.*)$")
# bare <PRI> with no structured header
_RE_PRI = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$")


def _blank(now=None):
    return {
        "ts": now or time.time(), "host": "", "source": "log",
        "severity": "INFO", "facility": "", "category": "log",
        "message": "", "raw": "", "fields": {},
    }


def parse_syslog(line, now=None):
    """Parse one syslog line (RFC 3164 or 5424, or bare <PRI>). Returns a
    normalized record. Never raises - unparseable lines still yield a record."""
    rec = _blank(now)
    rec["raw"] = line
    rec["source"] = "syslog"
    line = line.strip()

    m = _RE_5424.match(line)
    if m:
        pri = int(m.group("pri"))
        rec["severity"] = _SYSLOG_SEV.get(pri & 7, "INFO")
        rec["facility"] = _SYSLOG_FACILITY.get(pri >> 3, str(pri >> 3))
        rec["host"] = m.group("host")
        app = m.group("app")
        rec["fields"]["app"] = app if app != "-" else ""
        # strip a leading structured-data blob if present
        rest = m.group("rest")
        rest = re.sub(r"^\[.*?\]\s*", "", rest)
        rec["message"] = rest
        _apply_time(rec, m.group("ts"))
        _classify(rec)
        return rec

    m = _RE_3164.match(line)
    if m:
        pri = int(m.group("pri"))
        rec["severity"] = _SYSLOG_SEV.get(pri & 7, "INFO")
        rec["facility"] = _SYSLOG_FACILITY.get(pri >> 3, str(pri >> 3))
        rec["host"] = m.group("host")
        rec["fields"]["tag"] = m.group("tag").strip()
        if m.group("pid"):
            rec["fields"]["pid"] = m.group("pid")
        rec["message"] = m.group("msg")
        _classify(rec)
        return rec

    m = _RE_PRI.match(line)
    if m:
        pri = int(m.group("pri"))
        rec["severity"] = _SYSLOG_SEV.get(pri & 7, "INFO")
        rec["facility"] = _SYSLOG_FACILITY.get(pri >> 3, str(pri >> 3))
        rec["message"] = m.group("msg")
        _classify(rec)
        return rec

    # not syslog-shaped: treat the whole thing as a message
    rec["message"] = line
    _classify(rec)
    return rec


def parse_windows_event(evt, now=None):
    """Normalize a Windows Event Log entry. `evt` is a dict with keys like
    Channel, EventID, Level, Provider, Computer, Message, TimeCreated - the shape
    a pywin32 / wevtutil reader produces. Missing keys degrade gracefully."""
    rec = _blank(now)
    rec["source"] = "wineventlog"
    rec["host"] = evt.get("Computer", "") or evt.get("host", "")
    rec["severity"] = _WINLOG_SEV.get(evt.get("Level", ""), "INFO")
    rec["facility"] = evt.get("Channel", "") or "Windows"
    rec["fields"] = {
        "event_id": evt.get("EventID", ""),
        "provider": evt.get("Provider", ""),
        "channel": evt.get("Channel", ""),
    }
    msg = evt.get("Message", "") or ""
    # include the event id in the message so id-based patterns match
    eid = evt.get("EventID", "")
    rec["message"] = f"[{eid}] {msg}".strip() if eid else msg
    rec["raw"] = json.dumps(evt, default=str)
    _apply_time(rec, evt.get("TimeCreated"))
    _classify(rec)
    return rec


def parse_generic(line, source="applog", now=None):
    """Parse a generic log line: JSON object, key=value pairs, or plain text."""
    rec = _blank(now)
    rec["source"] = source
    rec["raw"] = line
    line = line.strip()

    # JSON object?
    if line.startswith("{"):
        try:
            obj = json.loads(line)
            rec["fields"] = {k: v for k, v in obj.items() if not isinstance(v, (dict, list))}
            rec["message"] = str(obj.get("message") or obj.get("msg") or line)
            rec["host"] = str(obj.get("host") or obj.get("hostname") or "")
            lvl = str(obj.get("level") or obj.get("severity") or "").upper()
            if lvl in ("INFO", "WARNING", "ALERT"):
                rec["severity"] = lvl
            elif lvl in ("ERROR", "ERR", "CRITICAL", "CRIT", "FATAL"):
                rec["severity"] = "ALERT"
            elif lvl in ("WARN",):
                rec["severity"] = "WARNING"
            _classify(rec)
            return rec
        except Exception:
            pass

    # key=value pairs?
    kv = dict(re.findall(r"(\w+)=(\"[^\"]*\"|\S+)", line))
    if len(kv) >= 2:
        rec["fields"] = {k: v.strip('"') for k, v in kv.items()}
        rec["host"] = rec["fields"].get("host", "") or rec["fields"].get("src", "")
        rec["message"] = rec["fields"].get("msg", line)
    else:
        rec["message"] = line
    _classify(rec)
    return rec


def _classify(rec):
    """Tag a record with a security category/severity if its message matches a
    known pattern. Raises the severity floor but never lowers it."""
    msg = rec.get("message", "") or ""
    for pat, (cat, floor) in _SECURITY_PATTERNS:
        if pat.search(msg):
            rec["category"] = cat
            if _sev_rank(floor) > _sev_rank(rec["severity"]):
                rec["severity"] = floor
            rec["fields"]["security_signal"] = True
            return
    # no security match: keep neutral 'log' category


def is_security_relevant(rec):
    return bool(rec.get("fields", {}).get("security_signal")) or rec.get("category") != "log"


def to_event(rec):
    """Shape a normalized record for events.log_event(severity, category, source,
    message). Returns a tuple ready to unpack, or None for non-security noise."""
    if not is_security_relevant(rec):
        return None
    src = rec.get("host") or rec.get("source") or "log"
    cat = rec.get("category") if rec.get("category") != "log" else "system"
    msg = rec.get("message", "")[:300]
    return (rec.get("severity", "INFO"), cat, src, msg)


def forward(rec, *, events=None):
    """Forward a security-relevant record into the events pipeline. Returns True
    if an event was emitted."""
    tup = to_event(rec)
    if tup and events is not None:
        try:
            events.log_event(*tup)
            return True
        except Exception:
            pass
    return False


def _apply_time(rec, ts_str):
    if not ts_str:
        return
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            rec["ts"] = time.mktime(time.strptime(str(ts_str)[:19], fmt))
            return
        except Exception:
            continue


def _sev_rank(s):
    return {"INFO": 0, "WARNING": 1, "ALERT": 2}.get(s, 0)
