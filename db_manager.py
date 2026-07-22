# db_manager.py
from sqlalchemy import create_engine, Table, Column, Integer, String, MetaData

# echo=False keeps the console clean. Set it to True to see every SQL statement.
engine = create_engine("sqlite:///incidents.db", echo=False)
meta = MetaData()

incidents = Table(
    "incidents",
    meta,
    Column("id", Integer, primary_key=True),
    Column("status", String),
    Column("details", String),
)

# Devices seen on the local network (a snapshot of "what's connected").
devices = Table(
    "devices",
    meta,
    Column("id", Integer, primary_key=True),
    Column("ip", String),
    Column("mac", String),
    Column("vendor", String),
    Column("hostname", String),
    Column("last_seen", String),
)

# Per-target focused captures (the .pcap lives on disk; this is the index).
captures = Table(
    "captures",
    meta,
    Column("id", Integer, primary_key=True),
    Column("target", String),
    Column("pcap_path", String),
    Column("packet_count", Integer),
    Column("dpi_summary", String),
    Column("captured_at", String),
)

# Security event / log entries (the central log everything reports into).
events = Table(
    "events",
    meta,
    Column("id", Integer, primary_key=True),
    Column("ts", String),
    Column("severity", String),
    Column("category", String),
    Column("source", String),
    Column("message", String),
)

# SOAR case management: an incident worked from open to closed. `notes` and
# `actions` hold JSON blobs (timeline of analyst notes; recommended actions).
cases = Table(
    "cases",
    meta,
    Column("id", Integer, primary_key=True),
    Column("title", String),
    Column("actor", String),
    Column("severity", String),
    Column("status", String),          # new / investigating / contained / closed
    Column("assignee", String),
    Column("score", String),
    Column("summary", String),
    Column("notes", String),           # JSON list of {ts, text}
    Column("actions", String),         # JSON list of recommended actions
    Column("incident_id", String),
    Column("created_at", String),
    Column("updated_at", String),
)

# SOAR run log: every automated playbook execution, for the audit trail.
playbook_runs = Table(
    "playbook_runs",
    meta,
    Column("id", Integer, primary_key=True),
    Column("playbook", String),
    Column("trigger", String),
    Column("actor", String),
    Column("case_id", String),
    Column("steps", String),           # JSON list of {action, result, ts}
    Column("ran_at", String),
)

# Feedback loop: analyst verdicts on detections, used to tune the engine.
feedback = Table(
    "feedback",
    meta,
    Column("id", Integer, primary_key=True),
    Column("category", String),        # detection category the verdict is about
    Column("verdict", String),         # true_positive / false_positive / false_negative
    Column("actor", String),
    Column("severity", String),
    Column("message", String),
    Column("note", String),
    Column("created_at", String),
)

meta.create_all(engine)  # only creates tables that don't exist yet


def insert_incident(incident_details):
    # Insert a new incident and commit so it persists.
    # (Without the commit, SQLAlchemy 2.x rolls the insert back on close.)
    with engine.connect() as conn:
        conn.execute(
            incidents.insert(),
            [
                {
                    "status": incident_details["status"],
                    "details": incident_details["details"],
                }
            ],
        )
        conn.commit()


def get_all_incidents():
    # Return all incidents as a list of plain, mutable dicts.
    try:
        with engine.connect() as conn:
            result = conn.execute(incidents.select())
            return [dict(row._mapping) for row in result]
    except Exception as e:
        print("Error while getting incidents: ", str(e))
        return []


def store_devices(device_list):
    # Replace the device table with the latest scan (current snapshot).
    with engine.connect() as conn:
        conn.execute(devices.delete())
        if device_list:
            conn.execute(
                devices.insert(),
                [
                    {
                        "ip": d.get("ip", ""),
                        "mac": d.get("mac", ""),
                        "vendor": d.get("vendor", ""),
                        "hostname": d.get("hostname", ""),
                        "last_seen": d.get("last_seen", ""),
                    }
                    for d in device_list
                ],
            )
        conn.commit()


def get_devices():
    try:
        with engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(devices.select())]
    except Exception as e:
        print("Error while getting devices: ", str(e))
        return []


def insert_capture(target, pcap_path, packet_count, dpi_summary, captured_at):
    with engine.connect() as conn:
        conn.execute(
            captures.insert(),
            [
                {
                    "target": target,
                    "pcap_path": pcap_path,
                    "packet_count": packet_count,
                    "dpi_summary": dpi_summary,
                    "captured_at": captured_at,
                }
            ],
        )
        conn.commit()


def get_captures():
    try:
        with engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(captures.select())]
    except Exception as e:
        print("Error while getting captures: ", str(e))
        return []


def insert_event(severity, category, source, message, ts):
    with engine.connect() as conn:
        conn.execute(
            events.insert(),
            [
                {
                    "ts": ts,
                    "severity": severity,
                    "category": category,
                    "source": source,
                    "message": message,
                }
            ],
        )
        conn.commit()


def search_events(text=None, category=None, severity=None, source=None, limit=1000):
    """Retro-hunt over the stored event history. All filters optional."""
    try:
        with engine.connect() as conn:
            q = events.select()
            rows = [dict(r._mapping) for r in conn.execute(q)]
    except Exception as e:
        print("Error searching events: ", str(e))
        return []
    needle = (text or "").lower()
    out = []
    for r in rows:
        if category and r.get("category") != category:
            continue
        if severity and r.get("severity") != severity:
            continue
        if source and source not in (r.get("source") or ""):
            continue
        if needle and needle not in (
                (r.get("message", "") + r.get("source", "") + r.get("category", "")).lower()):
            continue
        out.append(r)
    return out[-limit:]


def event_stats():
    """Counts by category and severity across all stored history."""
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(events.select())]
    except Exception:
        return {"total": 0, "by_category": {}, "by_severity": {}}
    by_cat, by_sev = {}, {}
    for r in rows:
        c = r.get("category", "?")
        s = r.get("severity", "?")
        by_cat[c] = by_cat.get(c, 0) + 1
        by_sev[s] = by_sev.get(s, 0) + 1
    return {"total": len(rows), "by_category": by_cat, "by_severity": by_sev}


def get_events(limit=500):
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(events.select())]
            return rows[-limit:]
    except Exception as e:
        print("Error while getting events: ", str(e))
        return []


# --- SOAR: cases -----------------------------------------------------------

def insert_case(row):
    """Insert a case row (dict). Returns the new case id, or None."""
    try:
        with engine.begin() as conn:
            res = conn.execute(cases.insert().values(**row))
            return res.inserted_primary_key[0]
    except Exception as e:
        print("Error inserting case:", str(e))
        return None


def update_case(case_id, **fields):
    """Update columns on a case by id. Returns True on success."""
    try:
        with engine.begin() as conn:
            conn.execute(cases.update().where(cases.c.id == case_id).values(**fields))
        return True
    except Exception as e:
        print("Error updating case:", str(e))
        return False


def get_case(case_id):
    try:
        with engine.connect() as conn:
            row = conn.execute(cases.select().where(cases.c.id == case_id)).fetchone()
            return dict(row._mapping) if row else None
    except Exception as e:
        print("Error getting case:", str(e))
        return None


def get_cases(status=None, limit=500):
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(cases.select())]
    except Exception as e:
        print("Error getting cases:", str(e))
        return []
    if status:
        rows = [r for r in rows if r.get("status") == status]
    rows.sort(key=lambda r: r.get("updated_at") or "", reverse=True)
    return rows[:limit]


def case_for_incident(incident_id):
    """Find an existing case linked to an incident id, or None."""
    try:
        with engine.connect() as conn:
            for r in conn.execute(cases.select()):
                d = dict(r._mapping)
                if str(d.get("incident_id")) == str(incident_id):
                    return d
    except Exception as e:
        print("Error finding case for incident:", str(e))
    return None


# --- SOAR: playbook run log ------------------------------------------------

def insert_playbook_run(row):
    try:
        with engine.begin() as conn:
            res = conn.execute(playbook_runs.insert().values(**row))
            return res.inserted_primary_key[0]
    except Exception as e:
        print("Error inserting playbook run:", str(e))
        return None


def get_playbook_runs(limit=300):
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(playbook_runs.select())]
    except Exception as e:
        print("Error getting playbook runs:", str(e))
        return []
    rows.sort(key=lambda r: r.get("ran_at") or "", reverse=True)
    return rows[:limit]


# --- Feedback loop ---------------------------------------------------------

def insert_feedback(row):
    try:
        with engine.begin() as conn:
            res = conn.execute(feedback.insert().values(**row))
            return res.inserted_primary_key[0]
    except Exception as e:
        print("Error inserting feedback:", str(e))
        return None


def get_feedback(limit=1000, category=None):
    try:
        with engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(feedback.select())]
    except Exception as e:
        print("Error getting feedback:", str(e))
        return []
    if category:
        rows = [r for r in rows if r.get("category") == category]
    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    return rows[:limit]
