"""SOC metrics - the numbers a security lead actually watches.

Detection is only half of operations; the other half is how well you *respond*.
This computes the operational metrics a SOC runs on: mean time to acknowledge and
resolve cases (MTTA / MTTR), how many cases are open and how old they're getting
(aging), and the trend of detections over time. These are the figures that go on
a status slide and tell you whether the team is keeping up.

Everything is derived from the case records and the stored event history, so it
reflects real activity. db_manager is injected for testability.
"""

import time


def _parse(ts):
    """Parse a stored 'YYYY-mm-dd HH:MM:SS' string to epoch, or None."""
    if not ts:
        return None
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
    except Exception:
        return None


def case_metrics(*, db):
    """MTTA / MTTR and status counts over all cases.

    MTTA approximated as time from open -> first status change away from 'new'
    (we infer it from the notes timeline). MTTR as open -> closed.
    """
    import json
    rows = db.get_cases()
    now = time.time()
    ack_times, resolve_times, ages = [], [], []
    by_status = {}
    for c in rows:
        by_status[c.get("status", "new")] = by_status.get(c.get("status", "new"), 0) + 1
        opened = _parse(c.get("created_at"))
        updated = _parse(c.get("updated_at"))
        if opened is None:
            continue
        # resolution time: closed cases only
        if c.get("status") == "closed" and updated:
            resolve_times.append(max(0.0, updated - opened))
        else:
            ages.append(max(0.0, now - opened))
        # acknowledgement: first note that isn't the "opened" note
        try:
            notes = json.loads(c.get("notes") or "[]")
        except Exception:
            notes = []
        for n in notes[1:]:
            t = _parse(n.get("ts"))
            if t:
                ack_times.append(max(0.0, t - opened))
                break

    return {
        "total": len(rows),
        "open": sum(v for k, v in by_status.items() if k != "closed"),
        "closed": by_status.get("closed", 0),
        "by_status": by_status,
        "mtta_sec": _mean(ack_times),
        "mttr_sec": _mean(resolve_times),
        "oldest_open_sec": max(ages) if ages else 0.0,
        "avg_open_age_sec": _mean(ages),
        "resolved_count": len(resolve_times),
    }


def aging_buckets(*, db):
    """Open cases bucketed by age - the classic 'is anything rotting' view."""
    rows = db.get_cases()
    now = time.time()
    buckets = {"<1h": 0, "1-24h": 0, "1-7d": 0, ">7d": 0}
    for c in rows:
        if c.get("status") == "closed":
            continue
        opened = _parse(c.get("created_at"))
        if opened is None:
            continue
        age = now - opened
        if age < 3600:
            buckets["<1h"] += 1
        elif age < 86400:
            buckets["1-24h"] += 1
        elif age < 7 * 86400:
            buckets["1-7d"] += 1
        else:
            buckets[">7d"] += 1
    return buckets


def detection_trend(*, db, days=7):
    """Count of events per day over the last `days`, plus by-severity totals.
    Uses the stored event history."""
    try:
        rows = db.search_events(limit=100000)
    except Exception:
        rows = []
    now = time.time()
    cutoff = now - days * 86400
    per_day = {}
    by_sev = {}
    for r in rows:
        t = _parse(r.get("ts"))
        if t is None or t < cutoff:
            continue
        day = time.strftime("%Y-%m-%d", time.localtime(t))
        per_day[day] = per_day.get(day, 0) + 1
        sev = r.get("severity", "INFO")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    # fill missing days with zero for a clean series
    series = []
    for i in range(days - 1, -1, -1):
        day = time.strftime("%Y-%m-%d", time.localtime(now - i * 86400))
        series.append({"day": day, "count": per_day.get(day, 0)})
    return {"series": series, "by_severity": by_sev, "total": sum(per_day.values())}


def summary(*, db):
    """Compact plain-language SOC status lines."""
    cm = case_metrics(db=db)
    ag = aging_buckets(db=db)
    tr = detection_trend(db=db)
    lines = [
        f"Cases: {cm['open']} open, {cm['closed']} closed ({cm['total']} total)",
        f"MTTA: {_hms(cm['mtta_sec'])}    MTTR: {_hms(cm['mttr_sec'])}",
        f"Oldest open case: {_hms(cm['oldest_open_sec'])}   "
        f"avg open age: {_hms(cm['avg_open_age_sec'])}",
        f"Aging: <1h {ag['<1h']}  |  1-24h {ag['1-24h']}  |  "
        f"1-7d {ag['1-7d']}  |  >7d {ag['>7d']}",
        f"Detections (7d): {tr['total']}  "
        f"({', '.join(f'{k} {v}' for k, v in sorted(tr['by_severity'].items()))})",
    ]
    return lines


def _mean(xs):
    return (sum(xs) / len(xs)) if xs else 0.0


def _hms(sec):
    sec = int(sec or 0)
    if sec <= 0:
        return "-"
    if sec < 60:
        return f"{sec}s"
    if sec < 3600:
        return f"{sec // 60}m {sec % 60}s"
    if sec < 86400:
        return f"{sec // 3600}h {(sec % 3600) // 60}m"
    return f"{sec // 86400}d {(sec % 86400) // 3600}h"
