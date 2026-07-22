"""Export alerts to CSV or JSON - for reporting, archiving, or importing into a
spreadsheet or SIEM. Pure standard-library so it's easy to test.

`is_acked` (optional) is a callable taking an event dict and returning whether it
has been acknowledged, so the export can carry a triage column.
"""

import csv
import json

FIELDS = ["time", "severity", "category", "source", "message", "acknowledged"]


def _rows(alerts, is_acked=None):
    for e in alerts:
        yield {
            "time": e.get("stamp", ""),
            "severity": e.get("severity", ""),
            "category": e.get("category", ""),
            "source": e.get("source", ""),
            "message": e.get("message", ""),
            "acknowledged": bool(is_acked(e)) if is_acked else False,
        }


def to_csv(alerts, path, is_acked=None):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        for row in _rows(alerts, is_acked):
            writer.writerow(row)
    return path


def to_json(alerts, path, is_acked=None):
    data = list(_rows(alerts, is_acked))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path
