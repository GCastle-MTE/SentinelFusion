"""Feedback loop - learn from what the detectors got right and wrong.

The last block of the architecture: close the loop. Analysts mark detections as
true positives, false positives, or note false negatives (things that should have
fired but didn't). Over time that history says which rules are noisy and which are
missing things, and this turns that signal into concrete, honest tuning
recommendations against the detection-rules catalog.

What it does NOT do is pretend to retrain a model or silently change thresholds.
It measures precision per category and *suggests* a direction - "scan is 78% false
positives, consider raising its threshold" - which a human reviews and applies. The
tool stays explainable and the analyst stays in control, consistent with the rest
of SentinelFusion.

db_manager and detection_rules are injected for testability.
"""

import time

TRUE_POSITIVE = "true_positive"
FALSE_POSITIVE = "false_positive"
FALSE_NEGATIVE = "false_negative"
VERDICTS = (TRUE_POSITIVE, FALSE_POSITIVE, FALSE_NEGATIVE)

# Precision below this per category suggests it's too noisy (raise threshold).
NOISY_PRECISION = 0.5
# Need at least this many verdicts before we trust a recommendation.
MIN_SAMPLES = 5


def record(verdict, *, db, category="", actor="", severity="", message="", note=""):
    """Store an analyst verdict about a detection. Returns the new row id."""
    if verdict not in VERDICTS:
        return None
    row = {
        "category": category, "verdict": verdict, "actor": actor,
        "severity": severity, "message": message[:300], "note": note[:300],
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    return db.insert_feedback(row)


def category_stats(*, db):
    """Per-category counts and precision.

    precision = TP / (TP + FP) - how often an alert in this category was real.
    false_negatives are counted separately (they don't have a precision meaning
    on their own but signal under-detection).
    """
    rows = db.get_feedback(100000)
    stats = {}
    for r in rows:
        cat = r.get("category") or "?"
        s = stats.setdefault(cat, {"tp": 0, "fp": 0, "fn": 0})
        v = r.get("verdict")
        if v == TRUE_POSITIVE:
            s["tp"] += 1
        elif v == FALSE_POSITIVE:
            s["fp"] += 1
        elif v == FALSE_NEGATIVE:
            s["fn"] += 1
    for cat, s in stats.items():
        judged = s["tp"] + s["fp"]
        s["judged"] = judged
        s["precision"] = (s["tp"] / judged) if judged else None
        s["total"] = judged + s["fn"]
    return stats


def recommendations(*, db, detection_rules=None):
    """Turn feedback history into tuning recommendations.

    Each is {category, issue, suggestion, precision, samples, rule_id, direction}.
    `direction` is 'raise' / 'lower' / None so a UI can offer a one-click nudge,
    but nothing is applied automatically.
    """
    stats = category_stats(db=db)
    # map category -> tunable rule id (if any) via the catalog
    rule_for_cat = {}
    if detection_rules is not None:
        try:
            for rule in detection_rules.rules():
                if rule.get("tunable") and rule.get("category"):
                    rule_for_cat[rule["category"]] = rule["id"]
        except Exception:
            pass

    recs = []
    for cat, s in sorted(stats.items()):
        prec = s["precision"]
        # Noisy: lots of judged alerts, low precision -> raise threshold
        if prec is not None and s["judged"] >= MIN_SAMPLES and prec < NOISY_PRECISION:
            recs.append({
                "category": cat,
                "issue": f"{int((1 - prec) * 100)}% of '{cat}' alerts were marked false",
                "suggestion": f"Consider raising the '{cat}' threshold to cut noise.",
                "precision": round(prec, 2), "samples": s["judged"],
                "rule_id": rule_for_cat.get(cat), "direction": "raise",
            })
        # Missing things: false negatives reported -> lower threshold / tighten
        if s["fn"] >= max(3, MIN_SAMPLES // 2):
            recs.append({
                "category": cat,
                "issue": f"{s['fn']} missed '{cat}' event(s) reported (false negatives)",
                "suggestion": f"Consider lowering the '{cat}' threshold to catch more.",
                "precision": round(prec, 2) if prec is not None else None,
                "samples": s["fn"], "rule_id": rule_for_cat.get(cat),
                "direction": "lower",
            })
        # Healthy: high precision, enough samples -> affirm, no change
        if prec is not None and s["judged"] >= MIN_SAMPLES and prec >= 0.9 and s["fn"] == 0:
            recs.append({
                "category": cat,
                "issue": f"'{cat}' is accurate ({int(prec * 100)}% precision)",
                "suggestion": "Well tuned - no change recommended.",
                "precision": round(prec, 2), "samples": s["judged"],
                "rule_id": rule_for_cat.get(cat), "direction": None,
            })
    return recs


def apply_recommendation(rec, *, detection_rules, factor=1.5):
    """Apply a tuning recommendation by nudging the rule's threshold.

    'raise' multiplies the current threshold by `factor`; 'lower' divides by it.
    This is only ever called from an explicit analyst action in the UI - the loop
    itself never calls it. Returns (ok, old, new) or (False, None, None).
    """
    rule_id = rec.get("rule_id")
    direction = rec.get("direction")
    if not rule_id or direction not in ("raise", "lower"):
        return (False, None, None)
    try:
        cur = None
        for r in detection_rules.rules():
            if r["id"] == rule_id:
                cur = r["value"]
                break
        if cur is None:
            return (False, None, None)
        new = cur * factor if direction == "raise" else cur / factor
        # keep ints as ints
        if isinstance(cur, int):
            new = int(round(new))
        ok = detection_rules.set_threshold(rule_id, new)
        return (ok, cur, new) if ok else (False, None, None)
    except Exception:
        return (False, None, None)


def summary(*, db):
    """Plain-language overview of feedback health."""
    stats = category_stats(db=db)
    if not stats:
        return ["No feedback recorded yet. Mark alerts as accurate or false to "
                "start tuning the engine from real outcomes."]
    total_tp = sum(s["tp"] for s in stats.values())
    total_fp = sum(s["fp"] for s in stats.values())
    total_fn = sum(s["fn"] for s in stats.values())
    judged = total_tp + total_fp
    overall = (total_tp / judged) if judged else None
    lines = [
        f"Verdicts: {total_tp} true / {total_fp} false positive / {total_fn} missed",
        f"Overall precision: {int(overall * 100)}%" if overall is not None
        else "Overall precision: n/a",
        "",
        "By category:",
    ]
    for cat, s in sorted(stats.items(), key=lambda kv: (kv[1]["precision"] or 1)):
        prec = f"{int(s['precision'] * 100)}%" if s["precision"] is not None else "n/a"
        lines.append(f"  {cat}: {prec} precision  "
                     f"({s['tp']} true, {s['fp']} false, {s['fn']} missed)")
    return lines
