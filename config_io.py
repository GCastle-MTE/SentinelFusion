"""Config export / import - portable, reproducible deployments.

A professional tool lets you capture its whole configuration and move it to
another machine (or back up before a change). This bundles the pieces that make a
SentinelFusion install behave the way it does - user settings and the detection
rule tuning (thresholds + which rules are enabled) - into one versioned JSON file,
and restores them on import.

It deliberately exports *configuration*, not captured data or secrets-in-the-clear
beyond what settings already stores. Injected modules keep it testable.
"""

import json
import time

SCHEMA_VERSION = 1


def export_config(*, settings=None, detection_rules=None):
    """Assemble a config bundle dict."""
    bundle = {
        "schema": SCHEMA_VERSION,
        "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "app": "SentinelFusion",
    }
    if settings is not None:
        try:
            bundle["settings"] = settings.snapshot()
        except Exception:
            bundle["settings"] = {}
    if detection_rules is not None:
        try:
            bundle["detection"] = detection_rules.snapshot()
        except Exception:
            bundle["detection"] = {}
    return bundle


def export_to_file(path, *, settings=None, detection_rules=None):
    bundle = export_config(settings=settings, detection_rules=detection_rules)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    return path


def import_config(bundle, *, settings=None, detection_rules=None):
    """Apply a config bundle. Returns a list of what was applied / skipped."""
    applied = []
    if not isinstance(bundle, dict):
        return ["error: not a config bundle"]
    schema = bundle.get("schema")
    if schema != SCHEMA_VERSION:
        applied.append(f"warning: schema {schema} != expected {SCHEMA_VERSION} "
                       "(attempting anyway)")

    if settings is not None and "settings" in bundle:
        try:
            settings.update(bundle["settings"])
            settings.save()
            applied.append(f"settings: {len(bundle['settings'])} key(s) applied")
        except Exception as exc:
            applied.append(f"settings: failed ({exc})")

    if detection_rules is not None and "detection" in bundle:
        try:
            detection_rules.restore(bundle["detection"])
            th = len((bundle["detection"] or {}).get("thresholds", {}))
            en = len((bundle["detection"] or {}).get("enabled", {}))
            applied.append(f"detection: {th} threshold(s), {en} rule state(s) applied")
        except Exception as exc:
            applied.append(f"detection: failed ({exc})")

    return applied or ["nothing to apply"]


def import_from_file(path, *, settings=None, detection_rules=None):
    with open(path, "r", encoding="utf-8") as f:
        bundle = json.load(f)
    return import_config(bundle, settings=settings, detection_rules=detection_rules)
