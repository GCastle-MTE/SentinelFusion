"""Digital forensics - reconstruct, extract, and bundle evidence.

When an investigation moves past "is this bad?" to "what exactly happened and can
I prove it?", an analyst needs three things this module provides:

  * a **timeline** - every event touching an actor, in order, from all sources
    (detections, DNS lookups, flows, HTTP, case notes), so the sequence is clear;
  * **indicators of compromise (IOCs)** pulled out into a clean list - the IPs,
    domains, JA3/JARM fingerprints, and URLs seen - ready to share or block;
  * an **evidence bundle** - a single folder/manifest gathering the timeline, the
    IOCs, the enrichment profile, and a pointer to the exported PCAP, with a hash
    of each artifact so the collection is tamper-evident.

Everything is assembled from data the app already holds; sources are injected so
this stays testable. It reconstructs and packages - it doesn't alter evidence.
"""

import os
import json
import time
import hashlib


def timeline(actor, *, db=None, dns_log=None, flow_tracker=None, http_log=None,
             case=None, limit=1000):
    """Build a time-ordered list of everything involving `actor`.

    Each entry: {ts, stamp, kind, detail}. Sources are best-effort and injected.
    """
    events = []

    # Detections / stored events mentioning the actor.
    if db is not None:
        try:
            for e in (db.search_events(limit=5000) or []):
                if actor in (e.get("source", ""), e.get("message", "")):
                    events.append(_ev(e.get("ts"), "detection",
                                      f"[{e.get('severity', '')}] {e.get('category', '')}: "
                                      f"{e.get('message', '')}"))
        except Exception:
            pass

    # DNS lookups that resolved to the actor.
    if dns_log is not None:
        try:
            for r in (dns_log.recent(2000) or []):
                if actor in (r.get("ips") or []):
                    events.append(_ev(r.get("ts"), "dns",
                                      f"{r.get('client', '')} resolved {r.get('name', '')} "
                                      f"-> {actor}"))
        except Exception:
            pass

    # Flows touching the actor.
    if flow_tracker is not None:
        try:
            for f in (flow_tracker.flows(2000, "bytes") or []):
                if actor in (f.get("src"), f.get("dst")):
                    events.append(_ev(f.get("start"), "flow",
                                      f"{f.get('src')}:{f.get('sport')} -> "
                                      f"{f.get('dst')}:{f.get('dport')} "
                                      f"{f.get('protocol') or f.get('proto', '')} "
                                      f"({f.get('bytes', 0)} bytes)"))
        except Exception:
            pass

    # HTTP transactions with the actor.
    if http_log is not None:
        try:
            for h in (http_log.recent(2000) or []):
                if actor in (h.get("dst", ""), h.get("host", ""), h.get("src", "")):
                    events.append(_ev(h.get("ts"), "http",
                                      f"{h.get('method', '')} {h.get('host', '')}"
                                      f"{h.get('url', '')} -> {h.get('status', '')}"))
        except Exception:
            pass

    # Case timeline notes.
    if case is not None:
        try:
            notes = json.loads(case.get("notes") or "[]")
            for n in notes:
                events.append(_ev(_parse(n.get("ts")), "case", n.get("text", "")))
        except Exception:
            pass

    events = [e for e in events if e["ts"] is not None]
    events.sort(key=lambda e: e["ts"])
    return events[:limit]


def extract_iocs(actor, *, dns_log=None, flow_tracker=None, http_log=None,
                 threat_detection=None, enrichment_profile=None):
    """Collect indicators of compromise related to an actor into clean lists."""
    iocs = {"ips": set(), "domains": set(), "urls": set(),
            "ja3": set(), "jarm": set(), "asns": set()}
    iocs["ips"].add(actor)

    if dns_log is not None:
        try:
            for r in (dns_log.recent(2000) or []):
                if actor in (r.get("ips") or []):
                    if r.get("name"):
                        iocs["domains"].add(r["name"])
        except Exception:
            pass

    if http_log is not None:
        try:
            for h in (http_log.recent(2000) or []):
                if actor in (h.get("dst", ""), h.get("host", "")):
                    if h.get("host"):
                        iocs["domains"].add(h["host"])
                    if h.get("url"):
                        iocs["urls"].add(f"{h.get('host', '')}{h['url']}")
        except Exception:
            pass

    if threat_detection is not None:
        try:
            rec = threat_detection.endpoint_stats.get(actor, {})
            for j in rec.get("ja3", []) or []:
                iocs["ja3"].add(j)
        except Exception:
            pass

    if enrichment_profile is not None:
        try:
            geo = enrichment_profile.get("geo", {}) or {}
            if geo.get("asn"):
                iocs["asns"].add(geo["asn"])
            if enrichment_profile.get("jarm"):
                iocs["jarm"].add(enrichment_profile["jarm"])
        except Exception:
            pass

    return {k: sorted(v) for k, v in iocs.items()}


def build_bundle(actor, out_dir, *, timeline_events=None, iocs=None,
                 enrichment_lines=None, pcap_path=None, case=None):
    """Assemble an evidence bundle in `out_dir`. Writes timeline.txt, iocs.json,
    enrichment.txt, an optional copy-reference to the PCAP, and a manifest.json
    with a SHA-256 of each artifact. Returns the manifest dict."""
    os.makedirs(out_dir, exist_ok=True)
    artifacts = []

    def _write(name, content):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        artifacts.append(_artifact(path))
        return path

    # timeline
    if timeline_events:
        lines = [f"{e['stamp']}  [{e['kind']}]  {e['detail']}" for e in timeline_events]
        _write("timeline.txt", "\n".join(lines))

    # IOCs
    if iocs:
        _write("iocs.json", json.dumps(iocs, indent=2))

    # enrichment
    if enrichment_lines:
        _write("enrichment.txt", "\n".join(enrichment_lines))

    # case summary
    if case:
        _write("case.json", json.dumps(case, indent=2, default=str))

    # PCAP reference (we hash it in place rather than copy, to avoid duplicating
    # potentially large captures; the manifest records where it lives).
    if pcap_path and os.path.exists(pcap_path):
        artifacts.append(_artifact(pcap_path))

    manifest = {
        "actor": actor,
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "SentinelFusion",
        "artifacts": artifacts,
    }
    mpath = os.path.join(out_dir, "manifest.json")
    with open(mpath, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def _artifact(path):
    return {
        "file": os.path.basename(path),
        "path": path,
        "bytes": _size(path),
        "sha256": _sha256(path),
    }


def _sha256(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0


def _ev(ts, kind, detail):
    ts = ts if isinstance(ts, (int, float)) else _parse(ts)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else ""
    return {"ts": ts, "stamp": stamp, "kind": kind, "detail": detail}


def _parse(ts):
    if isinstance(ts, (int, float)):
        return ts
    if not ts:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return time.mktime(time.strptime(str(ts)[:19], fmt))
        except Exception:
            continue
    return None
