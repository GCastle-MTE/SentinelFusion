"""Capture review - run the whole inspection stack over a pcap, offline.

The live engine inspects packets as they arrive. This does the same work to a
file and hands back a structured report instead: what protocols are in there,
who talked to whom, what was looked up in DNS, which certificates were
presented, what credentials crossed in the clear, and everything worth flagging.

Two deliberate properties:

  * **Isolated.** Nothing here touches the live endpoint, flow, map, DNS or
    event state. Reviewing a file must never contaminate what you're seeing from
    your own network. All the analysis modules it leans on (protocol_id,
    tls_certs, cred_sniffer, dns_log.parse_message) are pure functions, so this
    module keeps its own local tallies and throws them away with the report.
  * **Honest about time.** Findings are judged from the packet timestamps in the
    file, not the wall clock.

`review()` takes scapy packets but only ever reads fields through `_fields()`,
so the analysis is testable with plain stubs.
"""

import time
from collections import Counter

import cred_sniffer
import dns_log
import http_log
import protocol_id
import tls_certs

MAX_DNS_ROWS = 400
MAX_CERT_ROWS = 60
MAX_FINDINGS = 400


def _fields(packet):
    """Extract what we need from a packet. None if it isn't IP."""
    out = {"src": "", "dst": "", "sport": None, "dport": None, "proto": "other",
           "payload": b"", "ts": 0.0, "len": 0, "flags": 0}
    try:
        out["len"] = len(packet)
    except Exception:
        pass
    try:
        out["ts"] = float(getattr(packet, "time", 0) or 0)
    except Exception:
        pass
    try:
        if not packet.haslayer("IP"):
            return None
        ip = packet["IP"]
        out["src"], out["dst"] = str(ip.src), str(ip.dst)
    except Exception:
        return None
    try:
        if packet.haslayer("TCP"):
            layer = packet["TCP"]
            out["proto"] = "TCP"
            try:
                out["flags"] = int(layer.flags)
            except Exception:
                pass
        elif packet.haslayer("UDP"):
            layer = packet["UDP"]
            out["proto"] = "UDP"
        else:
            return out
        out["sport"], out["dport"] = int(layer.sport), int(layer.dport)
    except Exception:
        return out
    try:
        if packet.haslayer("Raw"):
            out["payload"] = bytes(packet["Raw"].load)
    except Exception:
        pass
    return out


def _fmt_ts(ts):
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else "?"
    except Exception:
        return "?"


def review(packets, progress=None):
    """Analyse packets and return a report dict. Never mutates live state."""
    report = {
        "packets": 0, "ip_packets": 0, "bytes": 0,
        "start": 0.0, "end": 0.0, "duration": 0.0,
        "protocols": Counter(), "ports": Counter(), "talkers": Counter(),
        "endpoints": set(), "dns": [], "certs": [], "creds": [], "findings": [],
        "http": [], "user_agents": Counter(), "conversations": 0, "errors": 0,
        "flows": {},
    }
    seen_proto_alert = set()
    seen_cert = set()
    seen_cred = set()
    seen_http = set()
    convs = set()
    pending_dns = {}
    pending_http = {}

    for index, packet in enumerate(packets):
        report["packets"] += 1
        if progress and index % 500 == 0:
            try:
                progress(index)
            except Exception:
                pass
        try:
            f = _fields(packet)
        except Exception:
            report["errors"] += 1
            continue
        if not f:
            continue

        report["ip_packets"] += 1
        report["bytes"] += f["len"]
        ts = f["ts"]
        if ts:
            report["start"] = ts if not report["start"] else min(report["start"], ts)
            report["end"] = max(report["end"], ts)
        report["endpoints"].add(f["src"])
        report["endpoints"].add(f["dst"])
        report["talkers"][(f["src"], f["dst"])] += 1
        if f["sport"] and f["dport"]:
            server_port = min(f["sport"], f["dport"])
            report["ports"][server_port] += 1
            convs.add((f["proto"], tuple(sorted([(f["src"], f["sport"]),
                                                 (f["dst"], f["dport"])]))))
            # Local flow accounting - direction-normalised 5-tuple, kept in the
            # report only (no shared flow_tracker state touched).
            left = (f["src"], f["sport"])
            right = (f["dst"], f["dport"])
            fkey = (f["proto"], min(left, right), max(left, right))
            fl = report["flows"].get(fkey)
            if fl is None:
                fl = {"proto": f["proto"], "a": min(left, right), "b": max(left, right),
                      "out": 0, "in": 0, "out_pkts": 0, "in_pkts": 0, "pkts": 0,
                      "start": f["ts"], "last": f["ts"], "protocol": "",
                      "_gaps": [], "_last_ts": f["ts"]}
                report["flows"][fkey] = fl
            if left == fl["a"]:
                fl["out"] += f["len"]
                fl["out_pkts"] += 1
            else:
                fl["in"] += f["len"]
                fl["in_pkts"] += 1
            fl["pkts"] += 1
            if f["ts"]:
                gap = f["ts"] - fl["_last_ts"]
                fl["_last_ts"] = f["ts"]
                if gap > 0 and len(fl["_gaps"]) < 60:
                    fl["_gaps"].append(gap)
                fl["last"] = max(fl["last"], f["ts"])

        payload = f["payload"]
        if not payload:
            continue

        # --- protocol classification ---
        try:
            result = protocol_id.classify(payload, f["sport"], f["dport"], f["proto"])
        except Exception:
            result = None
        if result and result.get("protocol") and result["protocol"] != "unknown":
            report["protocols"][result["protocol"]] += 1
            if f["sport"] and f["dport"]:
                left = (f["src"], f["sport"])
                fkey = (f["proto"], min(left, (f["dst"], f["dport"])),
                        max(left, (f["dst"], f["dport"])))
                fl = report["flows"].get(fkey)
                if fl and not fl["protocol"]:
                    fl["protocol"] = result["protocol"]
            verdict = protocol_id.assess(result)
            if verdict:
                key = (f["dst"], result["protocol"], result.get("port"))
                if key not in seen_proto_alert:
                    seen_proto_alert.add(key)
                    report["findings"].append(
                        (verdict[0], "protocol", f["dst"], verdict[1], _fmt_ts(ts)))

        # --- DNS (parsed locally; the live dns_log registry is untouched) ---
        if 53 in (f["sport"], f["dport"]):
            try:
                msg = dns_log.parse_message(payload)
            except Exception:
                msg = None
            if msg and msg["questions"]:
                qname, qtype = msg["questions"][0]
                if msg["qr"] == 0:
                    pending_dns[(msg["id"], f["src"], qname.lower())] = qname
                else:
                    ips = [a["data"] for a in msg["answers"]
                           if a["type"] in ("A", "AAAA") and a["data"]]
                    rcode = dns_log.RCODES.get(msg["rcode"], str(msg["rcode"]))
                    pending_dns.pop((msg["id"], f["dst"], qname.lower()), None)
                    if len(report["dns"]) < MAX_DNS_ROWS:
                        report["dns"].append({
                            "ts": ts, "client": f["dst"], "name": qname,
                            "type": dns_log.QTYPES.get(qtype, str(qtype)),
                            "rcode": rcode, "ips": ips,
                        })

        # --- TLS certificates ---
        if tls_certs.has_certificate(payload):
            try:
                ders = tls_certs.certs_from_records(payload)
            except Exception:
                ders = []
            if ders:
                cert = tls_certs.parse_certificate(ders[0])
                if cert:
                    serial = cert.get("serial", "")
                    if serial not in seen_cert:
                        seen_cert.add(serial)
                        subject = (cert.get("subject") or {}).get("CN") or "?"
                        if len(report["certs"]) < MAX_CERT_ROWS:
                            report["certs"].append(
                                {"host": f["src"], "subject": subject,
                                 "issuer": (cert.get("issuer") or {}).get("CN") or "?",
                                 "cert": cert})
                        for sev, label, detail in tls_certs.analyze(cert, now=ts or None):
                            if sev == "INFO":
                                continue
                            report["findings"].append(
                                (sev, "cert", f["src"],
                                 f"certificate ({subject}) - {label}: {detail}", _fmt_ts(ts)))

        # --- HTTP transactions (pure parser only; http_log's live registry is
        # never touched, preserving the isolation guarantee) ---
        msg = http_log.parse(payload)
        if msg:
            if msg["kind"] == "request":
                if msg.get("user_agent"):
                    report["user_agents"][msg["user_agent"]] += 1
                url = msg["target"] if msg["target"].startswith("http") else (
                    f"http://{msg['host']}{msg['target']}" if msg["host"] else msg["target"])
                pending_http[(f["src"], f["dst"], f["sport"], f["dport"])] = (
                    f["src"], url)
                if len(report["http"]) < MAX_DNS_ROWS:
                    report["http"].append(
                        {"ts": ts, "client": f["src"], "method": msg["method"],
                         "url": url, "status": 0, "ua": msg["user_agent"]})
                row = {"method": msg["method"], "target": msg["target"],
                       "host": msg["host"], "user_agent": msg["user_agent"],
                       "authorization": msg["authorization"], "cookie": msg["cookie"]}
                http_log._flag(row)
                for sev, message in row.get("flags", []):
                    if sev == "INFO":
                        continue
                    key = (f["src"], url, message)
                    if key not in seen_http:
                        seen_http.add(key)
                        report["findings"].append(
                            (sev, "http", f["src"],
                             f"{message}  -  {msg['method']} {url}", _fmt_ts(ts)))
            else:
                pend = pending_http.pop((f["dst"], f["src"], f["dport"], f["sport"]), None)
                if pend:
                    for entry in reversed(report["http"]):
                        if (entry["client"] == pend[0] and entry["url"] == pend[1]
                                and entry["status"] == 0):
                            entry["status"] = msg["status"]
                            break

        # --- cleartext credentials ---
        server_port = None
        for p in (f["dport"], f["sport"]):
            if p in cred_sniffer.PLAINTEXT_PORTS:
                server_port = p
                break
        if server_port:
            try:
                found = cred_sniffer.find_credentials(payload, server_port)
            except Exception:
                found = None
            if found:
                kind, detail = found
                key = (f["dst"], kind, detail)
                if key not in seen_cred:
                    seen_cred.add(key)
                    report["creds"].append(
                        {"ts": ts, "src": f["src"], "dst": f["dst"],
                         "port": server_port, "kind": kind, "detail": detail})
                    report["findings"].append(
                        ("ALERT", "creds", f["dst"],
                         f"cleartext credentials to {f['dst']}:{server_port} - "
                         f"{kind}: {detail}", _fmt_ts(ts)))

    report["conversations"] = len(convs)
    report["unanswered_dns"] = len(pending_dns)
    if report["start"] and report["end"]:
        report["duration"] = max(0.0, report["end"] - report["start"])

    # Per-flow behavioural findings (beacon / exfil / RTP), computed purely from
    # the local flow tallies - no shared analytics state, so isolation holds.
    for fl in report["flows"].values():
        a, b = fl["a"], fl["b"]
        snap = {
            "proto": fl["proto"], "protocol": fl["protocol"],
            "src": a[0], "sport": a[1], "dst": b[0], "dport": b[1], "host": "",
            "out_bytes": fl["out"], "in_bytes": fl["in"],
            "out_pkts": fl["out_pkts"], "in_pkts": fl["in_pkts"],
            "packets": fl["pkts"], "bytes": fl["out"] + fl["in"],
        }
        for sev, cat, msg in _flow_findings(snap, fl["_gaps"]):
            report["findings"].append((sev, cat, snap["src"], msg,
                                       _fmt_ts(fl.get("start", 0))))

    report["findings"] = report["findings"][:MAX_FINDINGS]
    return report


def _cv(values):
    if len(values) < 2:
        return 1.0
    mean = sum(values) / len(values)
    if mean <= 0:
        return 1.0
    var = sum((v - mean) ** 2 for v in values) / len(values)
    return (var ** 0.5) / mean


def _flow_findings(snap, gaps):
    """Local beacon/exfil/RTP judgement for one reviewed flow (pure, no state)."""
    out = []
    ob, ib = snap["out_bytes"], snap["in_bytes"]
    remote = snap["dst"]
    if ob >= 5 * 1024 * 1024 and ob > ib * 8.0:
        out.append(("ALERT", "exfil",
                    f"Outbound-heavy flow to {remote}:{snap['dport']} - "
                    f"{_fmt_bytes(ob)} out / {_fmt_bytes(ib)} in. Shape of a data upload."))
    if len(gaps) >= 6:
        mean = sum(gaps) / len(gaps)
        if mean >= 1.0 and _cv(gaps) < 0.20:
            out.append(("ALERT", "beacon",
                        f"Regular callouts to {remote}:{snap['dport']} - ~every "
                        f"{mean:.0f}s (jitter {_cv(gaps) * 100:.0f}%). C2 check-in pattern."))
    if (snap["proto"] == "UDP" and not snap["protocol"] and snap["packets"] >= 20):
        avg = snap["bytes"] / max(1, snap["packets"])
        both = snap["out_pkts"] >= 5 and snap["in_pkts"] >= 5
        cv = _cv(gaps) if len(gaps) >= 5 else 1.0
        if avg <= 400 and both and snap["dport"] > 1024 and cv < 0.6:
            out.append(("INFO", "protocol",
                        f"Likely RTP media stream {snap['src']} <-> {remote}:{snap['dport']} - "
                        f"{snap['packets']} small, steady UDP packets both ways."))
    return out


def _fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def summarize(report):
    """Human-readable lines for the review panel."""
    if not report or not report["packets"]:
        return ["No packets to review."]
    lines = []
    span = ""
    if report["duration"]:
        span = f"   spanning {report['duration']:.1f}s   ({_fmt_ts(report['start'])} -> {_fmt_ts(report['end'])})"
    lines.append(f"{report['packets']} packets   -   {report['ip_packets']} IP   -   "
                 f"{report['bytes'] / 1024:.1f} KB{span}")
    lines.append(f"{len(report['endpoints'])} endpoints   -   "
                 f"{report['conversations']} conversations")

    if report["protocols"]:
        top = ", ".join(f"{name} ({n})" for name, n in report["protocols"].most_common(10))
        lines.append("")
        lines.append(f"Protocols seen:  {top}")
    if report["ports"]:
        ports = ", ".join(f"{p} ({n})" for p, n in report["ports"].most_common(10))
        lines.append(f"Busiest ports:   {ports}")
    if report["talkers"]:
        lines.append("")
        lines.append("Top conversations:")
        for (a, b), n in report["talkers"].most_common(5):
            lines.append(f"   {a}  ->  {b}      {n} packets")

    if report["dns"]:
        lines.append("")
        lines.append(f"DNS lookups ({len(report['dns'])}):")
        for row in report["dns"][:8]:
            answer = ", ".join(row["ips"][:2]) if row["ips"] else row["rcode"]
            lines.append(f"   {row['name']}  ({row['type']})  ->  {answer}")
        if len(report["dns"]) > 8:
            lines.append(f"   ... and {len(report['dns']) - 8} more")

    if report["certs"]:
        lines.append("")
        lines.append(f"TLS certificates ({len(report['certs'])}):")
        for c in report["certs"][:5]:
            lines.append(f"   {c['subject']}   issued by {c['issuer']}   (from {c['host']})")

    if report.get("http"):
        lines.append("")
        lines.append(f"HTTP requests ({len(report['http'])}):")
        for tx in report["http"][:8]:
            code = tx["status"] or "-"
            lines.append(f"   {tx['method']:5} {tx['url'][:64]}   [{code}]")
        if len(report["http"]) > 8:
            lines.append(f"   ... and {len(report['http']) - 8} more")
    if report.get("user_agents"):
        lines.append("")
        lines.append("Software seen (User-Agents):")
        for ua, n in report["user_agents"].most_common(6):
            lines.append(f"   {ua[:72]}   ({n})")

    if report.get("flows"):
        top = sorted(report["flows"].values(),
                     key=lambda fl: fl["out"] + fl["in"], reverse=True)
        lines.append("")
        lines.append(f"Flows ({len(report['flows'])}):")
        for fl in top[:6]:
            a, b = fl["a"], fl["b"]
            name = fl["protocol"] or fl["proto"]
            total = (fl["out"] + fl["in"]) / 1024
            lines.append(f"   {name:10} {a[0]}:{a[1]} <-> {b[0]}:{b[1]}   "
                         f"{total:.1f} KB  ({fl['pkts']} pkts)")
        if len(report["flows"]) > 6:
            lines.append(f"   ... and {len(report['flows']) - 6} more")

    if report["creds"]:
        lines.append("")
        lines.append(f"CLEARTEXT CREDENTIALS ({len(report['creds'])}):")
        for c in report["creds"]:
            lines.append(f"   {c['src']} -> {c['dst']}:{c['port']}   {c['kind']}: {c['detail']}")

    if report["findings"]:
        lines.append("")
        lines.append(f"FINDINGS ({len(report['findings'])}):")
        for sev, cat, src, msg, stamp in report["findings"][:20]:
            lines.append(f"   [{sev}] {stamp} {cat}  {src}")
            lines.append(f"         {msg}")
        if len(report["findings"]) > 20:
            lines.append(f"   ... and {len(report['findings']) - 20} more")
    else:
        lines.append("")
        lines.append("No findings - nothing in this capture tripped a detector.")
    return lines
