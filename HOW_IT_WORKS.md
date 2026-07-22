# How SentinelFusion Works — One Detection, End to End

The [README](README.md) lists what SentinelFusion does and the [HTML docs](SentinelFusion_Docs.html) cover every module. This document does something different: it follows a **single piece of malicious traffic** all the way through the system, so you can see how the pieces fit and why the design is shaped the way it is.

The scenario: a laptop on your network has been compromised, and the malware is quietly beaconing to a command-and-control server, then exfiltrating a batch of data. Here is what happens inside SentinelFusion, in order.

---

## 1. Capture and attribution

Every packet the machine sees arrives at the engine (`threat_detection.py`) via scapy. For each one, the engine does three cheap things immediately:

- **Classifies the endpoint** — is the other end external, on your LAN, loopback, multicast? Only external traffic is interesting for most detections.
- **Attributes it to a process** — using the local socket table (`process_lookup.py`), so the traffic isn't just "port 51000 → 45.13.66.7", it's "*that* app is talking to 45.13.66.7". This is what makes the Applications view and the process→connection map possible.
- **Updates per-endpoint stats** — bytes in/out, packet counts, ports touched, first/last seen, JA3 fingerprints. This rolling picture is the substrate everything else reads from.

A small ring buffer also retains the last few thousand raw packets, so that *if* this endpoint later turns out to matter, we can export a PCAP of exactly its traffic without having captured everything to disk.

**Design note:** attribution happens on the hot path but stays cheap — no blocking lookups, no network calls. Enrichment that *does* touch the network (geo, reputation) happens later, on demand, off the capture thread.

---

## 2. Detection — heuristics and a model, in parallel

The beaconing itself is caught by a **heuristic** detector. Malware beacons on a regular interval, so the engine watches the *timing* of connections to each endpoint. It doesn't just count — it measures the coefficient of variation of the inter-connection gaps. Evenly-spaced connections (low variation) are the signature; bursty human traffic (high variation) is not. This is deliberately narrow: it looks for one known shape and flags it as a `beacon` event.

Running alongside the heuristics is the **ML anomaly detector** (`ml_anomaly.py`) — an Isolation Forest trained on your network's own baseline of endpoint behaviour. It doesn't know what "beaconing" is; it knows what *normal* looks like here, and this endpoint doesn't fit. Crucially, when it flags something it reports *why* — "outbound/inbound ratio unusually high (11.5σ)" — so it's a lead with reasons, not a black box. The two approaches are complementary: heuristics catch known shapes precisely, the model catches the unknown-unknowns fuzzily.

When the data exfiltration starts, a second heuristic (`exfil` — a large outbound transfer to one endpoint) fires, and the ML score climbs further.

**Design note:** every detector is tunable and can be disabled from the detection-rules catalog, and a disabled rule is suppressed at the source. The engine is not a black box you trust blindly — it's a set of rules you can see and adjust.

---

## 3. Correlation — from alerts to an incident

Three separate alerts about one IP (`beacon`, then `exfil`, plus maybe a `scan` from earlier recon) are, individually, just noise. The correlation engine (`correlation.py`) groups every alert about a single actor within a time window and scores the *whole picture*.

The key idea: **breadth beats repetition.** An actor that trips three *different* detectors spanning different stages of an attack (recon → C2 → exfiltration) is far more dangerous than one that trips the same detector ten times. The scoring rewards spanning the kill chain. So our compromised laptop's C2 server, which touched recon + C2 + exfil, rolls up into a single **CRITICAL incident** — one line in the Incidents tab instead of a scattered pile of alerts.

Each detector category is mapped to its **MITRE ATT&CK** technique (`mitre_attack.py`), so the incident doesn't just say "beacon + exfil" — it says T1071 (Application Layer Protocol) and T1041 (Exfiltration Over C2 Channel). That's the language every SOC analyst and threat report already speaks.

---

## 4. Response — the SOAR layer takes the routine first steps

The moment that CRITICAL incident appears, the SOAR layer (`case_manager.py`, `playbook_engine.py`) does automatically what an analyst would do by hand every single time:

- **Opens a case** — a record that persists, with a status lifecycle (new → investigating → contained → closed), an assignee, and a note timeline.
- **Runs investigative playbooks** — enrich the actor (geo, ASN, reputation, DNS history), trace the DNS resolution chain (did we even look this IP up, or is it hard-coded — a C2 tell?), capture a PCAP of the evidence, hunt the same pattern on other internal hosts, and attach recommended actions.

Every one of those actions is **read-only**. This is the deliberate boundary: the automation gathers, correlates, and *recommends* — "consider blocking 45.13.66.7 at the perimeter" — but a human applies containment. The tool is a force-multiplier for the analyst, not an autopilot that reaches into your network. Everything it did is written to an audit run-log.

---

## 5. Investigation and evidence

Now the analyst works the case. They can:

- **Enrich** the actor for the full dossier in one panel.
- **Build an evidence bundle** (`forensics.py`) — a folder with a chronological timeline reconstructed from every source (detections, DNS, flows, HTTP, case notes), the extracted IOCs (IPs, domains, JA3/JARM, URLs), the enrichment profile, and the PCAP — each artifact SHA-256 hashed in a manifest so the collection is tamper-evident.
- **Generate a PDF report** — the case, its ATT&CK techniques, timeline, and recommended actions, ready to hand off.
- **Notify the wider stack** — if configured, the incident fires an outbound webhook to Slack/Teams/SIEM. One-directional: SentinelFusion never receives commands back.

---

## 6. Closing the loop

When the analyst resolves the case, they mark the original alerts as accurate. Over time, those verdicts feed the **feedback loop** (`feedback_loop.py`): per-category precision reveals which detectors are noisy and which are missing things, producing honest tuning recommendations ("scan is 78% false positives — consider raising its threshold"). The analyst applies the nudge, and the engine gets sharper. This is the last arrow in the architecture — the system learns from its own track record, but a human stays in the loop.

---

## Why it's shaped this way

A few principles run through the whole design:

- **Defensive, always.** It detects, analyses, and recommends. It never attacks, and the automation never performs containment on its own.
- **Explainable over clever.** Every alert has a plain-English reason; even the ML detector reports which features made something anomalous. An analyst can trust what they can understand.
- **Breadth over noise.** Correlation and scoring are built to surface the one thing that matters, not to drown you in alerts.
- **Testable by construction.** ~60 modules using dependency injection, so each piece is verifiable in isolation with no import cycles — which is how a project this size stays maintainable.

That's the whole journey: a packet arrives, gets attributed, trips detectors, correlates into a scored incident, opens a case, runs investigative automation, produces evidence and a report, and finally teaches the engine to do better next time.
