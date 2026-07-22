# SentinelFusion

A defensive network-security, threat-hunting, and OSINT desktop console.

SentinelFusion watches the traffic on your own machine and network in real time, attributes it to the processes and remote endpoints responsible, geolocates and enriches those endpoints against public intelligence, and raises plain-English alerts when it sees behaviour that matches known attack or exposure patterns. When related alerts add up, it correlates them into scored **incidents**, opens **cases**, and runs investigative **playbooks** automatically.

It is built for **monitoring, investigation, and response** — it observes, detects, correlates, and recommends. It is not an attack tool, and it never executes containment on your behalf.

> **Defensive use only.** Use SentinelFusion only on networks you own or are explicitly authorised to monitor.

---

## Highlights

- **Live capture** with per-process and per-endpoint attribution
- **Detection engine** — port/host scans, SYN floods, ARP spoofing, DNS tunnelling & DGA, C2 beaconing, data exfiltration, malicious TLS (JA3/JARM) fingerprints, cleartext credentials, rogue DHCP, and more
- **Process → connection mapping** that classifies what each link is *for* (game server, voice, matchmaking, anti-cheat, CDN, telemetry)
- **One-click endpoint enrichment** — geo, ASN, reputation, DNS history, flows, HTTP, link quality (RTT/jitter), passive OS & JARM fingerprints
- **Incident correlation** mapped to **MITRE ATT&CK** techniques
- **SOAR layer** — case management, trigger-based investigative playbooks, and an audit run-log (investigative only; it recommends containment, never performs it)
- **Machine-learning anomaly detection** — an Isolation Forest over flow features, with explainable per-endpoint reasons
- **Log ingestion** — syslog (RFC 3164/5424), Windows Event Log, and generic JSON/key-value logs correlated alongside packet detections
- **Digital forensics** — multi-source timelines, IOC extraction, and tamper-evident evidence bundles (SHA-256 manifests)
- **Feedback loop** — mark detections true/false positive to drive honest, directional threshold tuning
- **External integrations** — severity-gated outbound webhooks to Slack, Teams, or a SOAR/SIEM endpoint
- **Reporting** — case-centric and traffic PDF reports; CSV/JSON export
- **802.11 wireless IDS**, a live world map, and PCAP import/export

---

## Requirements

- **OS:** Windows (run as Administrator). Most features are cross-platform, but packet capture and the Windows Event Log source are Windows-oriented.
- **Python:** 3.10
- **Npcap:** required for live packet capture on Windows.
- **Python packages:** see [`requirements.txt`](requirements.txt).

```bash
python -m pip install -r requirements.txt
```

`tkinter` ships with the standard CPython installer and is not a pip package. `scikit-learn` powers the ML anomaly detection; `pywin32` (Windows only, optional) enables the Windows Event Log source. Features whose optional dependency is missing degrade gracefully rather than crash.

---

## Running

```bash
# From the project folder, in an Administrator terminal:
python app.py
```

> The entry point is **`app.py`**.

On first launch, open **Settings → Capture interface** and pick the adapter you want to watch, or leave it on *Automatic*. Traffic then fills the **Metrics** tab, and anything suspicious lands in **Alerts** with an explanation — accumulating into **Incidents** and **Cases** as related signals correlate.

To see detectors fire safely, generate traffic against *your own* devices — e.g. run a port scan from another machine you own, or open a plaintext HTTP-basic login. Never test against systems you do not control.

---

## The interface

Sixteen tabs, grouped by task:

| Group | Tabs |
|---|---|
| Live view | Metrics, Applications, Active, Connections, Flows |
| Network | WiFi, Network, Inspection |
| Detect & correlate | Alerts, Incidents, DNS, HTTP, Logs |
| Respond | Cases |
| Configure | Watchlist, Settings |

The **Settings → Operations** console gathers the analyst tooling: health self-check, the detection-rule catalog & tuning, ATT&CK coverage, threat-hunting playbooks, ML anomalies, detection feedback, log sources, integrations, and config export/import.

---

## Architecture

Data flows left to right, mirroring a SOC pipeline:

```
   Log ingestion ┐
Threat intel feeds ┼─► Detection engine ─► Correlation ─► Incidents ─► Cases (SOAR) ─┐
   Live capture ┘        (heuristics + ML)   (ATT&CK)      (playbooks)                │
                                                                                      ▼
                        Feedback loop ◄── Reporting ◄── Forensics ◄── Integrations ◄──┘
                        (tune the engine)   (PDF)       (evidence)     (webhooks out)
```

The codebase is ~60 focused modules using dependency injection throughout, so components are testable in isolation and free of import cycles. A few load-bearing ones:

- `app.py` — the Tkinter application and all tab/panel wiring
- `threat_detection.py` — the packet engine (capture, attribution, endpoint stats)
- `events.py` / `correlation.py` — the event bus and kill-chain correlation
- `db_manager.py` — the SQLite store (`incidents.db`)
- `detection_rules.py` / `mitre_attack.py` — the tunable rule catalog and ATT&CK mapping
- `case_manager.py` / `playbook_engine.py` — the SOAR layer
- `ml_anomaly.py` / `feedback_loop.py` — the ML detector and its tuning loop
- `log_ingest.py` / `log_sources.py` — external log aggregation
- `forensics.py` / `integrations.py` — evidence bundling and outbound notification

Full per-module documentation lives in **`SentinelFusion_Docs.html`** (open it in any browser). For a narrative walkthrough that follows one detection from packet to case, see **[`HOW_IT_WORKS.md`](HOW_IT_WORKS.md)**.

---

## Safety & scope

SentinelFusion is a **defensive** tool. Concretely:

- It **detects and analyses**; it does not attack. There is no exploitation or offensive tooling.
- The **SOAR automation is investigative only** — it enriches, correlates, gathers evidence, and *recommends* containment for a human to apply. It never changes a firewall rule or kills a process.
- **External integrations are one-directional** — SentinelFusion sends notifications out; it never receives commands back.
- **Credentials are masked** wherever they appear.
- **Wireless monitoring is detection-only** (deauth floods, rogue APs, evil twins).

Use it to understand and defend networks you are responsible for.

---

## License

This project is based on the original SentinelFusion by Yaron Bereza and is distributed under the **GNU Affero General Public License (AGPL)**. See the upstream project for the full license text.
