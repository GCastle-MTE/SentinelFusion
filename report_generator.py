# report_generator.py
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.utils import simpleSplit


def _safe(s):
    # Keep text within what the standard PDF fonts can render.
    return str(s).encode("latin-1", "replace").decode("latin-1")


def _page_break_if_needed(c, y, height, min_y=90, font=("Helvetica", 11)):
    # Start a new page when we run low on vertical space.
    if y < min_y:
        c.showPage()
        c.setFont(*font)
        return height - 72
    return y


def _draw_wrapped(c, text, x, y, height, width=450, font=("Helvetica", 11)):
    # Draw possibly-long text across multiple lines, paginating as needed.
    for line in simpleSplit(_safe(text), font[0], font[1], width):
        y = _page_break_if_needed(c, y, height, font=font)
        c.drawString(x, y, line)
        y -= 14
    return y


def _section(c, y, height, title):
    # Paginate if low, then draw a bold section header. Returns new y.
    y = _page_break_if_needed(c, y, height, min_y=120)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, y, _safe(title))
    c.setFont("Helvetica", 11)
    return y - 20


def generate_pdf_report(incidents, traffic=None, devices=None, captures=None,
                        alerts=None, watchlist_rules=None):
    # Accept either a single incident dict or a list of them.
    if isinstance(incidents, dict):
        incidents = [incidents]

    c = canvas.Canvas("./report.pdf", pagesize=letter)
    height = letter[1]  # only the page height is needed for layout

    c.setFont("Helvetica", 24)
    c.drawString(72, height - 72, "Incident Report")
    y = height - 104

    # --- Traffic summary section ---
    if traffic:
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, y, "Traffic summary")
        y -= 20

        c.setFont("Helvetica", 11)
        c.drawString(
            72, y,
            f"Total packets: {traffic.get('total_packets', 0)}    "
            f"Unique sources: {traffic.get('unique_sources', 0)}",
        )
        y -= 16

        by_scope = traffic.get("by_scope", {})
        if by_scope:
            scope_str = ", ".join(f"{k}: {v}" for k, v in by_scope.items())
            c.drawString(72, y, _safe(f"Grouped by scope -> {scope_str}"))
            y -= 16

        protocols = traffic.get("protocols", {})
        if protocols:
            ordered = sorted(protocols.items(), key=lambda kv: kv[1], reverse=True)
            proto_str = ", ".join(f"{k}: {v}" for k, v in ordered)
            y = _draw_wrapped(c, f"Protocols -> {proto_str}", 72, y, height, width=460)
            y -= 2

        by_process = traffic.get("by_process", [])
        if by_process:
            c.drawString(72, y, "Traffic by application:")
            y -= 16
            for name, cnt in by_process:
                y = _page_break_if_needed(c, y, height)
                c.drawString(90, y, _safe(f"{name}: {cnt} packets"))
                y -= 14
            y -= 6

        by_country = traffic.get("by_country", {})
        if by_country:
            c.drawString(72, y, "External traffic by country:")
            y -= 16
            ordered = sorted(by_country.items(), key=lambda kv: kv[1], reverse=True)
            for country, cnt in ordered:
                y = _page_break_if_needed(c, y, height)
                c.drawString(90, y, _safe(f"{country}: {cnt} packets"))
                y -= 14
            y -= 6

        top_external = traffic.get("top_external", [])
        if top_external:
            c.drawString(72, y, "Top external endpoints:")
            y -= 16
            for row in top_external:
                ip, cnt, country, isp = row[0], row[1], row[2], row[3]
                asn = row[4] if len(row) > 4 else ""
                y = _page_break_if_needed(c, y, height)
                label = f"{ip}  -  {cnt} pkts  [{country}]"
                if isp:
                    label += f"  {isp}"
                if asn:
                    label += f"  ({asn})"
                c.drawString(90, y, _safe(label))
                y -= 14
            y -= 6

        top = traffic.get("top_sources", [])
        if top:
            c.drawString(72, y, "Top sources (all traffic):")
            y -= 16
            for ip, cnt in top:
                y = _page_break_if_needed(c, y, height)
                c.drawString(90, y, _safe(f"{ip}  -  {cnt} packets"))
                y -= 14
            y -= 10

    # --- Detections & alerts section ---
    if alerts is not None:
        y = _section(c, y, height, "Detections & alerts")
        n_alert = sum(1 for e in alerts if e.get("severity") == "ALERT")
        n_warn = sum(1 for e in alerts if e.get("severity") == "WARNING")
        by_cat = {}
        for e in alerts:
            by_cat[e.get("category", "?")] = by_cat.get(e.get("category", "?"), 0) + 1
        c.drawString(72, y, _safe(f"Total: {n_alert} alerts, {n_warn} warnings"))
        y -= 16
        if by_cat:
            ordered = sorted(by_cat.items(), key=lambda kv: kv[1], reverse=True)
            cat_str = ", ".join(f"{k}: {v}" for k, v in ordered)
            y = _draw_wrapped(c, f"By category -> {cat_str}", 72, y, height, width=460)
            y -= 2
        if alerts:
            c.drawString(72, y, "Most recent:")
            y -= 16
            for e in list(alerts)[-40:][::-1]:
                y = _page_break_if_needed(c, y, height)
                line = (f"[{e.get('stamp', '')}] {e.get('severity', '')}/"
                        f"{e.get('category', '')}  {e.get('source', '')} - {e.get('message', '')}")
                y = _draw_wrapped(c, line, 90, y, height, width=440, font=("Helvetica", 10))
            y -= 6
        else:
            c.drawString(72, y, "No alerts recorded this session.")
            y -= 16

    # --- Watchlist section ---
    if watchlist_rules:
        y = _section(c, y, height, "Watchlist rules")
        for r in watchlist_rules:
            y = _page_break_if_needed(c, y, height)
            line = f"{r.get('kind', '')} = {r.get('value', '')}"
            if r.get("note"):
                line += f"   ({r['note']})"
            c.drawString(90, y, _safe(line))
            y -= 14
        y -= 6

    # --- Network devices section ---
    if devices:
        y = _page_break_if_needed(c, y, height, min_y=120)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, y, "Devices on the network")
        y -= 20
        c.setFont("Helvetica", 11)
        for d in devices:
            y = _page_break_if_needed(c, y, height)
            label = d.get("hostname") or d.get("vendor") or ""
            line = f"{d.get('ip', '')}  {d.get('mac', '')}"
            if label:
                line += f"  {label}"
            c.drawString(90, y, _safe(line))
            y -= 14
        y -= 10

    # --- Stored captures section ---
    if captures:
        y = _page_break_if_needed(c, y, height, min_y=120)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(72, y, "Stored target captures")
        y -= 20
        c.setFont("Helvetica", 11)
        for cap in captures:
            y = _page_break_if_needed(c, y, height)
            c.drawString(
                90, y,
                _safe(
                    f"[{cap.get('captured_at', '')}] {cap.get('target', '')} - "
                    f"{cap.get('packet_count', 0)} pkts"
                ),
            )
            y -= 14
            path = cap.get("pcap_path") or ""
            if path:
                y = _draw_wrapped(c, f"file: {path}", 108, y, height, width=420)
            dpi_summary = cap.get("dpi_summary") or ""
            if dpi_summary:
                y = _draw_wrapped(c, f"DPI: {dpi_summary}", 108, y, height, width=420)
            y -= 4
        y -= 6

    # --- Incidents section ---
    y = _page_break_if_needed(c, y, height, min_y=120)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(72, y, "Incidents")
    y -= 20

    c.setFont("Helvetica", 11)
    if not incidents:
        c.drawString(72, y, "No incidents recorded.")
        y -= 16

    for i, incident in enumerate(incidents, start=1):
        status = _safe(incident.get("status", ""))
        details = incident.get("details", "")
        intel = incident.get("threat_intelligence")

        y = _page_break_if_needed(c, y, height)
        c.drawString(72, y, f"{i}. Status: {status}")
        y -= 16
        y = _draw_wrapped(c, f"Details: {details}", 90, y, height)
        if intel is not None:
            y = _draw_wrapped(c, f"Threat intel: {intel}", 90, y, height)
        y -= 6

    c.save()


def generate_case_report(case, *, path=None, techniques=None, metrics=None,
                         notes=None, actions=None, enrichment_lines=None):
    """Produce a professional, case-centric PDF an analyst can hand off.

    `case` is a case row dict. Optional extras: ATT&CK `techniques` (list of
    {id,name,tactic}), SOC `metrics` lines, the case `notes` timeline, recommended
    `actions`, and `enrichment_lines` for the actor. Returns the output path.
    """
    from reportlab.lib.pagesizes import letter as _letter
    path = path or f"./case_{case.get('id', 'report')}.pdf"
    c = canvas.Canvas(path, pagesize=_letter)
    width, height = _letter
    y = height - 72

    # Title block.
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, y, _safe(f"Incident Case Report  -  Case #{case.get('id', '?')}"))
    y -= 24
    c.setFont("Helvetica", 10)
    c.drawString(72, y, _safe(f"Generated {case.get('updated_at', '')}   "
                              f"SentinelFusion"))
    y -= 26

    # Summary table-ish block.
    c.setFont("Helvetica-Bold", 12)
    for label, val in (("Title", case.get("title", "")),
                       ("Actor", case.get("actor", "")),
                       ("Severity", case.get("severity", "")),
                       ("Status", case.get("status", "")),
                       ("Assignee", case.get("assignee", "") or "-"),
                       ("Score", case.get("score", "")),
                       ("Opened", case.get("created_at", ""))):
        y = _page_break_if_needed(c, y, height)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(72, y, _safe(f"{label}:"))
        c.setFont("Helvetica", 11)
        c.drawString(160, y, _safe(str(val)))
        y -= 15
    y -= 8

    y = _section(c, y, height, "Summary")
    y = _draw_wrapped(c, case.get("summary", "") or "-", 72, y, height)
    y -= 8

    if techniques:
        y = _section(c, y, height, "MITRE ATT&CK techniques")
        for t in techniques:
            y = _page_break_if_needed(c, y, height)
            c.drawString(90, y, _safe(f"{t['id']}  {t['name']}  ({t['tactic']})"))
            y -= 14
        y -= 8

    if enrichment_lines:
        y = _section(c, y, height, "Actor enrichment")
        for line in enrichment_lines:
            y = _draw_wrapped(c, line, 90, y, height)
        y -= 8

    if actions:
        y = _section(c, y, height, "Recommended actions")
        for a in actions:
            mark = "[applied]" if a.get("applied") else "[ ]"
            y = _draw_wrapped(c, f"{mark} {a.get('action', '')} - {a.get('detail', '')}",
                              90, y, height)
        y -= 8

    if notes:
        y = _section(c, y, height, "Investigation timeline")
        for n in notes:
            y = _draw_wrapped(c, f"{n.get('ts', '')}  {n.get('text', '')}", 90, y, height)
        y -= 8

    if metrics:
        y = _section(c, y, height, "SOC metrics at time of report")
        for line in metrics:
            y = _draw_wrapped(c, line, 90, y, height)

    c.save()
    return path
