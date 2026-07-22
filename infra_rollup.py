"""Infrastructure rollup - who owns everything you're talking to?

Individually, thirty external IPs are noise. Grouped by the organization that owns
them, a shape appears: "14 endpoints on Amazon, 3 on Cloudflare, 1 on i3D.net (a
game host), 1 on an ISP in another country you've never talked to." The outlier -
the single host that doesn't belong to a big known cloud - is usually the
interesting one.

This rolls the current endpoints up by ASN / ISP, counts hosts and bytes per org,
and marks orgs that are new or that hold only a single lonely host (which stands
out against clusters of cloud infrastructure). Injected geo source, so it's
testable and cycle-free.
"""


def rollup(endpoints, *, geo_lookup=None, novelty=None):
    """Group endpoint dicts by owning org. Each endpoint needs at least 'ip';
    optionally 'in_bytes'/'out_bytes'/'host'/'role'.

    Returns a list of org groups sorted by total bytes, each:
        {org, asn, hosts:[...], host_count, bytes, roles:{...}, is_new, singleton}
    """
    groups = {}
    for ep in endpoints or []:
        ip = ep.get("ip")
        if not ip:
            continue
        asn = isp = ""
        if geo_lookup is not None:
            try:
                g = geo_lookup.get(ip) or {}
                asn, isp = g.get("asn", ""), g.get("isp", "")
            except Exception:
                pass
        org = isp or asn or "unknown"
        grp = groups.setdefault(org, {
            "org": org, "asn": asn, "hosts": [], "bytes": 0,
            "roles": {}, "is_new": False,
        })
        grp["hosts"].append({"ip": ip, "host": ep.get("host", ""),
                             "role": ep.get("role", ""),
                             "bytes": ep.get("in_bytes", 0) + ep.get("out_bytes", 0)})
        grp["bytes"] += ep.get("in_bytes", 0) + ep.get("out_bytes", 0)
        role = ep.get("role")
        if role:
            grp["roles"][role] = grp["roles"].get(role, 0) + 1
        if novelty is not None and asn:
            try:
                if novelty.is_new("asn", asn):
                    grp["is_new"] = True
            except Exception:
                pass

    out = []
    for grp in groups.values():
        grp["host_count"] = len(grp["hosts"])
        grp["singleton"] = grp["host_count"] == 1
        grp["hosts"].sort(key=lambda h: h["bytes"], reverse=True)
        out.append(grp)
    out.sort(key=lambda g: g["bytes"], reverse=True)
    return out


def summarize(groups):
    """Plain-language lines describing the infrastructure spread."""
    if not groups:
        return ["No external infrastructure observed yet."]
    total_hosts = sum(g["host_count"] for g in groups)
    lines = [f"{total_hosts} endpoint(s) across {len(groups)} organization(s):"]
    for g in groups[:12]:
        tag = ""
        if g.get("is_new"):
            tag += "  [NEW]"
        if g["singleton"]:
            tag += "  [single host]"
        roles = ", ".join(sorted(g["roles"])) if g["roles"] else ""
        role_txt = f"  - {roles}" if roles else ""
        lines.append(f"  {g['org']}: {g['host_count']} host(s), "
                     f"{_mb(g['bytes'])}{role_txt}{tag}")
    return lines


def outliers(groups):
    """Orgs worth a second look: single-host orgs that aren't big clouds, and
    anything freshly appeared. These are the ones that stand out from clusters."""
    _BIG = ("amazon", "google", "microsoft", "cloudflare", "akamai", "fastly",
            "apple", "meta", "facebook", "ovh", "azure", "aws")
    flagged = []
    for g in groups:
        org_low = g["org"].lower()
        big = any(b in org_low for b in _BIG)
        if g.get("is_new") or (g["singleton"] and not big and g["org"] != "unknown"):
            flagged.append(g)
    return flagged


def _mb(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
