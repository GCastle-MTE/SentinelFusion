"""CVE lookup - ask NIST's NVD what is known about a specific software version.

This is the vulnerability-management half of asset discovery: once the scanner
knows a host on your network runs OpenSSH 8.2p1, this asks the National
Vulnerability Database which published CVEs cover that exact version, and how
severe they are, so you know what to patch.

Two design choices matter here, and both exist to keep the output trustworthy:

**Query by CPE, not by keyword.** The NVD API accepts a `cpeName` parameter and
applies its own version-range logic server-side, returning only CVEs whose
affected-version ranges actually include the version we pass. A keyword search
for "apache" instead returns every CVE that ever mentioned Apache - hundreds,
almost all irrelevant to the running version. Precision here is the whole point;
a vulnerability report nobody trusts gets ignored.

**Respect the rate limit and cache hard.** NVD allows roughly 5 requests per 30
seconds unauthenticated, 50 with a free API key. A scan of a modest LAN can
easily need a hundred lookups, so results are cached to disk with a TTL and
requests are spaced automatically. Without this the API simply starts refusing.

Findings are advisory. A version match means "this version is covered by a
published CVE" - not "this host is definitely exploitable". Distributions
routinely backport fixes without changing the version string, so a finding is a
prompt to verify and patch, never a confirmed weakness. No exploit code, proof
of concept, or attack tooling is included or intended: the output is a patch
list for systems you are responsible for.

The HTTP client is injected, so every code path here is testable offline.
"""

import os
import json
import time
import threading

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's published guidance: ~5 requests / 30s without a key, ~50 with one.
# We space requests conservatively rather than racing the limiter.
_INTERVAL_NO_KEY = 6.5
_INTERVAL_WITH_KEY = 0.8

CACHE_TTL = 24 * 3600          # a day; CVE data does not change by the minute
_CACHE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "cve_cache.json")

SEVERITY_ORDER = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

_lock = threading.Lock()
_cache = None
_api_key = ""
_last_request = 0.0


def set_api_key(key):
    """Supply a free NVD API key to raise the rate limit."""
    global _api_key
    _api_key = (key or "").strip()


def has_api_key():
    return bool(_api_key)


# --- cache -----------------------------------------------------------------

def _load_cache():
    global _cache
    if _cache is not None:
        return _cache
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
    except Exception:
        _cache = {}
    return _cache


def _save_cache():
    try:
        with open(_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache or {}, f)
    except Exception:
        pass


def cached_result(cpe):
    """Return a cached result for a CPE if it is still fresh, else None."""
    with _lock:
        cache = _load_cache()
        entry = cache.get(cpe)
    if not entry:
        return None
    if time.time() - entry.get("fetched", 0) > CACHE_TTL:
        return None
    return entry.get("cves")


def clear_cache():
    global _cache
    with _lock:
        _cache = {}
        _save_cache()


def cache_stats():
    with _lock:
        cache = _load_cache()
        fresh = sum(1 for e in cache.values()
                    if time.time() - e.get("fetched", 0) <= CACHE_TTL)
        return {"entries": len(cache), "fresh": fresh}


# --- lookup ----------------------------------------------------------------

def lookup(cpe, *, http=None, use_cache=True, timeout=20, broad=False,
           released=None):
    """Fetch CVEs affecting one CPE.

    `broad=True` queries by virtualMatchString instead of cpeName. cpeName does
    an exact comparison against the match criteria in each CVE, which is right
    for a precise version like OpenSSH 9.5 but returns nothing for a CPE whose
    version is a wildcard. Products indexed per patch revision - Windows above
    all - can only be matched at product level, and that needs the virtual form.

    `released` is an ISO date for when the detected version shipped. When given,
    CVEs published before it are marked suspect: they usually indicate an
    over-broad version range in the CVE record rather than a real exposure.

    Returns {ok, cves, cached, error}. Never raises.
    """
    if not cpe:
        return {"ok": False, "cves": [], "cached": False, "error": "no CPE"}

    cache_key = ("v:" if broad else "e:") + cpe
    if use_cache:
        hit = cached_result(cache_key)
        if hit is not None:
            return {"ok": True, "cves": _flag_suspect(hit, released),
                    "cached": True, "error": None}

    if http is None:
        try:
            import requests as http
        except Exception:
            return {"ok": False, "cves": [], "cached": False,
                    "error": "requests not available"}

    _throttle()
    headers = {"apiKey": _api_key} if _api_key else {}
    param = "virtualMatchString" if broad else "cpeName"
    try:
        resp = http.get(NVD_ENDPOINT, params={param: cpe},
                        headers=headers, timeout=timeout)
        code = getattr(resp, "status_code", None)
        if code in (403, 429):
            return {"ok": False, "cves": [], "cached": False,
                    "error": f"rate limited by NVD (HTTP {code}) - "
                             "add an API key or slow the scan"}
        if code != 200:
            return {"ok": False, "cves": [], "cached": False,
                    "error": f"HTTP {code}"}
        payload = resp.json()
    except Exception as exc:
        return {"ok": False, "cves": [], "cached": False, "error": str(exc)}

    cves = parse_nvd_response(payload)
    with _lock:
        cache = _load_cache()
        cache[cache_key] = {"fetched": time.time(), "cves": cves}
        _save_cache()
    return {"ok": True, "cves": _flag_suspect(cves, released), "cached": False,
            "error": None}


def _flag_suspect(cves, released):
    """Mark CVEs published before the running version existed.

    A 2008 advisory cannot describe a flaw in software released in 2023. When
    one appears, the cause is almost always a CVE record whose affected-version
    range is wider than reality. Flagging rather than dropping keeps the analyst
    in control - occasionally an old CVE genuinely resurfaces as a regression.
    """
    if not released:
        return cves
    out = []
    for c in cves:
        c = dict(c)
        pub = (c.get("published") or "")[:10]
        c["suspect"] = bool(pub and pub < released)
        out.append(c)
    return out


def parse_nvd_response(payload):
    """Normalize an NVD 2.0 response into a list of findings.

    The 2.0 schema nests each record as vulnerabilities[].cve - note this differs
    from the retired 1.0 schema (result.CVE_Items), which is a common source of
    silent empty results when code written for 1.0 is pointed at the 2.0 endpoint.
    """
    out = []
    if not isinstance(payload, dict):
        return out
    for item in payload.get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        score, severity, vector = _best_metric(cve.get("metrics") or {})
        out.append({
            "id": cve_id,
            "description": _english(cve.get("descriptions") or []),
            "severity": severity,
            "score": score,
            "vector": vector,
            "published": (cve.get("published") or "")[:10],
            "modified": (cve.get("lastModified") or "")[:10],
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    out.sort(key=lambda c: (_sev_rank(c["severity"]), c["score"] or 0),
             reverse=True)
    return out


def _best_metric(metrics):
    """Pick the most authoritative CVSS metric available.

    Preference order runs newest to oldest, since NVD populates several and the
    newer scoring systems are the ones defenders are expected to act on.
    """
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = (entries[0] or {}).get("cvssData") or {}
            return (data.get("baseScore"),
                    (data.get("baseSeverity") or "").upper(),
                    data.get("vectorString", ""))
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        entry = entries[0] or {}
        data = entry.get("cvssData") or {}
        return (data.get("baseScore"),
                (entry.get("baseSeverity") or "").upper(),
                data.get("vectorString", ""))
    return (None, "", "")


def _english(descriptions):
    for d in descriptions:
        if (d or {}).get("lang") == "en":
            return (d.get("value") or "").strip()
    return (descriptions[0].get("value", "").strip() if descriptions else "")


# --- scanning a whole host -------------------------------------------------

def assess_products(products, *, http=None, use_cache=True, max_lookups=25):
    """Look up every versioned product identity from service_fingerprint.

    Only identities with confidence 'high' (a real parsed version) are queried -
    a product without a version cannot be assessed, and guessing would produce
    exactly the false-positive noise this design avoids.

    Returns a list of {product, cpe, cves, error, skipped}.
    """
    results = []
    lookups = 0
    for p in products or []:
        label = p.get("label") or p.get("product", "?")
        if p.get("confidence") != "high" or not p.get("cpe"):
            results.append({
                "product": label, "version": p.get("version", ""), "cpe": "",
                "cves": [], "error": None, "skipped": True,
                "reason": "version not disclosed - cannot assess",
            })
            continue
        if lookups >= max_lookups:
            results.append({
                "product": label, "version": p.get("version", ""),
                "cpe": p["cpe"], "cves": [], "error": None, "skipped": True,
                "reason": "lookup budget reached for this scan",
            })
            continue
        lookups += 1
        res = lookup(p["cpe"], http=http, use_cache=use_cache,
                     broad=bool(p.get("cpe_broad")),
                     released=p.get("released"))
        results.append({
            "product": label, "version": p.get("version", ""), "cpe": p["cpe"],
            "cves": res["cves"], "error": res["error"], "skipped": False,
            "cached": res.get("cached", False),
            "precision": p.get("precision", "version"),
            "platform_note": p.get("platform_note", ""),
        })
    return results


def risk_rollup(assessments):
    """Summarize a host's assessments into one risk picture.

    Exact-version findings and release-level findings are counted separately.
    Adding them produces a number that looks like exposure but isn't: a release's
    CVE history runs to four figures and says nothing about whether this host is
    patched. Only exact-version matches belong in an exposure count.
    """
    total = 0
    context = 0
    worst = ""
    worst_score = 0.0
    by_sev = {}
    unassessed = 0
    for a in assessments or []:
        if a.get("skipped"):
            unassessed += 1
            continue
        if a.get("precision") == "release":
            context += len(a.get("cves") or [])
            continue
        for c in a.get("cves") or []:
            total += 1
            sev = c.get("severity") or "NONE"
            by_sev[sev] = by_sev.get(sev, 0) + 1
            if _sev_rank(sev) > _sev_rank(worst):
                worst = sev
            if (c.get("score") or 0) > worst_score:
                worst_score = c.get("score") or 0
    return {
        "total_cves": total, "worst_severity": worst or "NONE",
        "worst_score": worst_score, "by_severity": by_sev,
        "unassessed_services": unassessed,
        "release_context_cves": context,
    }


def summarize(assessments, limit=5):
    """Plain-language lines for a vulnerability panel or report."""
    roll = risk_rollup(assessments)
    if not assessments:
        return ["No services identified to assess."]
    lines = []
    if roll["total_cves"]:
        counts = ", ".join(f"{k.title()} {v}" for k, v in
                           sorted(roll["by_severity"].items(),
                                  key=lambda kv: -_sev_rank(kv[0])))
        lines.append(f"{roll['total_cves']} CVE(s) matched an exact service "
                     f"version - worst {roll['worst_severity'].title()} "
                     f"({roll['worst_score']}).")
        lines.append(f"   {counts}")
    else:
        lines.append("No CVEs matched an exact service version.")
    if roll.get("release_context_cves"):
        lines.append(f"Plus {roll['release_context_cves']} recorded against an "
                     "OS release identified here - history for context, not "
                     "this host's exposure (see below).")
    if roll["unassessed_services"]:
        lines.append(f"{roll['unassessed_services']} service(s) could not be "
                     "assessed (no version disclosed).")
    lines.append("")
    for a in assessments:
        if a.get("skipped"):
            lines.append(f"{a['product']} - {a.get('reason', 'not assessed')}")
            continue
        if a.get("error"):
            lines.append(f"{a['product']} {a['version']} - lookup failed: {a['error']}")
            continue
        cves = a.get("cves") or []
        if not cves:
            lines.append(f"{a['product']} {a['version']} - no known CVEs.")
            continue
        suspect_n = sum(1 for c in cves if c.get("suspect"))

        if a.get("precision") == "release":
            # Unauthenticated OS CVE enumeration is not an assessment. Windows
            # ships 50-100 CVEs a month, so any recency window still yields
            # hundreds, and none of them can be confirmed against a host whose
            # patch revision we cannot see. Real scanners authenticate and read
            # the installed update level instead. Report what we genuinely know -
            # the release - and point at what would actually answer the question.
            lines.append(f"{a['product']} {a['version']}")
            lines.append("   Identified over SMB. The patch revision is not "
                         "disclosed, so exposure cannot be assessed remotely.")
            recent = _recent(cves, 30)
            lines.append(f"   Context: {len(cves)} CVEs recorded against this "
                         f"release, {len(recent)} in the last 30 days.")
            lines.append("   To assess it: check Windows Update on the host, or "
                         "compare its build (winver) against Microsoft's "
                         "release-health page.")
            continue

        head = f"{a['product']} {a['version']} - {len(cves)} CVE(s):"
        lines.append(head)
        if a.get("platform_note"):
            lines.append(f"   NOTE: {a['platform_note']}")
        for c in cves[:limit]:
            lines.append("   " + _cve_line(c))
        if len(cves) > limit:
            lines.append(f"   ... and {len(cves) - limit} more")
        if suspect_n:
            lines.append(f"   {suspect_n} of these predate the running version "
                         "and are probably not applicable.")
    lines.append("")
    lines.append("Findings are advisory: distributions often backport fixes "
                 "without changing the version string. Verify against your "
                 "vendor's advisories before treating one as confirmed.")
    return lines


def _throttle():
    """Space requests so we stay inside NVD's published rate limits."""
    global _last_request
    interval = _INTERVAL_WITH_KEY if _api_key else _INTERVAL_NO_KEY
    with _lock:
        wait = interval - (time.time() - _last_request)
        if wait > 0:
            time.sleep(wait)
        _last_request = time.time()


def _sev_rank(sev):
    try:
        return SEVERITY_ORDER.index((sev or "NONE").upper())
    except ValueError:
        return 0




def _recent(cves, days):
    """CVEs published within the last `days`, newest first."""
    cutoff = time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))
    out = [c for c in cves if (c.get("published") or "")[:10] >= cutoff]
    out.sort(key=lambda c: c.get("published") or "", reverse=True)
    return out


def _cve_line(c):
    sev = c.get("severity") or "?"
    score = c["score"] if c.get("score") is not None else "-"
    date = (c.get("published") or "")[:10] or "?"
    mark = ("  <- predates this product line, likely an over-broad record"
            if c.get("suspect") else "")
    desc = (c.get("description") or "")[:95]
    return f"   {c['id']}  [{sev} {score}]  ({date})  {desc}{mark}"
