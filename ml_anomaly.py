"""ML anomaly detection - an unsupervised model over the traffic baseline.

The heuristic detectors (beaconing, exfil volume, scan counts) each look for one
specific known shape. This adds the complementary capability the architecture
diagram calls for: an unsupervised model that learns what *this* network's normal
endpoints look like and flags the ones that don't fit - without being told in
advance what "abnormal" means.

It uses an Isolation Forest (scikit-learn) over a handful of interpretable
per-endpoint features. Isolation Forest is a good fit here: it needs no labels,
handles the "mostly normal with rare outliers" shape of network data, and is
cheap to train and score. Crucially, we keep it *explainable* - alongside the
anomaly score we report which features are most unusual for that endpoint versus
the learned baseline, so an analyst sees *why* something scored high rather than
trusting a black box.

Honest scope: this finds statistical outliers, not "threats". An outlier might be
a backup server or a big download. It's a lead for investigation, surfaced with
its reasons, not a verdict. scikit-learn is imported lazily so the rest of the app
runs without it.
"""

import math
import threading

_lock = threading.Lock()
_model = None
_baseline = None      # dict of per-feature (mean, std) for explanation
_score_dist = (0.0, 1e-6)   # (mean, std) of baseline decision_function scores
_feature_names = ["log_bytes", "out_in_ratio", "log_packets", "distinct_ports",
                  "log_duration", "burstiness"]
_trained_n = 0


def _safe_log(x):
    return math.log10(x + 1.0)


def features_for(ep):
    """Turn one endpoint record into a fixed feature vector.

    `ep` is a dict like threat_detection.endpoint_stats values / enrichment
    totals: expects out_bytes, in_bytes, packets (or out_pkts+in_pkts), a set/len
    of ports, duration, and optionally a rate/burstiness signal.
    """
    out_b = float(ep.get("out_bytes", 0))
    in_b = float(ep.get("in_bytes", 0))
    total_b = out_b + in_b or float(ep.get("bytes", 0))
    ratio = (out_b / in_b) if in_b else (out_b if out_b else 0.0)
    ratio = min(ratio, 1000.0)  # cap the "pure upload" spike
    packets = float(ep.get("packets", ep.get("out_pkts", 0) + ep.get("in_pkts", 0)))
    ports = ep.get("ports", {})
    distinct_ports = float(len(ports) if hasattr(ports, "__len__") else (ports or 0))
    duration = float(ep.get("duration", 0) or 0)
    # burstiness: packets per second if we have duration, else 0
    burst = (packets / duration) if duration > 0 else 0.0
    return [
        _safe_log(total_b),
        _safe_log(ratio),
        _safe_log(packets),
        distinct_ports,
        _safe_log(duration),
        _safe_log(burst),
    ]


def train(endpoints, contamination=0.05):
    """Fit the model on a batch of endpoint records (the current baseline).

    contamination is the expected fraction of outliers in the baseline; 0.05 is a
    conservative default that keeps normal traffic from over-flagging. Returns the
    number of samples trained on, or 0 if sklearn is unavailable / too little data.
    """
    global _model, _baseline, _trained_n, _score_dist
    try:
        from sklearn.ensemble import IsolationForest
    except Exception:
        return 0
    vectors = [features_for(ep) for ep in endpoints if ep]
    if len(vectors) < 8:      # too little to learn a baseline
        return 0

    # per-feature mean/std for later explanation
    n = len(vectors)
    cols = list(zip(*vectors))
    baseline = {}
    for i, name in enumerate(_feature_names):
        col = cols[i]
        mean = sum(col) / n
        var = sum((v - mean) ** 2 for v in col) / n
        baseline[name] = (mean, math.sqrt(var) or 1e-6)

    model = IsolationForest(n_estimators=100, contamination=contamination,
                            random_state=42)
    model.fit(vectors)
    # Record the baseline decision-function distribution so scoring can express
    # "how far outside normal" on a stable 0-1 scale rather than raw values.
    try:
        base_scores = model.decision_function(vectors)
        bmean = sum(base_scores) / len(base_scores)
        bvar = sum((s - bmean) ** 2 for s in base_scores) / len(base_scores)
        bstd = math.sqrt(bvar) or 1e-6
    except Exception:
        bmean, bstd = 0.0, 1e-6
    with _lock:
        _model = model
        _baseline = baseline
        _trained_n = n
        _score_dist = (bmean, bstd)
    return n


def is_trained():
    with _lock:
        return _model is not None


def score(ep):
    """Score one endpoint. Returns {anomaly: bool, score: float 0-1, reasons:[...]}
    or None if the model isn't trained. Higher score = more anomalous."""
    with _lock:
        model, baseline, dist = _model, _baseline, _score_dist
    if model is None:
        return None
    vec = features_for(ep)
    try:
        raw = model.decision_function([vec])[0]
    except Exception:
        return None
    # Express anomaly relative to the baseline's own score distribution: how many
    # std-devs below the baseline mean (lower decision_function = more anomalous).
    bmean, bstd = dist
    z = (bmean - raw) / bstd
    anomaly_score = _squash(z)
    reasons = _explain(vec, baseline)
    is_anom = z >= 2.0      # clearly outside the normal band
    return {
        "anomaly": is_anom,
        "score": round(anomaly_score, 3),
        "reasons": reasons,
    }


def rank(endpoints, top=20):
    """Score many endpoints and return the most anomalous first."""
    out = []
    for ep in endpoints or []:
        s = score(ep)
        if s is not None:
            item = dict(s)
            item["ip"] = ep.get("ip") or ep.get("dst") or ""
            out.append(item)
    out.sort(key=lambda d: d["score"], reverse=True)
    return out[:top]


def _explain(vec, baseline):
    """Which features are most unusual vs the baseline (z-score), in words."""
    if not baseline:
        return []
    labels = {
        "log_bytes": "total volume",
        "out_in_ratio": "outbound/inbound ratio",
        "log_packets": "packet count",
        "distinct_ports": "number of ports",
        "log_duration": "connection duration",
        "burstiness": "packet rate",
    }
    zs = []
    for i, name in enumerate(_feature_names):
        mean, std = baseline.get(name, (0, 1e-6))
        z = (vec[i] - mean) / std
        zs.append((abs(z), name, z))
    zs.sort(reverse=True)
    reasons = []
    for absz, name, z in zs[:3]:
        if absz < 1.5:      # not actually unusual
            continue
        direction = "unusually high" if z > 0 else "unusually low"
        shown = f"{absz:.1f}\u03c3" if absz < 100 else ">100\u03c3"
        reasons.append(f"{labels.get(name, name)} {direction} ({shown})")
    return reasons


def _squash(z):
    # logistic over the baseline-relative z-score: z=0 (baseline mean) -> 0.5,
    # z=2 (edge of normal) -> ~0.75, large outliers approach 1.0.
    return 1.0 / (1.0 + math.exp(-0.9 * z))


def status():
    with _lock:
        return {"trained": _model is not None, "samples": _trained_n,
                "features": list(_feature_names)}
