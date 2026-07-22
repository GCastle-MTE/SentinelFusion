"""Match TLS JA3 fingerprints against a blocklist of known-bad fingerprints.

JA3 hashes a TLS ClientHello (its cipher suites, extensions, and curves) into an
md5. Many malware families and offensive tools have recognisable JA3s, so
checking a captured handshake's JA3 against a blocklist turns the fingerprint we
already collect from informational into an actual detection.

We ship NO fabricated fingerprints. Drop a blocklist file next to the app and it
loads automatically. Recognised names: ja3_fingerprints.txt / ja3_fingerprints.csv
(or ja3.txt / ja3.csv), or point the Settings field at any file. The format is
forgiving:
  - one md5 per line, OR
  - CSV lines like "md5,description[,...]" (abuse.ch's JA3 export works as-is),
  - '#' starts a comment; blank lines are ignored.

Where to get a list: abuse.ch SSLBL's JA3 export, or curated JA3 lists on GitHub.
Caveat: some JA3s are shared by legitimate software built on the same TLS stack,
so treat a single JA3 match as a lead to investigate, not proof of compromise.
"""

import os
import re
import threading

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_NAMES = ("ja3_fingerprints.txt", "ja3_fingerprints.csv", "ja3.txt", "ja3.csv")
_MD5 = re.compile(r"\b([0-9a-fA-F]{32})\b")

_lock = threading.Lock()
_db = {}            # ja3_md5 (lowercase) -> description
_source = None      # path actually loaded, or None
_extra_path = None  # user-configured file (from Settings)


def _parse_line(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    m = _MD5.search(line)
    if not m:
        return None
    ja3 = m.group(1).lower()
    rest = (line[:m.start()] + line[m.end():]).strip(" ,;\t\"'")
    return ja3, (rest or "known-bad JA3")


def configure(path):
    global _extra_path
    _extra_path = path.strip() if isinstance(path, str) and path.strip() else None
    reload()


def _candidate_files():
    files = []
    if _extra_path:
        files.append(_extra_path)
    for n in _DEFAULT_NAMES:
        files.append(os.path.join(_APP_DIR, n))
        files.append(os.path.join(_APP_DIR, "ja3", n))
    return files


def reload():
    global _db, _source
    with _lock:
        db, src = {}, None
        for path in _candidate_files():
            try:
                if not os.path.isfile(path):
                    continue
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parsed = _parse_line(line)
                        if parsed:
                            db[parsed[0]] = parsed[1]
                if db:
                    src = path
                    break
            except Exception:
                continue
        _db, _source = db, src


def is_bad(ja3):
    if not ja3:
        return None
    with _lock:
        return _db.get(str(ja3).lower())


def count():
    with _lock:
        return len(_db)


def status():
    with _lock:
        return {"count": len(_db), "source": _source}


# Best-effort load at import.
reload()
