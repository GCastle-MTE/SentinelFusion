"""Log sources - the listeners that feed log_ingest.

These are deliberately thin wrappers around real OS facilities: a UDP syslog
server, a file tailer, and a Windows Event Log reader. Each runs on a background
thread, parses every line/record via log_ingest, and hands the normalized record
to a callback (typically one that forwards security-relevant records into the
events pipeline).

The parsing is tested in log_ingest; the socket / file / Event Log plumbing here
needs a real machine to exercise, so it's kept minimal and defensive. Nothing
here blocks the UI - all loops are daemon threads that stop on a flag.
"""

import os
import time
import threading

import log_ingest

_running = {}      # name -> stop Event


def _mark(name):
    ev = threading.Event()
    _running[name] = ev
    return ev


def stop(name=None):
    """Stop one source by name, or all if name is None."""
    for n, ev in (list(_running.items()) if name is None else [(name, _running.get(name))]):
        if ev is not None:
            ev.set()


def running():
    return [n for n, ev in _running.items() if not ev.is_set()]


# --- syslog UDP server -----------------------------------------------------

def start_syslog_server(callback, host="0.0.0.0", port=5514):
    """Listen for syslog datagrams and hand each parsed record to `callback`.

    Port 514 is the standard but needs privilege; 5514 is a safe default. Returns
    the thread, or None if the socket couldn't be opened.
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.settimeout(1.0)
    except Exception as exc:
        print(f"syslog server bind failed on {host}:{port}: {exc}")
        return None

    stop_ev = _mark("syslog")

    def loop():
        while not stop_ev.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except Exception:
                break
            for line in data.decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = log_ingest.parse_syslog(line)
                    if not rec.get("host"):
                        rec["host"] = addr[0]
                    callback(rec)
                except Exception:
                    pass
        try:
            sock.close()
        except Exception:
            pass

    t = threading.Thread(target=loop, daemon=True, name="syslog-server")
    t.start()
    return t


# --- file tailer -----------------------------------------------------------

def start_file_tail(path, callback, source="applog", from_start=False):
    """Tail a growing log file, parsing each new line via parse_generic.

    Handles rotation crudely (if the file shrinks, re-open). Returns the thread,
    or None if the path doesn't exist.
    """
    if not os.path.exists(path):
        print(f"file tail: {path} does not exist")
        return None

    stop_ev = _mark(f"file:{os.path.basename(path)}")

    def loop():
        pos = 0 if from_start else os.path.getsize(path)
        while not stop_ev.is_set():
            try:
                size = os.path.getsize(path)
                if size < pos:      # rotated/truncated
                    pos = 0
                if size > pos:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(pos)
                        for line in f:
                            line = line.rstrip("\n")
                            if line.strip():
                                try:
                                    callback(log_ingest.parse_generic(line, source=source))
                                except Exception:
                                    pass
                        pos = f.tell()
            except Exception:
                pass
            time.sleep(1.0)

    t = threading.Thread(target=loop, daemon=True, name=f"tail-{os.path.basename(path)}")
    t.start()
    return t


# --- Windows Event Log reader ----------------------------------------------

def start_windows_eventlog(callback, channels=("Security", "System"), poll=5.0):
    """Poll Windows Event Log channels for new records (needs pywin32 on Windows).

    Best-effort: if pywin32 isn't present (e.g. non-Windows or missing dep), this
    returns None and logs why. Each record is normalized via parse_windows_event.
    """
    try:
        import win32evtlog
    except Exception as exc:
        print(f"Windows Event Log unavailable (pywin32 not present): {exc}")
        return None

    stop_ev = _mark("wineventlog")

    def loop():
        handles = {}
        for ch in channels:
            try:
                handles[ch] = win32evtlog.OpenEventLog(None, ch)
            except Exception:
                pass
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        seen_latest = {ch: None for ch in handles}
        while not stop_ev.is_set():
            for ch, h in handles.items():
                try:
                    events = win32evtlog.ReadEventLog(h, flags, 0)
                    for ev in (events or [])[:50]:
                        rec_num = getattr(ev, "RecordNumber", None)
                        if seen_latest[ch] is not None and rec_num is not None \
                                and rec_num <= seen_latest[ch]:
                            continue
                        evt = {
                            "Channel": ch,
                            "EventID": getattr(ev, "EventID", "") & 0xFFFF,
                            "Level": _win_level(getattr(ev, "EventType", 0)),
                            "Provider": str(getattr(ev, "SourceName", "")),
                            "Computer": str(getattr(ev, "ComputerName", "")),
                            "Message": " ".join(getattr(ev, "StringInserts", []) or []),
                        }
                        callback(log_ingest.parse_windows_event(evt))
                    if events:
                        top = getattr(events[0], "RecordNumber", None)
                        if top is not None:
                            seen_latest[ch] = top
                except Exception:
                    pass
            stop_ev.wait(poll)

    t = threading.Thread(target=loop, daemon=True, name="wineventlog")
    t.start()
    return t


def _win_level(event_type):
    # map win32 EVENTLOG_* types to our Level strings
    return {1: "Error", 2: "Warning", 4: "Information",
            8: "AuditSuccess", 16: "AuditFailure"}.get(event_type, "Information")
