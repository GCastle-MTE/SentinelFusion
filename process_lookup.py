# process_lookup.py
#
# Maps captured network flows to the local application that owns them.
#
# Packets don't carry process information, so this reads the OS connection
# table (via psutil), which links each TCP/UDP connection to the owning PID,
# and then to a process name. Flows are matched by LOCAL PORT: whichever side
# of a packet is this machine, that port identifies exactly one connection.
#
# This is the same approach NetLimiter / GlassWire / TCPView use. Seeing
# every application's connections requires running as administrator.
import socket
import threading
import time

try:
    import psutil
    _AVAILABLE = True
except Exception:
    psutil = None
    _AVAILABLE = False

REFRESH_SECONDS = 2
PORT_TTL = 90  # remember a port -> process mapping this long after last seen

_lock = threading.Lock()
_port_to_proc = {}     # local_port -> (process_name, pid, last_seen)
_pid_name_cache = {}
_local_ips = {"127.0.0.1", "::1"}
_stop = threading.Event()
_thread = None


def available():
    return _AVAILABLE


def _refresh_local_ips():
    ips = {"127.0.0.1", "::1"}
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0])
    except Exception:
        pass
    return ips


def _name_for_pid(pid):
    if pid is None:
        return None
    if pid in _pid_name_cache:
        return _pid_name_cache[pid]
    try:
        name = psutil.Process(pid).name()
    except Exception:
        name = None
    _pid_name_cache[pid] = name
    return name


def _snapshot():
    now = time.time()
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return  # e.g. AccessDenied without admin
    with _lock:
        for c in conns:
            if not c.laddr:
                continue
            lport = c.laddr.port
            name = _name_for_pid(c.pid)
            if not name:
                name = f"pid {c.pid}" if c.pid else "system"
            _port_to_proc[lport] = (name, c.pid, now)
        cutoff = now - PORT_TTL
        for p in [p for p, v in _port_to_proc.items() if v[2] < cutoff]:
            del _port_to_proc[p]


def attribute(src, sport, dst, dport):
    # Return the local application name for a flow, or a coarse bucket.
    if not _AVAILABLE:
        return "n/a (install psutil)"
    if src in _local_ips and sport is not None:
        lport = sport
    elif dst in _local_ips and dport is not None:
        lport = dport
    elif sport is None and dport is None:
        return "no port (ICMP/etc.)"
    else:
        return "other host"
    with _lock:
        entry = _port_to_proc.get(lport)
    return entry[0] if entry else "unknown"


def _loop():
    global _local_ips
    n = 0
    while not _stop.is_set():
        _snapshot()
        n += 1
        if n % 30 == 0:  # refresh interface IPs occasionally
            _local_ips = _refresh_local_ips()
        _stop.wait(REFRESH_SECONDS)


def start():
    global _thread, _local_ips
    if not _AVAILABLE:
        print("process_lookup: psutil not installed; application names disabled.")
        print("  install it with:  python -m pip install psutil")
        return
    _local_ips = _refresh_local_ips()
    _snapshot()  # prime once so early packets can be attributed
    _stop.clear()
    _thread = threading.Thread(target=_loop, daemon=True)
    _thread.start()


def stop():
    _stop.set()
