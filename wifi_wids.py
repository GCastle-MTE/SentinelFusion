"""Wireless 802.11 intrusion detection (WIDS) - defensive monitoring.

This is the wireless counterpart to the wired detection engine. Given raw 802.11
management frames (which requires a monitor-mode-capable adapter), it surfaces
the attacks a defender wants to catch on the air around them:

  * Deauthentication / disassociation floods - the classic Wi-Fi denial of
    service and the first step of many evil-twin attacks.
  * Rogue access points - an AP broadcasting your network's SSID from an
    unexpected BSSID (MAC), i.e. someone standing up a look-alike.
  * Evil twins - the same SSID appearing on two BSSIDs at once, or an SSID you
    know appearing on new hardware.
  * Unusually aggressive beaconing / probe activity.

Strictly passive and detection-only. It never transmits, never deauthenticates,
never cracks anything - it listens to frames already in the air and raises
alerts. It complements the wired engine; it does not replace it.

Monitor mode is the gate. Most built-in Windows Wi-Fi chipsets refuse it; a USB
adapter with a supported chipset (and Npcap in monitor mode) is the usual path.
`monitor_supported()` reports whether we can actually run, and the whole feature
stays dormant and clearly labelled until then. The frame *analysis* here is pure
and testable without any radio.
"""

import time

# --- tunables ---
DEAUTH_WINDOW = 10.0          # seconds
DEAUTH_FLOOD = 20             # deauth/disassoc frames in the window -> flood
BEACON_FLOOD = 200            # beacons from one BSSID in the window -> odd

# 802.11 management frame subtypes we care about.
SUBTYPE_ASSOC_REQ = 0
SUBTYPE_PROBE_REQ = 4
SUBTYPE_BEACON = 8
SUBTYPE_DISASSOC = 10
SUBTYPE_DEAUTH = 12

_frame_log = []               # recent (ts, subtype, bssid, src, dst)
_ssid_bssids = {}             # ssid -> set of bssids seen
_known_ssid_bssid = {}        # ssid -> the BSSID we trust (baseline)
_deauth_times = {}            # bssid/target -> [timestamps]
_beacon_times = {}            # bssid -> [timestamps]
_alerted = set()
_baseline_locked = False


def monitor_supported():
    """Best-effort check for monitor-mode capability on this machine.

    On Windows this depends on Npcap + the adapter's driver. We can't fully
    determine it without the live adapter, so the app calls this and, if False,
    keeps the feature dormant with an explanatory note. Returns (ok, reason).
    """
    try:
        import importlib.util
        if importlib.util.find_spec("scapy") is None:
            return False, "scapy not available"
    except Exception:
        return False, "scapy not available"
    # The real capability check happens on the adapter; we return a soft yes so
    # the UI can attempt it and report the concrete driver error if it fails.
    return True, "check adapter with: WlanHelper.exe <iface> mode monitor"


def set_known_network(ssid, bssid):
    """Register a trusted SSID->BSSID mapping (your real AP)."""
    if ssid:
        _known_ssid_bssid[ssid] = bssid


def observe_frame(subtype, bssid=None, src=None, dst=None, ssid=None,
                  signal=None, ts=None):
    """Fold one parsed 802.11 management frame into the detectors.

    Returns a list of (severity, category, message) findings raised by this
    frame (usually empty; alerts are deduped).
    """
    ts = ts or time.time()
    out = []
    _frame_log.append((ts, subtype, bssid, src, dst))
    if len(_frame_log) > 5000:
        del _frame_log[:1000]

    # --- deauth / disassoc flood ---
    if subtype in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
        key = bssid or dst or "?"
        times = _deauth_times.setdefault(key, [])
        times.append(ts)
        cutoff = ts - DEAUTH_WINDOW
        times[:] = [t for t in times if t >= cutoff]
        if len(times) >= DEAUTH_FLOOD:
            akey = ("deauth", key)
            if akey not in _alerted:
                _alerted.add(akey)
                kind = "deauth" if subtype == SUBTYPE_DEAUTH else "disassoc"
                out.append(("ALERT", "wifi",
                            f"802.11 {kind} flood involving {key}: "
                            f"{len(times)} frames in {DEAUTH_WINDOW:.0f}s. "
                            "Classic Wi-Fi denial-of-service / evil-twin precursor."))

    # --- beacon tracking: SSID <-> BSSID relationships ---
    if subtype == SUBTYPE_BEACON and ssid is not None and bssid:
        seen = _ssid_bssids.setdefault(ssid, set())
        was_new = bssid not in seen
        seen.add(bssid)

        # Rogue AP: a known SSID from an unexpected BSSID.
        if ssid in _known_ssid_bssid and bssid != _known_ssid_bssid[ssid]:
            akey = ("rogue", ssid, bssid)
            if akey not in _alerted:
                _alerted.add(akey)
                out.append(("ALERT", "wifi",
                            f"Rogue AP: SSID '{ssid}' is being broadcast from {bssid}, "
                            f"but your known AP for it is {_known_ssid_bssid[ssid]}. "
                            "Possible look-alike / evil twin."))

        # Evil twin: same SSID now on 2+ BSSIDs (and we didn't pre-approve it).
        if was_new and len(seen) >= 2 and ssid not in _known_ssid_bssid:
            akey = ("twin", ssid, tuple(sorted(seen)))
            if akey not in _alerted:
                _alerted.add(akey)
                out.append(("WARNING", "wifi",
                            f"SSID '{ssid}' seen on {len(seen)} different BSSIDs "
                            f"({', '.join(sorted(seen))}). Could be roaming/mesh, "
                            "or an evil twin - verify the hardware."))

        # Beacon flood.
        bt = _beacon_times.setdefault(bssid, [])
        bt.append(ts)
        cutoff = ts - DEAUTH_WINDOW
        bt[:] = [t for t in bt if t >= cutoff]
        if len(bt) >= BEACON_FLOOD:
            akey = ("beaconflood", bssid)
            if akey not in _alerted:
                _alerted.add(akey)
                out.append(("WARNING", "wifi",
                            f"Beacon flood from {bssid}: {len(bt)} beacons in "
                            f"{DEAUTH_WINDOW:.0f}s. Possible fake-AP spam."))
    return out


def access_points():
    """Current view of SSID -> BSSIDs seen, for the UI."""
    return {ssid: sorted(bssids) for ssid, bssids in _ssid_bssids.items()}


def stats():
    return {"frames": len(_frame_log),
            "ssids": len(_ssid_bssids),
            "bssids": len({b for bs in _ssid_bssids.values() for b in bs}),
            "known": len(_known_ssid_bssid)}


def lock_baseline():
    """Treat the SSID/BSSID pairs seen so far as trusted (call once settled)."""
    global _baseline_locked
    for ssid, bssids in _ssid_bssids.items():
        if ssid not in _known_ssid_bssid and len(bssids) == 1:
            _known_ssid_bssid[ssid] = next(iter(bssids))
    _baseline_locked = True


def clear():
    _frame_log.clear()
    _ssid_bssids.clear()
    _known_ssid_bssid.clear()
    _deauth_times.clear()
    _beacon_times.clear()
    _alerted.clear()


# --- live capture (monitor mode) --------------------------------------------
# Separate from the wired engine: 802.11 frames are a different parsing path
# (radiotap + Dot11), so this has its own sniffer. It only runs if the adapter
# is in monitor mode; otherwise it stays dormant.

_sniffer = None
_stop = False


def parse_dot11(packet):
    """Pull the fields we need out of a scapy Dot11 frame. Returns a dict or None.

    Kept separate and defensive so a malformed frame never takes down capture.
    """
    try:
        import scapy.all as _scapy
        if not hasattr(_scapy, "Dot11"):
            return None
    except Exception:
        return None
    try:
        if not packet.haslayer("Dot11"):
            return None
        d = packet["Dot11"]
        subtype = int(getattr(d, "subtype", -1))
        bssid = getattr(d, "addr3", None)
        src = getattr(d, "addr2", None)
        dst = getattr(d, "addr1", None)
        ssid = None
        if packet.haslayer("Dot11Beacon") or packet.haslayer("Dot11ProbeResp"):
            elt = packet.getlayer("Dot11Elt")
            while elt is not None and getattr(elt, "ID", None) is not None:
                if elt.ID == 0:  # SSID element
                    try:
                        ssid = elt.info.decode(errors="replace")
                    except Exception:
                        ssid = ""
                    break
                elt = elt.payload.getlayer("Dot11Elt")
        return {"subtype": subtype, "bssid": bssid, "src": src, "dst": dst,
                "ssid": ssid}
    except Exception:
        return None


def start_capture(iface, emit=None):
    """Start sniffing 802.11 frames on a monitor-mode interface.

    `emit(severity, category, message)` is called for each finding (usually the
    app's events.log_event). Returns (ok, message). Does not raise.
    """
    global _sniffer, _stop
    ok, reason = monitor_supported()
    if not ok:
        return False, reason
    try:
        from scapy.all import AsyncSniffer
    except Exception as exc:
        return False, f"scapy unavailable: {exc}"

    _stop = False

    def _handle(pkt):
        if _stop:
            return
        info = parse_dot11(pkt)
        if not info:
            return
        findings = observe_frame(info["subtype"], bssid=info["bssid"],
                                 src=info["src"], dst=info["dst"],
                                 ssid=info["ssid"])
        if emit:
            for sev, cat, msg in findings:
                try:
                    emit(sev, cat, msg)
                except Exception:
                    pass

    try:
        _sniffer = AsyncSniffer(iface=iface, prn=_handle, store=False)
        _sniffer.start()
        return True, f"802.11 WIDS capturing on {iface}"
    except Exception as exc:
        # The most common failure: adapter not actually in monitor mode.
        return False, (f"could not start monitor capture on {iface}: {exc}. "
                       "The adapter may not support monitor mode - a compatible "
                       "USB Wi-Fi adapter is usually needed on Windows.")


def stop_capture():
    global _sniffer, _stop
    _stop = True
    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:
            pass
        _sniffer = None


def is_capturing():
    return _sniffer is not None and not _stop
