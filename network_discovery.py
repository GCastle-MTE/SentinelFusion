# network_discovery.py
#
# Lists devices on the local network by ARP-scanning the local subnet.
# Each responder gives us its IP and MAC; we add a best-effort vendor
# (from the MAC) and reverse-DNS hostname.
#
# Requires Npcap + administrator (same as packet capture).
import socket
import ipaddress

from scapy.all import Ether, ARP, srp, conf

try:
    import psutil
    _HAVE_PSUTIL = True
except Exception:
    psutil = None
    _HAVE_PSUTIL = False


def _primary_ip():
    # The IP this host actually uses to reach the internet.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def _local_subnet():
    # Turn this host's real LAN address into a CIDR subnet, skipping
    # loopback and link-local (169.254.x.x / APIPA) adapters.
    if not _HAVE_PSUTIL:
        return None

    primary = _primary_ip()
    candidates = []  # (ip, netmask)
    try:
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family != socket.AF_INET or not a.netmask:
                    continue
                ip = a.address
                if ip.startswith("127."):
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if addr.is_link_local:  # skip 169.254.x.x
                    continue
                candidates.append((ip, a.netmask))
    except Exception:
        pass

    # Prefer the interface holding our primary outbound IP.
    if primary:
        for ip, mask in candidates:
            if ip == primary:
                return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))

    # Otherwise the first private candidate.
    for ip, mask in candidates:
        try:
            if ipaddress.ip_address(ip).is_private:
                return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
        except Exception:
            continue
    return None


def _vendor(mac):
    # Best-effort MAC -> vendor using scapy's manufacturer DB (if present).
    try:
        return conf.manufdb._get_manuf(mac) or ""
    except Exception:
        return ""


def _hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def default_gateway():
    # The router for the default route - normally also the legitimate DHCP server.
    try:
        gw = conf.route.route("0.0.0.0")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None


def scan_network(timeout=3):
    subnet = _local_subnet()
    if not subnet:
        print("Could not determine a usable local subnet "
              "(only loopback/link-local found, or psutil missing).")
        return []

    print(f"ARP-scanning {subnet} ...")
    try:
        # Raw ARP request to the whole subnet, no BPF filter (Npcap can't
        # compile arping()'s 'arp[7]=2'); scapy matches the replies for us.
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout,
            verbose=0,
        )
    except Exception as e:
        print("ARP scan failed:", e)
        return []

    devices = []
    for _, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "vendor": _vendor(mac),
                "hostname": _hostname(ip),
            }
        )

    devices.sort(key=lambda d: tuple(int(p) for p in d["ip"].split(".")))
    return devices
