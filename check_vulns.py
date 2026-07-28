"""Standalone vulnerability-coverage check - run this against your own network.

The GUI does this per device, but this script answers the question that decides
how useful the feature is on *your* LAN: how many of your services actually
disclose a version? Version disclosure is what makes a CVE check possible, and
it varies enormously between networks.

Run it from the project folder (Administrator, so the scanner can work):

    python check_vulns.py                 # scan the local subnet
    python check_vulns.py 192.168.1.50    # one host
    python check_vulns.py --no-cve        # fingerprint only, no NVD calls

Without --no-cve it queries NIST's NVD, which is rate-limited: about 6.5s per
unique service version without an API key. Set one in the GUI (Settings ->
Vulnerability data) or via the NVD_API_KEY environment variable to go ~10x
faster. Results are cached, so a second run costs nothing.

Only scan networks you own or are authorised to test.
"""

import os
import sys

import port_scanner
import service_fingerprint
import cve_lookup
import asset_registry


def scan_host(ip, do_cve=True):
    print(f"\n{'=' * 68}\n{ip}\n{'=' * 68}")
    try:
        findings = port_scanner.scan_host(ip, timeout=0.5)
    except Exception as exc:
        print(f"  scan failed: {exc}")
        return (0, 0, 0)

    if not findings:
        print("  no open ports found")
        return (0, 0, 0)

    rows = service_fingerprint.identify_findings(findings, ip=ip)
    # Persist to the shared asset record, so a CLI scan feeds the same inventory
    # the GUI reads. Previously this ran, printed, and left no trace.
    asset_registry.note_services(ip, rows)
    for f in findings:
        if f.get("cert_issues"):
            asset_registry.note_cert_issues(ip, f["port"], f["cert_issues"])
    products = []
    identified = versioned = 0
    for row in rows:
        for p in row["products"]:
            identified += 1
            if p["confidence"] == "high":
                versioned += 1
                products.append(p)
                print(f"  {row['port']:>5}/tcp  {p['label']} {p['version']}")
            else:
                if p["confidence"] == "low":
                    why = "product named, version not disclosed"
                elif p.get("had_banner"):
                    # A banner with no digits in it cannot contain a version, so
                    # there is nothing a parser rule could extract. Generic
                    # strings like "HTTP Server" are the common case. Only a
                    # banner that does carry digits is worth investigating.
                    banner = row.get("banner", "")
                    if any(c.isdigit() for c in banner):
                        why = "banner has digits but no rule matched - see diag_banners.py"
                    else:
                        why = "banner carries no version information"
                else:
                    why = "silent - no banner sent"
                print(f"  {row['port']:>5}/tcp  {p['label']}  ({why})")

    if not do_cve or not products:
        return (len(findings), identified, versioned)

    print(f"\n  checking {len(products)} version(s) against NVD ...")
    assessments = cve_lookup.assess_products(products)
    asset_registry.note_vulnerabilities(ip, assessments)
    # Feed serious findings into the shared event store so a CLI scan shows up
    # in the application's Alerts and Logs like anything else. Release-level OS
    # matches are excluded: they are history, not this host's exposure.
    try:
        import events
        for a in assessments:
            if a.get("skipped") or a.get("precision") == "release":
                continue
            for c in a.get("cves") or []:
                if c.get("severity") in ("HIGH", "CRITICAL") and not c.get("suspect"):
                    events.log_event(
                        "WARNING", "vuln", ip,
                        f"{ip} runs {a['product']} {a['version']} - "
                        f"{c['id']} ({c['severity']} {c['score']})")
    except Exception as exc:
        print(f"  (could not record events: {exc})")
    for line in cve_lookup.summarize(assessments):
        print("  " + line)
    return (len(findings), identified, versioned)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    do_cve = "--no-cve" not in sys.argv

    asset_registry.load()
    key = os.environ.get("NVD_API_KEY", "")
    if key:
        cve_lookup.set_api_key(key)
        print("using NVD API key from environment")

    if args:
        targets = args
    else:
        try:
            import network_discovery
            print("discovering devices on the local subnet ...")
            devices = network_discovery.scan_network()
            targets = [d["ip"] for d in devices]
            print(f"found {len(targets)} device(s)")
        except Exception as exc:
            print(f"discovery failed ({exc}); pass an IP explicitly")
            return

    total_ports = total_ident = total_ver = 0
    for ip in targets:
        p, i, v = scan_host(ip, do_cve)
        total_ports += p
        total_ident += i
        total_ver += v

    asset_registry.save()
    print(f"\n{'=' * 68}\nCOVERAGE SUMMARY\n{'=' * 68}")
    print(f"  open ports found:          {total_ports}")
    print(f"  services identified:       {total_ident}")
    print(f"  versions disclosed:        {total_ver}")
    if total_ident:
        pct = 100.0 * total_ver / total_ident
        print(f"  version-disclosure rate:   {pct:.0f}%")
        print("\n  That percentage is the ceiling on how much of your network a "
              "CVE check\n  can assess. The rest are services that simply do not "
              "announce a version.")


if __name__ == "__main__":
    main()
