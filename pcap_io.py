"""Read and write .pcap files. Scapy is isolated here so the rest of the app
(and the import/export UI) stays decoupled from it.
"""

from scapy.all import rdpcap, wrpcap


def read_pcap(path):
    """Return a list of packets from a .pcap / .pcapng file."""
    return list(rdpcap(path))


def write_pcap(path, packets):
    """Write a list of packets to `path` in pcap format."""
    wrpcap(path, packets)
