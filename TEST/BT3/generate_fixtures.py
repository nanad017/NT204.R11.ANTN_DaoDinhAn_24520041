#!/usr/bin/env python3
"""Generate the deterministic PCAP used by the Assignment 3 E2E test."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap


ROOT = Path(__file__).resolve().parent


def generate() -> Path:
    output = ROOT / "T14" / "input.pcap"
    packets = [
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=8080, flags="S", seq=100),
        IP(src="198.51.100.20", dst="192.0.2.10")
        / TCP(sport=8080, dport=50000, flags="SA", seq=200, ack=101),
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=8080, flags="A", seq=101, ack=201),
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=8080, flags="PA", seq=101, ack=201)
        / Raw(b"USER xxadmin"),
    ]
    for index, packet in enumerate(packets):
        packet.time = 1_793_404_800 + index / 10
    wrpcap(str(output), packets)
    return output


if __name__ == "__main__":
    print(generate())
