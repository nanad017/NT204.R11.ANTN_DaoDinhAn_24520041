import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw


@pytest.fixture
def http_packet():
    return IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
        sport=50000,
        dport=8080,
        flags="PA",
    ) / Raw(b"GET /health HTTP/1.1\r\nHost: example.test\r\n\r\n")


@pytest.fixture
def udp_packet():
    return IP(src="192.0.2.10", dst="198.51.100.20") / UDP(
        sport=50000,
        dport=9999,
    ) / Raw(b"payload")
