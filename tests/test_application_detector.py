from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP

from src.detection.application_detector import detect_application


def test_payload_signatures_override_port_hints():
    payload = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"

    assert detect_application(payload, 2000, 25) == "http"


def test_detector_recognizes_dns_layer_and_empty_unknown_payload():
    packet = IP() / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname="example.test"))

    assert detect_application(b"", 50000, 53) == "unknown"
    assert detect_application(bytes(packet[UDP].payload), 50000, 53, packet) == "dns"
    assert detect_application(b"EHLO mail.example\r\n", 3000, 3001) == "smtp"
