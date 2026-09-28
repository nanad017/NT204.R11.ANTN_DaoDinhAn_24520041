from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.parsers.network import parse_ipv4
from src.schema import PacketEvent


def test_parse_ipv4_populates_network_and_ethernet_fields():
    event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    packet = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(
        src="192.0.2.1",
        dst="198.51.100.1",
        flags="MF",
        frag=3,
        ttl=42,
        proto=17,
    )

    parse_ipv4(packet, event)

    assert event.ether is not None
    assert event.ip is not None
    assert event.ip.header_length == 20
    assert event.ip.flags == ["MF"]
    assert event.ip.fragment_offset == 3
    assert event.ip.ttl == 42
    assert event.proto == "UDP"


def test_parse_ipv4_marks_non_ipv4_as_unknown():
    event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")

    parse_ipv4(Ether(), event)

    assert event.parser.status == "unknown"
    assert event.parser.warnings
