from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from src.parsers.udp import parse_udp
from src.schema import PacketEvent


def test_parse_udp_reads_ports_length_and_payload():
    event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    packet = IP() / UDP(sport=53000, dport=53) / Raw(b"abc")

    payload = parse_udp(packet, event)

    assert payload == b"abc"
    assert event.src_port == 53000
    assert event.dest_port == 53
    assert event.udp is not None
    assert event.udp.length == 11
    assert event.udp.payload_length == 3
