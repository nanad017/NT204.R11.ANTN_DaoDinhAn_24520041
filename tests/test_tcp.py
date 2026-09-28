from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from src.parsers.tcp import parse_tcp
from src.schema import PacketEvent


def test_parse_tcp_reads_flags_header_and_payload():
    event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    packet = IP() / TCP(
        sport=12345,
        dport=80,
        seq=10,
        ack=20,
        flags="SA",
        window=4096,
    ) / Raw(b"abc")

    payload = parse_tcp(packet, event)

    assert payload == b"abc"
    assert event.src_port == 12345
    assert event.dest_port == 80
    assert event.tcp is not None
    assert event.tcp.flags == ["SYN", "ACK"]
    assert event.tcp.header_length == 20
    assert event.tcp.payload_length == 3
