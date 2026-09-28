from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from src.parsers.dns import parse_dns
from src.schema import PacketEvent


def test_parse_dns_query_and_response_records():
    query_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    query = IP() / UDP(sport=50000, dport=53) / DNS(
        id=7,
        rd=1,
        qd=DNSQR(qname="example.test", qtype="AAAA"),
    )
    parse_dns(query, query_event)

    assert query_event.dns is not None
    assert query_event.dns.type == "query"
    assert query_event.dns.id == 7
    assert query_event.dns.queries[0].rrname == "example.test"
    assert query_event.dns.queries[0].rrtype == "AAAA"

    response_event = PacketEvent(timestamp="2026-01-01T00:00:00+00:00")
    response = IP() / UDP(sport=53, dport=50000) / DNS(
        id=7,
        qr=1,
        qd=DNSQR(qname="example.test"),
        an=DNSRR(rrname="example.test", type="A", ttl=60, rdata="192.0.2.1"),
    )
    parse_dns(response, response_event)

    assert response_event.dns is not None
    assert response_event.dns.type == "response"
    assert response_event.dns.answers[0].rdata == "192.0.2.1"
    assert response_event.dns.grouped["A"] == ["192.0.2.1"]
