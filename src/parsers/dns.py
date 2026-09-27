from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP, UDP
from scapy.packet import NoPayload, Packet

from src.schema import DNSInfo, DNSQuery, DNSRecord

_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}
_RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def parse_dns(packet, event):
    dns_packet = _materialize_dns(_get_dns_layer(packet))
    info = DNSInfo(
        type="response" if int(dns_packet.qr) else "query",
        id=_optional_int(dns_packet.id),
        flags=_flags(dns_packet),
        qr=bool(dns_packet.qr),
        aa=bool(dns_packet.aa),
        tc=bool(dns_packet.tc),
        rd=bool(dns_packet.rd),
        ra=bool(dns_packet.ra),
        z=bool(dns_packet.z),
        rcode=_rcode_name(_optional_int(dns_packet.rcode)),
    )
    info.queries = [
        DNSQuery(rrname=_name(record.qname), rrtype=_type_name(record.qtype))
        for record in _records(dns_packet.qd, _optional_int(dns_packet.qdcount), DNSQR)
    ]
    info.answers = _dns_records(dns_packet.an, _optional_int(dns_packet.ancount))
    info.authorities = _dns_records(dns_packet.ns, _optional_int(dns_packet.nscount))
    info.additionals = _dns_records(dns_packet.ar, _optional_int(dns_packet.arcount))
    for record in info.answers:
        if record.rdata is not None:
            info.grouped.setdefault(record.rrtype, []).append(record.rdata)
    event.dns = info


def _get_dns_layer(packet):
    if packet.haslayer(DNS):
        return packet[DNS]

    if packet.haslayer(UDP):
        payload = bytes(packet[UDP].payload)
    elif packet.haslayer(TCP):
        payload = bytes(packet[TCP].payload)
    else:
        payload = bytes(packet.payload)
    if len(payload) >= 14 and int.from_bytes(payload[:2], "big") == len(payload) - 2:
        payload = payload[2:]
    if len(payload) < 12:
        raise ValueError("DNS payload is shorter than its header")
    return DNS(payload)


def _materialize_dns(dns_packet):
    counts = (
        dns_packet.qdcount,
        dns_packet.ancount,
        dns_packet.nscount,
        dns_packet.arcount,
    )
    return DNS(bytes(dns_packet)) if any(value is None for value in counts) else dns_packet


def _records(
    first,
    count,
    expected_type,
):
    if isinstance(first, (list, tuple)):
        for record in first[: count or len(first)]:
            if isinstance(record, expected_type):
                yield record
        return

    if not isinstance(first, Packet):
        return
    current = first
    remaining = count or 0
    while remaining and not isinstance(current, NoPayload):
        if not isinstance(current, expected_type):
            break
        yield current
        current = current.payload
        remaining -= 1


def _dns_records(first, count):
    return [
        DNSRecord(
            rrname=_name(record.rrname),
            rrtype=_type_name(record.type),
            ttl=_optional_int(record.ttl),
            rdata=_rdata(record.rdata),
        )
        for record in _records(first, count, DNSRR)
    ]


def _optional_int(value):
    return int(value) if value is not None else None


def _type_name(value):
    number = _optional_int(value)
    return _TYPE_NAMES.get(number, f"TYPE{number}") if number is not None else "UNKNOWN"


def _rcode_name(value):
    return _RCODE_NAMES.get(value, f"RCODE{value}") if value is not None else "UNKNOWN"


def _name(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def _rdata(value):
    return _name(value)


def _flags(dns_packet):
    names = []
    for field, name in (
        ("qr", "QR"),
        ("aa", "AA"),
        ("tc", "TC"),
        ("rd", "RD"),
        ("ra", "RA"),
    ):
        if bool(getattr(dns_packet, field)):
            names.append(name)
    return "|".join(names)
