from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from src.schema import EtherInfo, IPv4Info


def parse_ipv4(packet, event):
    if packet.haslayer(Ether):
        ethernet = packet[Ether]
        event.ether = EtherInfo(
            src_mac=str(ethernet.src),
            dest_mac=str(ethernet.dst),
        )

    if not packet.haslayer(IP):
        if not event.parser.errors:
            event.parser.status = "unknown"
        event.parser.warnings.append("Unsupported network protocol: not IPv4")
        return

    ip_packet = _materialize_ipv4(packet[IP])
    protocol_number = _optional_int(ip_packet.proto)
    event.src_ip = str(ip_packet.src)
    event.dest_ip = str(ip_packet.dst)
    event.proto = _transport_protocol(protocol_number)
    event.ip = IPv4Info(
        version=_optional_int(ip_packet.version) or 4,
        header_length=_header_length(ip_packet.ihl),
        total_length=_optional_int(ip_packet.len),
        identification=_optional_int(ip_packet.id),
        flags=_ipv4_flags(ip_packet.flags),
        fragment_offset=_optional_int(ip_packet.frag),
        ttl=_optional_int(ip_packet.ttl),
        checksum=_optional_int(ip_packet.chksum),
    )


def _materialize_ipv4(ip_packet):
    if any(value is None for value in (ip_packet.ihl, ip_packet.len, ip_packet.chksum)):
        return IP(bytes(ip_packet))
    return ip_packet


def _header_length(ihl):
    value = _optional_int(ihl)
    return (value if value is not None else 5) * 4


def _optional_int(value):
    return int(value) if value is not None else None


def _ipv4_flags(flags):
    value = str(flags)
    return value.split("+") if value else []


def _transport_protocol(protocol_number):
    if protocol_number == 6:
        return "TCP"
    if protocol_number == 17:
        return "UDP"
    return None
