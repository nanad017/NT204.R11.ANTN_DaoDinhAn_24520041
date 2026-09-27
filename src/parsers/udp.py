from scapy.layers.inet import UDP

from src.schema import UDPInfo


def parse_udp(packet, event):
    if not packet.haslayer(UDP):
        event.parser.warnings.append("IPv4 protocol is UDP but no UDP layer was found")
        return b""

    udp_packet = _materialize_udp(packet[UDP])
    payload = bytes(udp_packet.payload)
    length = _optional_int(udp_packet.len)
    if length is not None and length < 8:
        event.parser.warnings.append(f"Invalid UDP length: {length}")
    elif length is not None and length < len(payload) + 8:
        event.parser.warnings.append("UDP payload appears truncated")

    event.src_port = _optional_int(udp_packet.sport)
    event.dest_port = _optional_int(udp_packet.dport)
    event.udp = UDPInfo(
        length=length,
        checksum=_optional_int(udp_packet.chksum),
        payload_length=len(payload),
    )
    return payload


def _materialize_udp(udp_packet):
    if any(value is None for value in (udp_packet.len, udp_packet.chksum)):
        return UDP(bytes(udp_packet))
    return udp_packet


def _optional_int(value):
    return int(value) if value is not None else None
