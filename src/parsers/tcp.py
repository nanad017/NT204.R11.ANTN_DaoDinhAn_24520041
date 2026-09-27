from scapy.layers.inet import TCP

from src.schema import TCPInfo

_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}


def parse_tcp(packet, event):
    if not packet.haslayer(TCP):
        event.parser.warnings.append("IPv4 protocol is TCP but no TCP layer was found")
        return b""

    tcp_packet = _materialize_tcp(packet[TCP])
    payload = bytes(tcp_packet.payload)
    event.src_port = _optional_int(tcp_packet.sport)
    event.dest_port = _optional_int(tcp_packet.dport)
    event.tcp = TCPInfo(
        seq=_optional_int(tcp_packet.seq),
        ack=_optional_int(tcp_packet.ack),
        header_length=_header_length(tcp_packet.dataofs),
        flags=_tcp_flags(tcp_packet.flags),
        window=_optional_int(tcp_packet.window),
        checksum=_optional_int(tcp_packet.chksum),
        payload_length=len(payload),
    )
    return payload


def _materialize_tcp(tcp_packet):
    if any(value is None for value in (tcp_packet.dataofs, tcp_packet.chksum)):
        return TCP(bytes(tcp_packet))
    return tcp_packet


def _header_length(data_offset):
    value = _optional_int(data_offset)
    return (value if value is not None else 5) * 4


def _optional_int(value):
    return int(value) if value is not None else None


def _tcp_flags(flags):
    return [name for code, name in _FLAG_NAMES.items() if code in str(flags)]
