import re

from scapy.layers.dns import DNS

_HTTP_REQUEST = re.compile(
    rb"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE)\s+\S+\s+HTTP/1\.[01](?:\r?\n|$)",
    re.IGNORECASE,
)
_HTTP_RESPONSE = re.compile(rb"^HTTP/1\.[01]\s+\d{3}(?:\s|\r|\n|$)", re.IGNORECASE)
_SMTP_COMMAND = re.compile(
    rb"^(EHLO|HELO|MAIL\s+FROM:|RCPT\s+TO:|DATA|QUIT|RSET|NOOP)(?:\s|\r|\n|$)",
    re.IGNORECASE,
)
_SMTP_RESPONSE = re.compile(rb"^\d{3}(?:[ -]|\r|\n|$)")

_HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
_DNS_PORTS = {53}
_SMTP_PORTS = {25, 465, 587}


def detect_application(
    payload,
    src_port,
    dest_port,
    packet=None,
):
    if not payload and (packet is None or not packet.haslayer(DNS)):
        return "unknown"
    if _looks_like_http(payload):
        return "http"
    if _looks_like_smtp(payload):
        return "smtp"
    if _looks_like_dns(payload, packet):
        return "dns"

    ports = {port for port in (src_port, dest_port) if port is not None}
    if ports & _DNS_PORTS:
        return "dns"
    if ports & _HTTP_PORTS:
        return "http"
    if ports & _SMTP_PORTS:
        return "smtp"
    return "unknown"


def _looks_like_http(payload):
    return bool(_HTTP_REQUEST.match(payload) or _HTTP_RESPONSE.match(payload))


def _looks_like_smtp(payload):
    return bool(_SMTP_COMMAND.match(payload) or _SMTP_RESPONSE.match(payload))


def _looks_like_dns(payload, packet):
    if packet is not None and packet.haslayer(DNS):
        return True
    if len(payload) < 12:
        return False

    flags = int.from_bytes(payload[2:4], "big")
    counts = [int.from_bytes(payload[index:index + 2], "big") for index in range(4, 12, 2)]
    opcode = (flags >> 11) & 0x0F
    return opcode <= 5 and any(counts) and all(count <= 4096 for count in counts)
