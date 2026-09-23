# src/models.py

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

@dataclass
class EtherInfo:
    src_mac: Optional[str] = None
    dest_mac: Optional[str] = None

@dataclass
class IPv4Info:
    version: int = 4

    header_length: Optional[int] = None
    total_length: Optional[int] = None

    identification: Optional[int] = None

    flags: list[str] = field(default_factory=list)
    fragment_offset: Optional[int] = None

    ttl: Optional[int] = None
    checksum: Optional[int] = None

@dataclass
class TCPInfo:
    seq: Optional[int] = None
    ack: Optional[int] = None

    header_length: Optional[int] = None

    flags: list[str] = field(default_factory=list)

    window: Optional[int] = None
    checksum: Optional[int] = None

    payload_length: int = 0


@dataclass
class UDPInfo:
    length: Optional[int] = None
    checksum: Optional[int] = None

    payload_length: int = 0


@dataclass
class HTTPHeader:
    name: str
    value: str


@dataclass
class HTTPInfo:
    # Basic fields
    hostname: Optional[str] = None
    http_port: Optional[int] = None

    url: Optional[str] = None

    http_user_agent: Optional[str] = None
    http_content_type: Optional[str] = None

    cookie: Optional[str] = None

    # Extended fields
    length: Optional[int] = None

    status: Optional[int] = None

    # HTTP/1.0, HTTP/1.1
    protocol: Optional[str] = None

    # GET, POST, HEAD, ...
    http_method: Optional[str] = None

    http_refer: Optional[str] = None

    # Optional full header dump
    request_headers: list[HTTPHeader] = field(default_factory=list)
    response_headers: list[HTTPHeader] = field(default_factory=list)

    # Useful for assignment HTTP POST test
    body: Optional[str] = None

@dataclass
class DNSQuery:
    rrname: str
    rrtype: str


@dataclass
class DNSRecord:
    rrname: str
    rrtype: str

    ttl: Optional[int] = None
    rdata: Optional[str] = None


@dataclass
class DNSInfo:
    # inspired by Suricata DNS logging v3.
    version: int = 3

    # request / answer
    type: Optional[str] = None

    # DNS transaction ID
    id: Optional[int] = None

    # DNS flags
    flags: Optional[str] = None

    qr: Optional[bool] = None
    aa: Optional[bool] = None
    tc: Optional[bool] = None
    rd: Optional[bool] = None
    ra: Optional[bool] = None
    z: Optional[bool] = None

    # NOERROR, NXDOMAIN, ...
    rcode: Optional[str] = None

    queries: list[DNSQuery] = field(default_factory=list)

    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    # Optional grouped format:
    #
    # {
    #     "A": ["192.0.2.1"],
    #     "CNAME": ["example.com"]
    # }
    grouped: dict[str, list[str]] = field(default_factory=dict)

@dataclass
class SMTPInfo:
    # Session information
    helo: Optional[str] = None

    mail_from: Optional[str] = None
    rcpt_to: list[str] = field(default_factory=list)

    # Per-packet command parsing required by assignment.
    #
    # Examples:
    # command = "EHLO"
    # argument = "mail.example.com"
    #
    # command = "MAIL FROM"
    # argument = "<alice@example.com>"
    command: Optional[str] = None
    argument: Optional[str] = None

    # SMTP server response
    #
    # 250 OK
    # 220 Service ready
    status_code: Optional[int] = None
    response: Optional[str] = None

@dataclass
class EmailInfo:
    status: Optional[str] = None

    from_address: Optional[str] = None
    to: list[str] = field(default_factory=list)

    subject: Optional[str] = None
    date: Optional[str] = None

    message_id: Optional[str] = None
    x_mailer: Optional[str] = None

    attachment: list[str] = field(default_factory=list)

    body_md5: Optional[str] = None


@dataclass
class ParserInfo:
    """
    Parser state.

    status:
        success -> parsed normally
        partial -> some data parsed, but errors occurred
        unknown -> unsupported/unrecognized protocol
        error   -> parsing failed, but processing continues
    """

    status: str = "success"

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================
# Base Event
#
# Common fields shared by current and future IDS event types.
# ============================================================

@dataclass
class BaseEvent:
    timestamp: str

    # Generic event type.
    # PacketEvent overrides this with "packet".
    event_type: str = "event"

    # --------------------------------------------------------
    # Future flow support
    # --------------------------------------------------------

    # Remains None until a Flow Engine exists.
    flow_id: Optional[int] = None

    # --------------------------------------------------------
    # Capture metadata
    # --------------------------------------------------------

    # Packet number inside the capture/input stream.
    pcap_cnt: Optional[int] = None

    # Examples:
    # "live"
    # "pcap"
    # "wire/pcap"
    pkt_src: Optional[str] = None

    # --------------------------------------------------------
    # Common network tuple
    # --------------------------------------------------------

    src_ip: Optional[str] = None
    src_port: Optional[int] = None

    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None

    # TCP / UDP
    proto: Optional[str] = None

    # http / dns / smtp / unknown
    app_proto: Optional[str] = None

    # --------------------------------------------------------
    # Parser state
    # --------------------------------------------------------

    parser: ParserInfo = field(default_factory=ParserInfo)

    # --------------------------------------------------------
    # Serialization
    # --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Convert the event and all nested dataclasses into
        a JSON-compatible dictionary.

        None values and empty containers are omitted.
        """
        return _clean(asdict(self))


# ============================================================
# Packet Event
# ============================================================

@dataclass
class PacketEvent(BaseEvent):
    event_type: str = "packet"

    # --------------------------------------------------------
    # Layer 2
    # --------------------------------------------------------

    ether: Optional[EtherInfo] = None

    # --------------------------------------------------------
    # Layer 3
    # --------------------------------------------------------

    ip: Optional[IPv4Info] = None

    # --------------------------------------------------------
    # Layer 4
    # --------------------------------------------------------

    tcp: Optional[TCPInfo] = None
    udp: Optional[UDPInfo] = None

    # --------------------------------------------------------
    # Application Layer
    # --------------------------------------------------------

    http: Optional[HTTPInfo] = None
    dns: Optional[DNSInfo] = None
    smtp: Optional[SMTPInfo] = None

    # Future / optional extension
    email: Optional[EmailInfo] = None


def _clean(value: Any) -> Any:
    """
    Recursively clean the dictionary generated by dataclasses.

    Removes:
        - None
        - empty dictionaries
        - empty lists

    Keeps:
        - 0
        - False
        - non-empty strings
        - populated lists/dicts
    """

    if isinstance(value, dict):
        result: dict[str, Any] = {}

        for key, item in value.items():
            cleaned_item = _clean(item)

            if cleaned_item is None:
                continue

            if cleaned_item == {}:
                continue

            if cleaned_item == []:
                continue

            result[key] = cleaned_item

        return result

    if isinstance(value, list):
        return [_clean(item) for item in value]

    return value