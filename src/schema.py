from dataclasses import asdict, dataclass, field
@dataclass
class EtherInfo:
    src_mac: str | None = None
    dest_mac: str | None = None

@dataclass
class IPv4Info:
    version: int = 4

    header_length: int | None = None
    total_length: int | None = None

    identification: int | None = None

    flags: list[str] = field(default_factory=list)
    fragment_offset: int | None = None

    ttl: int | None = None
    checksum: int | None = None

@dataclass
class TCPInfo:
    seq: int | None = None
    ack: int | None = None

    header_length: int | None = None

    flags: list[str] = field(default_factory=list)

    window: int | None = None
    checksum: int | None = None

    payload_length: int = 0


@dataclass
class UDPInfo:
    length: int | None = None
    checksum: int | None = None

    payload_length: int = 0


@dataclass
class HTTPHeader:
    name: str
    value: str
    original_name: str | None = None


@dataclass
class HTTPInfo:
    hostname: str | None = None
    http_port: int | None = None

    url: str | None = None

    raw_url: str | None = None
    decoded_url: str | None = None
    decoded_path: str | None = None
    decoded_query: str | None = None
    normalized_url: str | None = None
    raw_form_data: str | None = None
    decoded_form: dict[str, object] = field(default_factory=dict)

    http_user_agent: str | None = None
    http_content_type: str | None = None

    cookie: str | None = None

    length: int | None = None

    status: int | None = None

    protocol: str | None = None

    http_method: str | None = None

    http_refer: str | None = None

    request_headers: list[HTTPHeader] = field(default_factory=list)
    response_headers: list[HTTPHeader] = field(default_factory=list)

    body: str | None = None
    raw_body: str | None = None
    decoded_body: str | None = None
    html_decoded_body: str | None = None

@dataclass
class DNSQuery:
    rrname: str
    rrtype: str


@dataclass
class DNSRecord:
    rrname: str
    rrtype: str

    ttl: int | None = None
    rdata: str | None = None


@dataclass
class DNSInfo:
    version: int = 3

    type: str | None = None

    id: int | None = None

    flags: str | None = None

    qr: bool | None = None
    aa: bool | None = None
    tc: bool | None = None
    rd: bool | None = None
    ra: bool | None = None
    z: bool | None = None

    rcode: str | None = None

    queries: list[DNSQuery] = field(default_factory=list)

    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    grouped: dict[str, list[str]] = field(default_factory=dict)

@dataclass
class SMTPInfo:
    helo: str | None = None

    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)

    command: str | None = None
    argument: str | None = None

    status_code: int | None = None
    response: str | None = None

@dataclass
class EmailInfo:
    status: str | None = None

    from_address: str | None = None
    to: list[str] = field(default_factory=list)

    subject: str | None = None
    date: str | None = None

    message_id: str | None = None
    x_mailer: str | None = None

    attachment: list[str] = field(default_factory=list)

    body_md5: str | None = None

    raw_body: str | None = None
    decoded_body: str | None = None
    decoded_size: int | None = None
    decode_status: str | None = None
    content_transfer_encoding: str | None = None
    charset: str | None = None


@dataclass
class DecoderInfo:
    status: str = "not_applicable"
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class PreprocessInfo:
    status: str = "valid"
    processing_action: str = "retain"
    reason: str | None = None
    original_values: dict[str, object] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class EndpointInfo:
    ip: str
    port: int | None = None


@dataclass
class FlowInfo:
    flow_id: int
    protocol: str
    application_protocol: str | None = None
    endpoint_a: EndpointInfo | None = None
    endpoint_b: EndpointInfo | None = None
    start_time: str | None = None
    last_seen: str | None = None
    duration: float = 0.0
    packet_count: int = 0
    byte_count: int = 0
    forward_packet_count: int = 0
    forward_byte_count: int = 0
    backward_packet_count: int = 0
    backward_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    state: str | None = None


@dataclass
class ParserInfo:
    status: str = "success"

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class BaseEvent:
    timestamp: str

    event_type: str = "event"

    flow_id: int | None = None

    pcap_cnt: int | None = None

    pkt_src: str | None = None

    src_ip: str | None = None
    src_port: int | None = None

    dest_ip: str | None = None
    dest_port: int | None = None

    packet_length: int | None = None

    proto: str | None = None

    app_proto: str | None = None

    parser: ParserInfo = field(default_factory=ParserInfo)

    decoder: DecoderInfo | None = None
    preprocess: PreprocessInfo | None = None
    flow_direction: str | None = None
    flow: FlowInfo | None = None

    def to_dict(self) -> dict[str, object]:
        return _clean(asdict(self))


@dataclass
class PacketEvent(BaseEvent):
    event_type: str = "packet"

    ether: EtherInfo | None = None

    ip: IPv4Info | None = None

    tcp: TCPInfo | None = None
    udp: UDPInfo | None = None

    http: HTTPInfo | None = None
    dns: DNSInfo | None = None
    smtp: SMTPInfo | None = None

    email: EmailInfo | None = None


def _clean(value: object) -> object:
    if isinstance(value, dict):
        result: dict[str, object] = {}

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
