import pytest

from src.core_engine.inspection import InspectionContext
from src.core_engine.matcher import (
    ContentMatcher,
    HeaderMatcher,
    PacketMatcher,
    RuleMatcher,
)
from src.core_engine.models import MatchStatus
from src.core_engine.parser import parse_rule
from src.schema import (
    DNSInfo,
    DNSQuery,
    EmailInfo,
    FlowInfo,
    HTTPInfo,
    PacketEvent,
    SMTPInfo,
    TCPInfo,
    UDPInfo,
)


def _rule(header, options="", sid=700001):
    return parse_rule(
        f'alert {header} (msg:"test {sid}"; {options} sid:{sid}; rev:1;)'
    )


def _event(
    *,
    proto="TCP",
    src_ip="192.0.2.10",
    src_port=50000,
    dest_ip="198.51.100.20",
    dest_port=80,
    payload=b"",
    flags=("ACK", "PSH"),
    flow_role="to_server",
    established=True,
):
    event = PacketEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        proto=proto,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        flow_role=flow_role,
        flow=FlowInfo(
            flow_id=1,
            protocol=proto,
            established=established,
        ),
    )
    if proto.upper() == "TCP":
        event.tcp = TCPInfo(flags=list(flags), payload_length=len(payload))
    elif proto.upper() == "UDP":
        event.udp = UDPInfo(length=len(payload) + 8, payload_length=len(payload))
    event._application_payload = payload
    return event


def test_header_matcher_checks_protocol_ipv4_cidr_and_port_range():
    rule = _rule("tcp 192.0.2.0/24 49152:65535 -> 198.51.100.20 80")
    matcher = HeaderMatcher()

    assert matcher.matches(rule.header, _event())
    assert not matcher.matches(rule.header, _event(proto="UDP"))
    assert not matcher.matches(rule.header, _event(src_ip="192.0.3.10"))
    assert not matcher.matches(rule.header, _event(src_port=49151))
    assert not matcher.matches(rule.header, _event(dest_port=443))
    assert not matcher.matches(rule.header, _event(src_ip="not-an-ip"))


def test_bidirectional_header_matches_forward_and_reverse_tuples():
    rule = _rule("tcp 192.0.2.10 50000 <> 198.51.100.20 80")
    matcher = HeaderMatcher()

    assert matcher.matches(rule.header, _event())
    assert matcher.matches(
        rule.header,
        _event(
            src_ip="198.51.100.20",
            src_port=80,
            dest_ip="192.0.2.10",
            dest_port=50000,
        ),
    )


def test_forward_header_does_not_match_reverse_tuple():
    rule = _rule("tcp 192.0.2.10 50000 -> 198.51.100.20 80")

    result = RuleMatcher().match(
        rule,
        _event(
            src_ip="198.51.100.20",
            src_port=80,
            dest_ip="192.0.2.10",
            dest_port=50000,
        ),
    )

    assert result.status == MatchStatus.NO_MATCH
    assert result.reason == "header did not match"


def test_flow_combines_direction_and_established_state():
    rule = _rule(
        "tcp any any -> any 80",
        "flow:to_server,established;",
    )
    matcher = RuleMatcher()

    assert matcher.match(rule, _event()).matched
    assert not matcher.match(rule, _event(flow_role="to_client")).matched
    assert not matcher.match(rule, _event(established=False)).matched


def test_not_established_requires_real_flow_context():
    rule = _rule("tcp any any -> any 80", "flow:not_established;")
    event = _event(established=False)

    assert RuleMatcher().match(rule, event).matched
    event.flow = None
    assert not RuleMatcher().match(rule, event).matched


def test_tcp_flags_are_normalized_and_compared_exactly():
    rule = _rule("tcp any any -> any 80", "flags:PA;")
    matcher = PacketMatcher()

    assert matcher.matches(rule, _event(flags=("P", "A")))
    assert matcher.matches(rule, _event(flags=("ACK", "PSH")))
    assert not matcher.matches(rule, _event(flags=("SYN", "ACK", "PSH")))


def test_flags_zero_matches_only_packet_without_tcp_flags():
    rule = _rule("tcp any any -> any 80", "flags:0;")

    assert PacketMatcher().matches(rule, _event(flags=()))
    assert not PacketMatcher().matches(rule, _event(flags=("SYN",)))


@pytest.mark.parametrize(
    ("expression", "payload_size", "expected"),
    [
        ("4", 4, True),
        ("4", 5, False),
        ("<4", 3, True),
        ("<4", 4, False),
        (">4", 5, True),
        (">4", 4, False),
        ("3<>5", 3, False),
        ("3<>5", 4, True),
        ("3<>5", 5, False),
        ("3<>5", 6, False),
    ],
)
def test_dsize_uses_transport_payload_length(expression, payload_size, expected):
    rule = _rule("tcp any any -> any 80", f"dsize:{expression};")
    event = _event(payload=b"x" * payload_size)
    event.packet_length = 9999

    assert PacketMatcher().matches(rule, event) is expected


def test_content_default_is_case_sensitive_and_nocase_is_supported():
    sensitive = _rule("tcp any any -> any 80", 'content:"admin";', sid=710001)
    insensitive = _rule(
        "tcp any any -> any 80",
        'content:"admin"; nocase;',
        sid=710002,
    )
    event = _event(payload=b"GET /ADMIN HTTP/1.1")

    assert not RuleMatcher().match(sensitive, event).matched
    result = RuleMatcher().match(insensitive, event)
    assert result.matched
    assert result.matched_information[0].buffer == "transport"
    assert result.matched_information[0].field == "payload"
    assert result.matched_information[0].start == 5
    assert result.matched_information[0].end == 10


def test_offset_and_depth_limit_the_absolute_search_window():
    matching = _rule(
        "tcp any any -> any 80",
        'content:"needle"; offset:2; depth:6;',
        sid=720001,
    )
    too_shallow = _rule(
        "tcp any any -> any 80",
        'content:"needle"; offset:2; depth:5;',
        sid=720002,
    )
    wrong_offset = _rule(
        "tcp any any -> any 80",
        'content:"needle"; offset:3; depth:6;',
        sid=720003,
    )
    event = _event(payload=b"xxneedleyy")

    assert RuleMatcher().match(matching, event).matched
    assert not RuleMatcher().match(too_shallow, event).matched
    assert not RuleMatcher().match(wrong_offset, event).matched


def test_distance_within_and_content_order_are_enforced():
    matching = _rule(
        "tcp any any -> any 80",
        'content:"USER"; content:"admin"; distance:1; within:8;',
        sid=730001,
    )
    too_narrow = _rule(
        "tcp any any -> any 80",
        'content:"USER"; content:"admin"; distance:1; within:6;',
        sid=730002,
    )
    event = _event(payload=b"USER xxadmin")

    result = RuleMatcher().match(matching, event)
    assert result.matched
    assert [(item.start, item.end) for item in result.matched_information] == [
        (0, 4),
        (7, 12),
    ]
    assert not RuleMatcher().match(too_narrow, event).matched
    assert not RuleMatcher().match(matching, _event(payload=b"admin USER")).matched


def test_all_contents_must_match_in_the_same_inspection_buffer():
    rule = _rule(
        "tcp any any -> any 80",
        'content:"raw-only"; content:"normalized";',
    )
    event = _event(payload=b"raw-only")
    event.http = HTTPInfo(normalized_url="/normalized")

    assert not RuleMatcher().match(rule, event).matched


def test_content_can_match_normalized_application_buffer_with_metadata():
    rule = _rule(
        "tcp any any -> any 80",
        'content:"/admin"; nocase;',
    )
    event = _event(payload=b"unrelated raw payload")
    event.http = HTTPInfo(normalized_url="/ADMIN?mode=1")

    result = RuleMatcher().match(rule, event)

    assert result.matched
    assert result.matched_information[0].buffer == "http"
    assert result.matched_information[0].field == "normalized_url"
    assert result.matched_information[0].start == 0
    assert result.matched_information[0].end == 6


def test_content_can_match_dns_smtp_and_decoded_email_buffers():
    matcher = RuleMatcher()

    dns_event = _event(proto="UDP", dest_port=53)
    dns_event.dns = DNSInfo(queries=[DNSQuery("evil.example", "A")])
    dns_rule = _rule("udp any any -> any 53", 'content:"evil.example";', sid=740001)
    dns_result = matcher.match(dns_rule, dns_event)
    assert dns_result.matched
    assert dns_result.matched_information[0].buffer == "dns"

    smtp_event = _event(dest_port=25)
    smtp_event.smtp = SMTPInfo(command="MAIL FROM")
    smtp_rule = _rule("tcp any any -> any 25", 'content:"MAIL FROM";', sid=740002)
    smtp_result = matcher.match(smtp_rule, smtp_event)
    assert smtp_result.matched
    assert smtp_result.matched_information[0].buffer == "smtp"

    email_event = _event(dest_port=25)
    email_event.email = EmailInfo(decoded_body="decoded secret")
    email_rule = _rule("tcp any any -> any 25", 'content:"secret";', sid=740003)
    email_result = matcher.match(email_rule, email_event)
    assert email_result.matched
    assert email_result.matched_information[0].buffer == "email"
    assert email_result.matched_information[0].field == "decoded_body"


def test_explicit_payload_builds_context_without_changing_event_schema():
    rule = _rule("udp any any -> any 80", 'content:"probe";')
    event = _event(proto="UDP", payload=b"")
    context = InspectionContext.from_event(event, b"probe")

    result = RuleMatcher().match(rule, event, context)

    assert result.matched
    assert context.raw_payload == b"probe"


def test_header_failure_stops_before_invalid_content_context_is_built():
    rule = _rule("tcp any any -> any 443", 'content:"secret";')
    event = _event(dest_port=80)
    event._application_payload = "not bytes"

    result = RuleMatcher().match(rule, event)

    assert not result.matched
    assert result.reason == "header did not match"


def test_rule_without_content_does_not_require_payload_context():
    rule = _rule("tcp any any -> any 80", "dsize:0;")
    event = _event(payload=b"")
    event._application_payload = "not bytes"

    result = RuleMatcher().match(rule, event)

    assert result.matched
    assert result.matched_information == []


def test_non_evaluable_rule_returns_no_match_without_raising():
    invalid = parse_rule(
        'alert udp any any -> any 80 (msg:"bad"; flags:S; sid:799999; rev:1;)'
    )

    result = RuleMatcher().match(invalid, _event())

    assert result.status == MatchStatus.NO_MATCH
    assert result.sid == 799999
    assert result.reason == "rule is not evaluable"


def test_content_matcher_returns_empty_information_when_rule_has_no_content():
    context = InspectionContext.from_event(_event(payload=b"anything"))

    assert ContentMatcher().match([], context) == []
