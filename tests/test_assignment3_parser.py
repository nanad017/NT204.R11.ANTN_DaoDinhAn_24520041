import pytest

from src.core_engine.loader import RuleLoader
from src.core_engine.models import DsizeOperator, RuleStatus
from src.core_engine.parser import SnortRuleParser, parse_rule


def test_parser_builds_complete_internal_rule_for_supported_keywords():
    rule = parse_rule(
        "alert tcp 192.0.2.10 1024:65535 -> 198.51.100.0/24 80 "
        '(msg:"Traversal; detected"; flow:to_server,established; '
        'content:"../"; nocase; offset:1; depth:20; flags:PA; dsize:>0; '
        "classtype:web-application-attack; priority:1; sid:100001; rev:2;)"
    )

    assert rule.status == RuleStatus.VALID
    assert rule.is_evaluable
    assert rule.header.action == "alert"
    assert rule.header.protocol == "tcp"
    assert rule.header.source_ip.network.prefixlen == 32
    assert rule.header.source_port.start == 1024
    assert rule.header.source_port.end == 65535
    assert rule.header.destination_ip.network.prefixlen == 24
    assert rule.header.destination_port.start == 80
    assert rule.msg == "Traversal; detected"
    assert rule.flow == ("to_server", "established")
    assert rule.contents[0].pattern == b"../"
    assert rule.contents[0].nocase is True
    assert rule.contents[0].offset == 1
    assert rule.contents[0].depth == 20
    assert rule.flags == frozenset({"PSH", "ACK"})
    assert rule.dsize.operator == DsizeOperator.GREATER_THAN
    assert rule.dsize.value == 0
    assert rule.classtype == "web-application-attack"
    assert rule.priority == 1
    assert rule.sid == 100001
    assert rule.rev == 2


def test_parser_supports_udp_any_and_bidirectional_header():
    rule = parse_rule(
        'alert udp any any <> 203.0.113.53 53 (msg:"DNS traffic"; sid:100002; rev:1;)'
    )

    assert rule.status == RuleStatus.VALID
    assert rule.header.protocol == "udp"
    assert rule.header.source_ip.is_any
    assert rule.header.source_port.is_any
    assert rule.header.direction == "<>"
    assert rule.header.destination_port.is_single


def test_parser_links_distance_and_within_to_second_content():
    rule = parse_rule(
        'alert tcp any any -> any 80 (msg:"relative"; content:"USER"; '
        'content:"admin"; distance:1; within:12; sid:100003; rev:1;)'
    )

    assert rule.status == RuleStatus.VALID
    assert len(rule.contents) == 2
    assert rule.contents[0].distance is None
    assert rule.contents[1].distance == 1
    assert rule.contents[1].within == 12


def test_parser_decodes_content_hex_blocks_and_escaped_characters():
    rule = parse_rule(
        r'alert tcp any any -> any 80 (msg:"escaped \"quote\""; '
        r'content:"GET|20|/a\;b|0d 0a|"; sid:100004; rev:1;)'
    )

    assert rule.status == RuleStatus.VALID
    assert rule.msg == 'escaped "quote"'
    assert rule.contents[0].pattern == b"GET /a;b\r\n"


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "empty"),
        ("alert tcp any any -> any 80", "opening parenthesis"),
        (
            'alert tcp bad-ip any -> any 80 (msg:"x"; sid:1; rev:1;)',
            "invalid IPv4",
        ),
        (
            'alert tcp any 90000 -> any 80 (msg:"x"; sid:1; rev:1;)',
            "port range",
        ),
        (
            'alert tcp any any => any 80 (msg:"x"; sid:1; rev:1;)',
            "direction",
        ),
        (
            'alert tcp any any -> any 80 (msg:"x"; sid:not-int; rev:1;)',
            "sid must be an integer",
        ),
    ],
)
def test_parser_marks_malformed_rules_invalid_without_raising(text, reason):
    rule = parse_rule(text)

    assert rule.status == RuleStatus.INVALID
    assert any(reason in item.reason for item in rule.diagnostics)


def test_validator_requires_msg_sid_and_rev():
    rule = parse_rule("alert tcp any any -> any 80 (content:\"x\";)")

    assert rule.status == RuleStatus.INVALID
    reasons = {item.reason for item in rule.diagnostics}
    assert "msg is required" in reasons
    assert "sid must be a positive integer" in reasons
    assert "rev must be a positive integer" in reasons


@pytest.mark.parametrize(
    "text",
    [
        'drop tcp any any -> any 80 (msg:"x"; sid:200001; rev:1;)',
        'alert icmp any any -> any any (msg:"x"; sid:200002; rev:1;)',
        'alert tcp any any -> any 80 (msg:"x"; pcre:"/x/"; sid:200003; rev:1;)',
        'alert tcp any any -> any 80 (msg:"x"; content:!"deny"; sid:200004; rev:1;)',
    ],
)
def test_parser_classifies_out_of_scope_constructs_as_unsupported(text):
    rule = parse_rule(text)

    assert rule.status == RuleStatus.UNSUPPORTED
    assert rule.diagnostics


def test_invalid_diagnostic_has_precedence_over_unsupported():
    rule = parse_rule(
        'alert tcp any any -> any 80 (msg:"x"; pcre:"/x/"; sid:0; rev:1;)'
    )

    assert rule.status == RuleStatus.INVALID
    assert {item.kind.value for item in rule.diagnostics} >= {"invalid", "unsupported"}


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ("nocase;", "preceding content"),
        ('content:"one"; distance:1;', "first content"),
        ('content:"one"; offset:0; distance:1;', "cannot mix"),
        ('content:"one"; depth:0;', "depth must be at least 1"),
        ('content:"one"; nocase; nocase;', "duplicate content modifier"),
    ],
)
def test_parser_rejects_invalid_content_modifier_combinations(options, reason):
    rule = parse_rule(
        f'alert tcp any any -> any 80 (msg:"x"; {options} sid:300001; rev:1;)'
    )

    assert rule.status == RuleStatus.INVALID
    assert any(reason in item.reason for item in rule.diagnostics)


@pytest.mark.parametrize(
    ("options", "reason"),
    [
        ("flow:to_server,to_client;", "both to_server and to_client"),
        ("flow:established,not_established;", "both established and not_established"),
        ("flow:from_client;", "unsupported flow value"),
        ("flags:S;", "flags can only be used with TCP"),
        ("flow:established;", "requires a TCP rule"),
    ],
)
def test_validator_checks_flow_and_tcp_only_options(options, reason):
    rule = parse_rule(
        f'alert udp any any -> any 53 (msg:"x"; {options} sid:300002; rev:1;)'
    )

    expected = RuleStatus.UNSUPPORTED if "from_client" in options else RuleStatus.INVALID
    assert rule.status == expected
    assert any(reason in item.reason for item in rule.diagnostics)


@pytest.mark.parametrize(
    ("expression", "operator", "value", "upper"),
    [
        ("42", DsizeOperator.EQUAL, 42, None),
        ("<42", DsizeOperator.LESS_THAN, 42, None),
        (">42", DsizeOperator.GREATER_THAN, 42, None),
        ("10<>42", DsizeOperator.RANGE, 10, 42),
    ],
)
def test_parser_supports_dsize_comparisons(expression, operator, value, upper):
    rule = parse_rule(
        f'alert tcp any any -> any 80 (msg:"x"; dsize:{expression}; sid:400001; rev:1;)'
    )

    assert rule.status == RuleStatus.VALID
    assert rule.dsize.operator == operator
    assert rule.dsize.value == value
    assert rule.dsize.upper == upper


def test_parser_preserves_source_metadata_and_rejects_duplicate_single_options():
    rule = SnortRuleParser().parse(
        'alert tcp any any -> any 80 (msg:"first"; msg:"second"; sid:1; rev:1;)',
        source_file="local.rules",
        source_line=17,
    )

    assert rule.status == RuleStatus.INVALID
    assert rule.source_file == "local.rules"
    assert rule.source_line == 17
    assert any("duplicate option: msg" in item.reason for item in rule.diagnostics)


def test_real_parser_integrates_with_loader_and_keeps_processing(tmp_path):
    rule_file = tmp_path / "integration.rules"
    rule_file.write_text(
        'alert tcp any any -> any 80 (msg:"valid"; sid:500001; rev:1;)\n'
        'alert tcp bad-ip any -> any 80 (msg:"invalid"; sid:500002; rev:1;)\n'
        'alert tcp any any -> any 80 (msg:"unsupported"; pcre:"/x/"; '
        "sid:500003; rev:1;)\n",
        encoding="utf-8",
    )

    result = RuleLoader(SnortRuleParser()).load_file(rule_file)

    assert len(result.rules) == 3
    assert result.valid_count == 1
    assert result.invalid_count == 1
    assert result.unsupported_count == 1
    assert [rule.source_line for rule in result.rules] == [1, 2, 3]
