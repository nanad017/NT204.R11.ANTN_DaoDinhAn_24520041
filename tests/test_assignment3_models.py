import json
from ipaddress import ip_network

import pytest

from src.core_engine.models import (
    ContentOption,
    DetectionEvent,
    DiagnosticKind,
    DsizeOperator,
    DsizeOption,
    EvaluationStatistics,
    IPAddressSpec,
    InternalRule,
    MatchInformation,
    MatchStatus,
    PortSpec,
    RuleDiagnostic,
    RuleHeader,
    RuleMatch,
    RuleStatus,
)
def test_rule_models_represent_valid_and_invalid_rules():
    header = RuleHeader(
        action="alert",
        protocol="tcp",
        source_ip=IPAddressSpec("192.0.2.0/24", ip_network("192.0.2.0/24")),
        source_port=PortSpec.match_any(),
        direction="->",
        destination_ip=IPAddressSpec.match_any(),
        destination_port=PortSpec.range(80, 8080),
    )
    valid = InternalRule(
        raw_text='alert tcp 192.0.2.0/24 any -> any 80:8080 (msg:"test"; sid:1; rev:1;)',
        status=RuleStatus.VALID,
        header=header,
        msg="test",
        sid=1,
        rev=1,
        contents=[ContentOption(pattern=b"admin", raw="admin", nocase=True)],
        dsize=DsizeOption(DsizeOperator.GREATER_THAN, 0),
    )
    invalid = InternalRule(
        raw_text="broken rule",
        status=RuleStatus.INVALID,
        diagnostics=[
            RuleDiagnostic(
                kind=DiagnosticKind.INVALID,
                reason="missing rule header",
                position=0,
            )
        ],
    )

    assert valid.is_evaluable
    assert valid.header.destination_port.start == 80
    assert not invalid.is_evaluable
    assert invalid.diagnostics[0].reason == "missing rule header"


def test_port_and_dsize_models_reject_impossible_ranges():
    with pytest.raises(ValueError):
        PortSpec.range(8080, 80)
    with pytest.raises(ValueError):
        DsizeOption(DsizeOperator.RANGE, 100, 10)


def test_rule_match_and_detection_event_are_json_serializable():
    information = MatchInformation(
        kind="content",
        buffer="http.decoded_path",
        field="decoded_path",
        content="../",
        start=1,
        end=4,
    )
    match = RuleMatch(
        status=MatchStatus.MATCH,
        sid=100001,
        rev=1,
        msg="Directory traversal detected",
        matched_information=[information],
    )
    detection = DetectionEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        sid=match.sid,
        rev=match.rev,
        msg=match.msg,
        priority=1,
        classtype="web-application-attack",
        src_ip="192.0.2.1",
        src_port=50000,
        dest_ip="198.51.100.1",
        dest_port=80,
        protocol="TCP",
        application_protocol="http",
        flow_id=7,
        flow_direction="forward",
        flow_role="to_server",
        matched_information=match.matched_information,
    )

    data = detection.to_dict()

    assert match.matched
    assert data["event_type"] == "detection"
    assert data["sid"] == 100001
    assert data["matched_information"][0]["content"] == "../"
    assert json.loads(json.dumps(data)) == data


def test_evaluation_statistics_accumulate_and_validate_counts():
    statistics = EvaluationStatistics()
    statistics.record(candidate_rules=4, rules_evaluated=3, matches=2)
    statistics.record(candidate_rules=1, rules_evaluated=1, matches=0)

    assert statistics.events_evaluated == 2
    assert statistics.candidate_rules == 5
    assert statistics.rules_evaluated == 4
    assert statistics.matches == 2

    with pytest.raises(ValueError):
        statistics.record(candidate_rules=1, rules_evaluated=2, matches=0)
