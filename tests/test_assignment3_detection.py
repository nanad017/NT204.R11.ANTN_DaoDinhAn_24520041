import json

import pytest

from src.core_engine.detection import (
    DetectionEventGenerationError,
    DetectionEventGenerator,
    detection_event_to_json,
    generate_detection_events,
)
from src.core_engine.evaluator import RuleEvaluationEngine
from src.core_engine.models import MatchInformation, MatchStatus, RuleMatch
from src.core_engine.parser import parse_rule
from src.core_engine.repository import RuleRepository
from src.schema import FlowInfo, PacketEvent, TCPInfo


def _rule(options="", sid=900001):
    return parse_rule(
        'alert tcp any any -> any 80 '
        f'(msg:"Phat hien {sid}"; {options} sid:{sid}; rev:2;)'
    )


def _event(payload=b"admin", *, app_proto="HTTP"):
    event = PacketEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        flow_id=42,
        src_ip="192.0.2.10",
        src_port=50000,
        dest_ip="198.51.100.20",
        dest_port=80,
        proto="tcp",
        app_proto=app_proto,
        flow_direction="forward",
        flow_role="to_server",
        flow=FlowInfo(
            flow_id=42,
            protocol="TCP",
            application_protocol="http",
            established=True,
        ),
        tcp=TCPInfo(flags=["ACK", "PSH"], payload_length=len(payload)),
    )
    event._application_payload = payload
    return event


def _evaluation_result(rules, event=None):
    packet_event = event or _event()
    return RuleEvaluationEngine(RuleRepository(rules)).evaluate(packet_event)


def test_generator_builds_complete_detection_event_from_match():
    rule = _rule(
        'content:"admin"; classtype:web-application-attack; priority:1;',
        sid=910001,
    )
    result = _evaluation_result([rule])

    detections = DetectionEventGenerator().generate_from_result(result)

    assert len(detections) == 1
    detection = detections[0]
    assert detection.timestamp == "2026-01-01T00:00:00+00:00"
    assert detection.sid == 910001
    assert detection.rev == 2
    assert detection.msg == "Phat hien 910001"
    assert detection.priority == 1
    assert detection.classtype == "web-application-attack"
    assert detection.src_ip == "192.0.2.10"
    assert detection.src_port == 50000
    assert detection.dest_ip == "198.51.100.20"
    assert detection.dest_port == 80
    assert detection.protocol == "TCP"
    assert detection.application_protocol == "http"
    assert detection.flow_id == 42
    assert detection.flow_direction == "forward"
    assert detection.flow_role == "to_server"
    assert detection.matched_information[0].content == "admin"
    assert detection.matched_information[0].buffer == "transport"
    assert detection.matched_information[0].field == "payload"
    assert detection.matched_information[0].start == 0
    assert detection.matched_information[0].end == 5


def test_generator_emits_every_match_and_ignores_no_match_results():
    first = _rule('content:"admin";', sid=920001)
    second = _rule("dsize:5;", sid=920002)
    missing = _rule('content:"missing";', sid=920003)
    result = _evaluation_result([first, second, missing])

    detections = generate_detection_events(result)

    assert [event.sid for event in detections] == [920001, 920002]


def test_no_match_returns_none_before_event_validation():
    rule = _rule(sid=930001)
    no_match = RuleMatch(
        status=MatchStatus.NO_MATCH,
        sid=930001,
        rev=2,
        msg="Phat hien 930001",
        reason="header did not match",
    )

    assert DetectionEventGenerator().generate(object(), rule, no_match) is None


def test_generator_rejects_rule_and_match_identity_mismatch():
    rule = _rule(sid=940001)
    wrong_match = RuleMatch(
        status=MatchStatus.MATCH,
        sid=940099,
        rev=2,
        msg="Phat hien 940001",
    )

    with pytest.raises(
        DetectionEventGenerationError,
        match="rule and match identity",
    ):
        DetectionEventGenerator().generate(_event(), rule, wrong_match)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("timestamp", "", "event.timestamp is required"),
        ("src_ip", "invalid", "event.src_ip must be a valid IPv4"),
        ("dest_ip", "2001:db8::1", "event.dest_ip must be a valid IPv4"),
        ("src_port", True, "event.src_port must be an integer"),
        ("dest_port", 70000, "event.dest_port must be an integer"),
        ("proto", "ICMP", "event.proto must be TCP or UDP"),
    ],
)
def test_generator_rejects_incomplete_or_invalid_event_fields(field, value, reason):
    rule = _rule(sid=950001)
    result = _evaluation_result([rule])
    event = _event()
    setattr(event, field, value)

    with pytest.raises(DetectionEventGenerationError, match=reason):
        DetectionEventGenerator().generate(
            event,
            rule,
            result.matches[0],
        )


def test_flow_id_falls_back_to_flow_context_and_is_required():
    rule = _rule(sid=960001)
    result = _evaluation_result([rule])
    event = _event()
    event.flow_id = None

    detection = DetectionEventGenerator().generate(event, rule, result.matches[0])
    assert detection.flow_id == 42

    event.flow = None
    with pytest.raises(DetectionEventGenerationError, match="event.flow_id"):
        DetectionEventGenerator().generate(event, rule, result.matches[0])


def test_unknown_application_protocol_is_explicit_in_serialized_event():
    rule = _rule(sid=970001)
    event = _event(app_proto=None)
    result = _evaluation_result([rule], event)

    detection = generate_detection_events(result)[0]
    serialized = json.loads(detection_event_to_json(detection))

    assert serialized["event_type"] == "detection"
    assert serialized["application_protocol"] == "unknown"
    assert serialized["flow_id"] == 42
    assert serialized["sid"] == 970001
    assert serialized["matched_information"] == [
        {"kind": "rule", "field": "header/options"}
    ]


def test_generator_copies_match_information_for_output_isolation():
    rule = _rule('content:"admin";', sid=980001)
    result = _evaluation_result([rule])
    evaluation = result.matched_evaluations[0]

    detection = DetectionEventGenerator().generate_for_evaluation(
        result.event,
        evaluation,
    )
    evaluation.match.matched_information.append(
        MatchInformation(kind="synthetic", field="later mutation")
    )

    assert detection is not None
    assert len(detection.matched_information) == 1
    assert detection.matched_information is not evaluation.match.matched_information


def test_json_serializer_rejects_non_detection_objects():
    with pytest.raises(TypeError, match="DetectionEvent"):
        detection_event_to_json(object())
