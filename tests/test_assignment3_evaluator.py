from src.core_engine.evaluator import RuleEvaluationEngine, evaluate_event
from src.core_engine.inspection import InspectionContext, InspectionContextBuilder
from src.core_engine.matcher import RuleMatcher
from src.core_engine.models import MatchStatus
from src.core_engine.parser import parse_rule
from src.core_engine.repository import RuleRepository
from src.schema import FlowInfo, PacketEvent, TCPInfo, UDPInfo


def _rule(header, options="", sid=800001):
    return parse_rule(
        f'alert {header} (msg:"rule {sid}"; {options} sid:{sid}; rev:1;)'
    )


def _event(
    *,
    proto="TCP",
    src_ip="192.0.2.10",
    src_port=50000,
    dest_ip="198.51.100.20",
    dest_port=80,
    payload=b"admin",
):
    event = PacketEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        proto=proto,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        flow_role="to_server",
        flow=FlowInfo(
            flow_id=1,
            protocol=proto,
            established=True,
        ),
    )
    if proto == "TCP":
        event.tcp = TCPInfo(flags=["ACK", "PSH"], payload_length=len(payload))
    else:
        event.udp = UDPInfo(length=len(payload) + 8, payload_length=len(payload))
    event._application_payload = payload
    return event


def test_engine_evaluates_all_candidates_and_returns_multiple_matches():
    content_match = _rule(
        "tcp any any -> any 80",
        'content:"admin";',
        sid=810001,
    )
    size_match = _rule("tcp any any -> any 80", "dsize:5;", sid=810002)
    no_match = _rule(
        "tcp any any -> any 80",
        'content:"missing";',
        sid=810003,
    )
    wrong_protocol = _rule("udp any any -> any 80", sid=810004)
    engine = RuleEvaluationEngine(
        RuleRepository([content_match, size_match, no_match, wrong_protocol])
    )

    result = engine.evaluate(_event())

    assert result.candidates == (content_match, size_match, no_match)
    assert result.candidate_count == 3
    assert result.rules_evaluated == 3
    assert [item.rule.sid for item in result.evaluations] == [810001, 810002, 810003]
    assert [match.sid for match in result.matches] == [810001, 810002]
    assert result.matched_rules == (content_match, size_match)
    assert result.match_count == 2
    assert result.errors == ()
    assert engine.statistics.events_evaluated == 1
    assert engine.statistics.candidate_rules == 3
    assert engine.statistics.rules_evaluated == 3
    assert engine.statistics.matches == 2


def test_repository_candidate_can_still_be_rejected_by_header_matcher():
    ip_specific = _rule(
        "tcp 203.0.113.10 any -> any 80",
        sid=820001,
    )

    result = RuleEvaluationEngine(RuleRepository([ip_specific])).evaluate(_event())

    assert result.candidate_count == 1
    assert result.match_count == 0
    assert result.evaluations[0].match.status == MatchStatus.NO_MATCH
    assert result.evaluations[0].match.reason == "header did not match"


def test_statistics_accumulate_across_events_and_reset_in_place():
    rule = _rule("tcp any any -> any any", sid=830001)
    engine = RuleEvaluationEngine(RuleRepository([rule]))
    statistics = engine.statistics

    engine.evaluate(_event(dest_port=80))
    engine.evaluate(_event(dest_port=443))

    assert statistics.events_evaluated == 2
    assert statistics.candidate_rules == 2
    assert statistics.rules_evaluated == 2
    assert statistics.matches == 2

    engine.reset_statistics()

    assert engine.statistics is statistics
    assert statistics.events_evaluated == 0
    assert statistics.candidate_rules == 0
    assert statistics.rules_evaluated == 0
    assert statistics.matches == 0


class _FailingMatcher:
    def __init__(self, failing_sid):
        self.failing_sid = failing_sid
        self.delegate = RuleMatcher()

    def match(self, rule, event, context=None, *, payload=None):
        if rule.sid == self.failing_sid:
            raise RuntimeError("synthetic matcher failure")
        return self.delegate.match(rule, event, context, payload=payload)


def test_one_rule_error_does_not_hide_other_matches():
    first = _rule("tcp any any -> any 80", sid=840001)
    broken = _rule("tcp any any -> any 80", sid=840002)
    last = _rule("tcp any any -> any 80", sid=840003)
    broken.source_file = "broken.rules"
    broken.source_line = 17
    engine = RuleEvaluationEngine(
        RuleRepository([first, broken, last]),
        matcher=_FailingMatcher(840002),
    )

    result = engine.evaluate(_event())

    assert [match.sid for match in result.matches] == [840001, 840003]
    assert result.rules_evaluated == 3
    assert len(result.errors) == 1
    assert result.errors[0].sid == 840002
    assert result.errors[0].error_type == "RuntimeError"
    assert result.errors[0].reason == "synthetic matcher failure"
    assert result.errors[0].source_file == "broken.rules"
    assert result.errors[0].source_line == 17
    assert engine.statistics.matches == 2


class _InvalidResultMatcher(_FailingMatcher):
    def match(self, rule, event, context=None, *, payload=None):
        if rule.sid == self.failing_sid:
            return "not a RuleMatch"
        return super().match(rule, event, context, payload=payload)


def test_invalid_matcher_result_is_isolated_as_a_rule_error():
    invalid_result = _rule("tcp any any -> any 80", sid=850001)
    valid_result = _rule("tcp any any -> any 80", sid=850002)
    engine = RuleEvaluationEngine(
        RuleRepository([invalid_result, valid_result]),
        matcher=_InvalidResultMatcher(850001),
    )

    result = engine.evaluate(_event())

    assert [match.sid for match in result.matches] == [850002]
    assert result.errors[0].sid == 850001
    assert result.errors[0].error_type == "TypeError"
    assert result.errors[0].reason == "matcher must return a RuleMatch"


class _CountingInspectionBuilder:
    def __init__(self):
        self.calls = 0
        self.delegate = InspectionContextBuilder()

    def build(self, event, *, payload=None):
        self.calls += 1
        return self.delegate.build(event, payload=payload)


def test_inspection_context_is_built_once_for_all_content_candidates():
    first = _rule("tcp any any -> any 80", 'content:"adm";', sid=860001)
    second = _rule("tcp any any -> any 80", 'content:"min";', sid=860002)
    builder = _CountingInspectionBuilder()
    engine = RuleEvaluationEngine(
        RuleRepository([first, second]),
        inspection_builder=builder,
    )

    result = engine.evaluate(_event())

    assert result.match_count == 2
    assert builder.calls == 1


def test_prebuilt_context_is_reused_without_calling_builder():
    rule = _rule("tcp any any -> any 80", 'content:"admin";', sid=870001)
    event = _event()
    context = InspectionContext.from_event(event)
    builder = _CountingInspectionBuilder()
    engine = RuleEvaluationEngine(
        RuleRepository([rule]),
        inspection_builder=builder,
    )

    result = engine.evaluate(event, context)

    assert result.match_count == 1
    assert builder.calls == 0


def test_bad_payload_only_errors_content_rules_and_engine_continues():
    content_rule = _rule(
        "tcp any any -> any 80",
        'content:"admin";',
        sid=880001,
    )
    header_only_rule = _rule("tcp any any -> any 80", sid=880002)
    event = _event()
    event._application_payload = "not bytes"
    engine = RuleEvaluationEngine(
        RuleRepository([content_rule, header_only_rule])
    )

    result = engine.evaluate(event)

    assert [match.sid for match in result.matches] == [880002]
    assert result.errors[0].sid == 880001
    assert result.errors[0].error_type == "TypeError"
    assert result.rules_evaluated == 2
    assert engine.statistics.matches == 1


def test_no_candidates_still_records_an_evaluated_event():
    engine = RuleEvaluationEngine(
        RuleRepository([_rule("udp any any -> any 53", sid=890001)])
    )

    result = engine.evaluate(_event())

    assert result.candidates == ()
    assert result.evaluations == ()
    assert result.matches == ()
    assert engine.statistics.events_evaluated == 1
    assert engine.statistics.candidate_rules == 0


def test_convenience_apis_return_the_same_match_contract():
    rule = _rule("tcp any any -> any 80", sid=895001)
    repository = RuleRepository([rule])
    event = _event()

    function_result = evaluate_event(repository, event)
    engine_matches = RuleEvaluationEngine(repository).evaluate_matches(event)

    assert [match.sid for match in function_result.matches] == [895001]
    assert [match.sid for match in engine_matches] == [895001]
