from src.core_engine.models import InternalRule, RuleStatus
from src.core_engine.parser import parse_rule
from src.core_engine.repository import RuleRepository
from src.schema import PacketEvent


def _rule(header, sid):
    return parse_rule(
        f'alert {header} (msg:"rule {sid}"; sid:{sid}; rev:1;)'
    )


def _sids(rules):
    return [rule.sid for rule in rules]


def test_repository_only_stores_valid_enabled_complete_rules():
    valid = _rule("tcp any any -> any 80", 600001)
    invalid = parse_rule(
        'alert tcp bad-ip any -> any 80 (msg:"bad"; sid:600002; rev:1;)'
    )
    unsupported = parse_rule(
        'alert icmp any any -> any any (msg:"icmp"; sid:600003; rev:1;)'
    )
    disabled = _rule("tcp any any -> any 443", 600004)
    disabled.enabled = False
    incomplete = InternalRule(
        raw_text="incomplete",
        status=RuleStatus.VALID,
        sid=600005,
        rev=1,
        msg="incomplete",
    )

    repository = RuleRepository()
    result = repository.add_many(
        [valid, invalid, unsupported, disabled, incomplete]
    )

    assert result.added == 1
    assert result.skipped == 4
    assert len(repository) == 1
    assert repository.rules == (valid,)
    assert repository.statistics.rules_skipped == 4


def test_repository_selects_candidates_by_protocol_and_destination_port():
    tcp_http = _rule("tcp any any -> any 80", 610001)
    tcp_any = _rule("tcp any any -> any any", 610002)
    udp_dns = _rule("udp any any -> any 53", 610003)
    repository = RuleRepository([tcp_http, tcp_any, udp_dns])

    assert _sids(repository.get_candidates("TCP", 50000, 80)) == [610001, 610002]
    assert _sids(repository.get_candidates("tcp", 50000, 443)) == [610002]
    assert _sids(repository.get_candidates("UDP", 53000, 53)) == [610003]
    assert repository.protocol_rule_count("tcp") == 2
    assert repository.protocol_rule_count("UDP") == 1


def test_repository_indexes_directional_source_single_port():
    source_specific = _rule("tcp any 12345 -> any any", 620001)
    repository = RuleRepository([source_specific])

    assert _sids(repository.get_candidates("tcp", 12345, 80)) == [620001]
    assert repository.get_candidates("tcp", 80, 12345) == []


def test_repository_filters_port_ranges_and_includes_boundaries():
    ranged = _rule("tcp any 1000:2000 -> any 8080:8090", 630001)
    repository = RuleRepository([ranged])

    assert _sids(repository.get_candidates("tcp", 1000, 8080)) == [630001]
    assert _sids(repository.get_candidates("tcp", 2000, 8090)) == [630001]
    assert repository.get_candidates("tcp", 999, 8080) == []
    assert repository.get_candidates("tcp", 1500, 8091) == []


def test_bidirectional_rules_match_both_directions_without_duplicates():
    bidirectional = _rule("tcp any 443 <> any 8443", 640001)
    repository = RuleRepository([bidirectional])

    forward = repository.get_candidates("tcp", 443, 8443)
    reverse = repository.get_candidates("tcp", 8443, 443)

    assert _sids(forward) == [640001]
    assert _sids(reverse) == [640001]
    assert len(forward) == len(set(id(rule) for rule in forward))
    assert len(reverse) == len(set(id(rule) for rule in reverse))


def test_ip_constraints_are_left_for_phase_5_header_matcher():
    network_rule = _rule("tcp 192.0.2.0/24 any -> 198.51.100.10 80", 650001)
    repository = RuleRepository([network_rule])

    candidates = repository.get_candidates("tcp", 50000, 80)

    assert _sids(candidates) == [650001]


def test_candidates_for_event_normalizes_protocol_and_rejects_bad_ports():
    repository = RuleRepository([_rule("udp any any -> any 53", 660001)])
    event = PacketEvent(
        timestamp="2026-01-01T00:00:00+00:00",
        proto="UDP",
        src_port=53000,
        dest_port=53,
    )

    assert _sids(repository.candidates_for_event(event)) == [660001]
    event.src_port = None
    assert repository.candidates_for_event(event) == []
    assert repository.get_candidates("udp", True, 53) == []
    assert repository.get_candidates(None, 53000, 53) == []


def test_add_same_rule_object_twice_is_counted_and_not_duplicated():
    rule = _rule("tcp any any -> any 80", 670001)
    repository = RuleRepository()

    result = repository.add_many([rule, rule])

    assert result.added == 1
    assert result.duplicates == 1
    assert len(repository) == 1
    assert repository.statistics.duplicate_additions == 1


def test_rebuild_replaces_indexes_and_resets_query_statistics():
    repository = RuleRepository([_rule("tcp any any -> any 80", 680001)])
    repository.get_candidates("tcp", 50000, 80)

    update = repository.rebuild([_rule("udp any any -> any 53", 680002)])

    assert update.added == 1
    assert repository.get_candidates("tcp", 50000, 80) == []
    assert _sids(repository.get_candidates("udp", 53000, 53)) == [680002]
    assert repository.statistics.candidate_queries == 2
    assert repository.statistics.candidates_returned == 1


def test_rule_disabled_after_indexing_is_not_returned():
    rule = _rule("tcp any any -> any 80", 690001)
    repository = RuleRepository([rule])
    rule.enabled = False

    assert repository.get_candidates("tcp", 50000, 80) == []
