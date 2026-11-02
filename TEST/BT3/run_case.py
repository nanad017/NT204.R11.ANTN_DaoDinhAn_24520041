#!/usr/bin/env python3
"""Run one reproducible Assignment 3 acceptance test (T01..T14)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
BT3_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.core_engine.evaluator import RuleEvaluationEngine
from src.core_engine.loader import RuleLoader
from src.core_engine.matcher import HeaderMatcher, RuleMatcher
from src.core_engine.parser import SnortRuleParser, parse_rule
from src.core_engine.repository import RuleRepository
from src.flow_tracker import FlowTracker
from src.schema import FlowInfo, PacketEvent, TCPInfo, UDPInfo


def event(
    *,
    proto: str = "TCP",
    src_ip: str = "192.0.2.10",
    src_port: int = 50000,
    dest_ip: str = "198.51.100.20",
    dest_port: int = 80,
    payload: bytes = b"",
    flags: tuple[str, ...] = ("ACK", "PSH"),
    flow_role: str = "to_server",
    established: bool = True,
    timestamp: str = "2026-01-01T00:00:00+00:00",
) -> PacketEvent:
    packet = PacketEvent(
        timestamp=timestamp,
        flow_id=1,
        proto=proto,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        flow_direction="forward",
        flow_role=flow_role,
        flow=FlowInfo(flow_id=1, protocol=proto, established=established),
    )
    if proto.upper() == "TCP":
        packet.tcp = TCPInfo(flags=list(flags), payload_length=len(payload))
    else:
        packet.udp = UDPInfo(length=len(payload) + 8, payload_length=len(payload))
    packet._application_payload = payload
    return packet


def load(case: str):
    return RuleLoader(SnortRuleParser()).load_file(BT3_ROOT / case / "input.rules")


def rules(case: str):
    return load(case).active_rules


def t01():
    result = load("T01")
    return {
        "active_sids": [rule.sid for rule in result.active_rules],
        "diagnostic_count": len(result.diagnostics),
        "files_loaded": result.files_loaded,
        "rule_lines_seen": result.rule_lines_seen,
        "valid_count": result.valid_count,
    }


def t02():
    result = load("T02")
    return {
        "active_sids": [rule.sid for rule in result.active_rules],
        "continued_after_error": [rule.sid for rule in result.active_rules] == [3200002],
        "diagnostic_count": len(result.diagnostics),
        "diagnostic_kinds": sorted({item.kind.value for item in result.diagnostics}),
        "invalid_count": result.invalid_count,
        "valid_count": result.valid_count,
    }


def t03():
    result = load("T03")
    return {
        "active_sids": [rule.sid for rule in result.active_rules],
        "continued_after_unsupported": [rule.sid for rule in result.active_rules] == [3300002],
        "diagnostic_kinds": [item.kind.value for item in result.diagnostics],
        "unsupported_count": result.unsupported_count,
        "valid_count": result.valid_count,
    }


def t04():
    rule = rules("T04")[0]
    header = rule.header
    assert header is not None
    return {
        "destination_ip": header.destination_ip.raw,
        "destination_port": [header.destination_port.start, header.destination_port.end],
        "direction": header.direction,
        "protocol": header.protocol,
        "source_ip": header.source_ip.raw,
        "source_port": [header.source_port.start, header.source_port.end],
        "status": rule.status.value,
    }


def t05():
    forward, bidirectional = rules("T05")
    reverse = event(
        src_ip="198.51.100.20",
        src_port=80,
        dest_ip="192.0.2.10",
        dest_port=50000,
    )
    matcher = HeaderMatcher()
    return {
        "bidirectional_matches_reverse": matcher.matches(bidirectional.header, reverse),
        "forward_matches_reverse": matcher.matches(forward.header, reverse),
    }


def t06():
    repository = RuleRepository(rules("T06"))
    tcp_sids = [rule.sid for rule in repository.candidates_for_event(event(dest_port=80))]
    udp_sids = [
        rule.sid
        for rule in repository.candidates_for_event(
            event(proto="UDP", src_port=53000, dest_port=53)
        )
    ]
    return {
        "candidate_sids_tcp_80": tcp_sids,
        "candidate_sids_udp_53": udp_sids,
        "duplicates_returned": len(tcp_sids) != len(set(tcp_sids)),
        "rules_indexed": repository.statistics.rules_indexed,
    }


class CountingContentMatcher:
    def __init__(self):
        self.calls = 0

    def match(self, contents, context):
        self.calls += 1
        raise AssertionError("content matcher must not run after header rejection")


def t07():
    content_matcher = CountingContentMatcher()
    matcher = RuleMatcher(content_matcher=content_matcher)
    result = matcher.match(rules("T07")[0], event(payload=b"SECRET"))
    return {
        "content_match_calls": content_matcher.calls,
        "matched": result.matched,
        "reason": result.reason,
    }


def t08():
    tracker = FlowTracker()
    packets = [
        event(payload=b"", flags=("SYN",), timestamp="2026-01-01T00:00:00+00:00"),
        event(
            src_ip="198.51.100.20",
            src_port=80,
            dest_ip="192.0.2.10",
            dest_port=50000,
            flags=("SYN", "ACK"),
            flow_role="to_client",
            timestamp="2026-01-01T00:00:00.100000+00:00",
        ),
        event(flags=("ACK",), timestamp="2026-01-01T00:00:00.200000+00:00"),
        event(
            payload=b"AUTH",
            flags=("ACK", "PSH"),
            timestamp="2026-01-01T00:00:00.300000+00:00",
        ),
    ]
    for packet in packets:
        packet.flow_id = None
        packet.flow = None
        packet.flow_direction = None
        packet.flow_role = None
        tracker.process(packet)
    data = packets[-1]
    result = RuleMatcher().match(rules("T08")[0], data)
    return {
        "established": data.flow.established,
        "flow_role": data.flow_role,
        "matched": result.matched,
        "state": data.flow.state,
    }


def t09():
    sensitive, nocase = rules("T09")
    packet = event(payload=b"GET /ADMIN")
    matcher = RuleMatcher()
    return {
        "case_sensitive_match": matcher.match(sensitive, packet).matched,
        "nocase_match": matcher.match(nocase, packet).matched,
    }


def t10():
    matching, wrong_offset = rules("T10")
    packet = event(payload=b"xxneedlezz")
    matcher = RuleMatcher()
    return {
        "offset_2_depth_6": matcher.match(matching, packet).matched,
        "offset_3_depth_6": matcher.match(wrong_offset, packet).matched,
    }


def t11():
    matching, too_narrow = rules("T11")
    packet = event(payload=b"USER xxadmin")
    matcher = RuleMatcher()
    match = matcher.match(matching, packet)
    return {
        "distance_1_within_8": match.matched,
        "match_spans": [[item.start, item.end] for item in match.matched_information],
        "distance_1_within_6": matcher.match(too_narrow, packet).matched,
    }


def t12():
    exact, wrong_flags, too_large = rules("T12")
    packet = event(payload=b"admin", flags=("ACK", "PSH"))
    matcher = RuleMatcher()
    return {
        "flags_pa_dsize_5": matcher.match(exact, packet).matched,
        "flags_s_dsize_5": matcher.match(wrong_flags, packet).matched,
        "flags_pa_dsize_gt_5": matcher.match(too_large, packet).matched,
    }


def t13():
    repository = RuleRepository(rules("T13"))
    engine = RuleEvaluationEngine(repository)
    result = engine.evaluate(event(payload=b"admin"))
    return {
        "candidate_count": result.candidate_count,
        "error_count": len(result.errors),
        "match_count": result.match_count,
        "matched_sids": [match.sid for match in result.matches],
        "statistics": {
            "events_evaluated": engine.statistics.events_evaluated,
            "matches": engine.statistics.matches,
            "rules_evaluated": engine.statistics.rules_evaluated,
        },
    }


def _jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def t14():
    case = BT3_ROOT / "T14"
    command = [
        sys.executable,
        str(PROJECT_ROOT / "main.py"),
        "--pcap",
        str(case / "input.pcap"),
        "--output",
        str(case / "events.jsonl"),
        "--flow-output",
        str(case / "flows.jsonl"),
        "--rules",
        str(case / "input.rules"),
        "--alert-output",
        str(case / "alerts.jsonl"),
        "--overwrite",
    ]
    completed = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    print("CLI stdout:\n" + completed.stdout.rstrip())
    if completed.stderr:
        print("CLI stderr:\n" + completed.stderr.rstrip())
    events = _jsonl(case / "events.jsonl")
    flows = _jsonl(case / "flows.jsonl")
    alerts = _jsonl(case / "alerts.jsonl")
    required = {
        "timestamp",
        "event_type",
        "sid",
        "rev",
        "msg",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "protocol",
        "application_protocol",
        "flow_id",
        "flow_direction",
        "flow_role",
        "matched_information",
    }
    return {
        "alert_count": len(alerts),
        "all_required_fields_present": all(required <= set(alert) for alert in alerts),
        "cli_exit_code": completed.returncode,
        "flow_count": len(flows),
        "matched_sids": [alert["sid"] for alert in alerts],
        "packet_event_count": len(events),
        "same_flow_id": len({alert["flow_id"] for alert in alerts}) == 1,
    }


CASES = {
    "T01": t01,
    "T02": t02,
    "T03": t03,
    "T04": t04,
    "T05": t05,
    "T06": t06,
    "T07": t07,
    "T08": t08,
    "T09": t09,
    "T10": t10,
    "T11": t11,
    "T12": t12,
    "T13": t13,
    "T14": t14,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in CASES:
        print("Usage: python TEST/BT3/run_case.py T01|...|T14", file=sys.stderr)
        return 2
    case_name = sys.argv[1]
    case_dir = BT3_ROOT / case_name
    actual = CASES[case_name]()
    (case_dir / "actual.json").write_text(
        json.dumps(actual, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expected = json.loads((case_dir / "expected.json").read_text(encoding="utf-8"))
    print(json.dumps(actual, indent=2, sort_keys=True))
    if actual != expected:
        print("FAIL: actual.json differs from expected.json", file=sys.stderr)
        return 1
    print(f"PASS: {case_name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
