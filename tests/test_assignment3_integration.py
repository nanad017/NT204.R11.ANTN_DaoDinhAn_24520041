import json
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from main import main
from src.core_engine.runtime import CoreEngineRuntime
from src.pipeline import build_pipeline_handler
from src.schema import PreprocessInfo


def _write_rules(path, *rules):
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")
    return path


def _rule(sid, *, rev=1, content=None, port=8080):
    content_option = f'content:"{content}"; ' if content is not None else ""
    return (
        f'alert tcp any any -> any {port} (msg:"rule {sid}"; '
        f"{content_option}sid:{sid}; rev:{rev};)"
    )


def _probe_packet():
    return (
        IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=50000, dport=8080, flags="PA")
        / Raw(b"probe payload")
    )


def test_runtime_loads_multiple_files_and_resolves_duplicate_sid_by_revision(
    tmp_path,
):
    first = _write_rules(
        tmp_path / "first.rules",
        _rule(1000001, rev=1),
        _rule(1000002),
    )
    second = _write_rules(
        tmp_path / "second.rules",
        _rule(1000001, rev=3),
        _rule(1000003),
    )

    runtime = CoreEngineRuntime.from_rule_files(
        [first, second],
        disabled_sids=[1000002, 1000003],
    )

    assert runtime.load_result.files_loaded == 2
    assert runtime.active_rule_count == 1
    assert runtime.repository.rules[0].sid == 1000001
    assert runtime.repository.rules[0].rev == 3
    assert runtime.duplicate_sids == (1000001,)
    assert runtime.load_result.disabled_count == 3
    assert any("duplicate SID 1000001" in item.reason for item in runtime.diagnostics)


def test_runtime_honors_disabled_rule_file_and_reports_missing_file(tmp_path):
    enabled = _write_rules(tmp_path / "enabled.rules", _rule(1100001))
    disabled = _write_rules(tmp_path / "disabled.rules", _rule(1100002))
    missing = tmp_path / "missing.rules"

    runtime = CoreEngineRuntime.from_rule_files(
        [enabled, disabled, missing],
        disabled_files=[disabled],
    )

    assert runtime.active_rule_count == 1
    assert runtime.repository.rules[0].sid == 1100001
    assert runtime.load_result.files_seen == 3
    assert runtime.load_result.files_loaded == 1
    assert runtime.load_result.files_skipped == 1
    assert any("file disabled" in item.reason for item in runtime.diagnostics)
    assert any("could not read rule file" in item.reason for item in runtime.diagnostics)


def test_pipeline_runs_core_engine_after_flow_tracking(tmp_path):
    rule_file = _write_rules(
        tmp_path / "probe.rules",
        _rule(1200001, content="probe"),
    )
    runtime = CoreEngineRuntime.from_rule_files(rule_file)
    packets = []
    detections = []
    pipeline = build_pipeline_handler(
        "pcap",
        packets.append,
        core_engine=runtime,
        detection_handler=detections.append,
    )

    event = pipeline(_probe_packet())

    assert packets == [event]
    assert event.flow_id == 1
    assert len(detections) == 1
    assert detections[0].sid == 1200001
    assert detections[0].flow_id == event.flow_id
    assert detections[0].matched_information[0].content == "probe"
    assert runtime.evaluator.statistics.events_evaluated == 1
    assert pipeline.detections_generated == 1


class _SkipPreprocessor:
    def process(self, event):
        event.preprocess = PreprocessInfo(
            status="invalid",
            processing_action="skip",
            reason="test skip",
        )
        return event


def test_preprocessor_skip_prevents_flow_and_core_evaluation(tmp_path):
    rule_file = _write_rules(tmp_path / "skip.rules", _rule(1300001))
    runtime = CoreEngineRuntime.from_rule_files(rule_file)
    pipeline = build_pipeline_handler(
        "pcap",
        preprocessor=_SkipPreprocessor(),
        core_engine=runtime,
    )

    event = pipeline(_probe_packet())

    assert event.preprocess.processing_action == "skip"
    assert event.flow_id is None
    assert runtime.evaluator.statistics.events_evaluated == 0
    assert pipeline.detections_generated == 0


def test_detection_handler_failure_is_isolated_from_packet_output(tmp_path):
    rule_file = _write_rules(tmp_path / "writer.rules", _rule(1400001))
    runtime = CoreEngineRuntime.from_rule_files(rule_file)
    emitted = []

    def failing_writer(_detection):
        raise OSError("alert output unavailable")

    pipeline = build_pipeline_handler(
        "pcap",
        emitted.append,
        core_engine=runtime,
        detection_handler=failing_writer,
    )

    event = pipeline(_probe_packet())

    assert emitted == [event]
    assert pipeline.detections_generated == 1
    assert event.parser.status == "partial"
    assert any("Detection handler failed" in error for error in event.parser.errors)


def test_cli_processes_pcap_and_writes_separate_alert_jsonl(tmp_path, capsys):
    first_rules = _write_rules(
        tmp_path / "http-method.rules",
        _rule(1500001, content="GET ", port=80),
    )
    second_rules = _write_rules(
        tmp_path / "http-path.rules",
        _rule(1500002, content="/download.html", port=80),
    )
    events_path = tmp_path / "events.jsonl"
    flows_path = tmp_path / "flows.jsonl"
    alerts_path = tmp_path / "alerts.jsonl"
    pcap_path = Path("TEST/assignment1/http_get/input.pcap")

    exit_code = main(
        [
            "--pcap",
            str(pcap_path),
            "--output",
            str(events_path),
            "--flow-output",
            str(flows_path),
            "--rules",
            str(first_rules),
            "--rules",
            str(second_rules),
            "--alert-output",
            str(alerts_path),
            "--overwrite",
        ]
    )

    packet_events = [json.loads(line) for line in events_path.read_text().splitlines()]
    flow_events = [json.loads(line) for line in flows_path.read_text().splitlines()]
    alerts = [json.loads(line) for line in alerts_path.read_text().splitlines()]
    output = capsys.readouterr().out

    assert exit_code == 0
    assert len(packet_events) == 43
    assert len(flow_events) == 4
    assert len(alerts) == 4
    assert {alert["sid"] for alert in alerts} == {1500001, 1500002}
    assert all(alert["event_type"] == "detection" for alert in alerts)
    assert all(isinstance(alert["flow_id"], int) and alert["flow_id"] > 0 for alert in alerts)
    assert all(alert["protocol"] == "TCP" for alert in alerts)
    assert all(alert["application_protocol"] == "http" for alert in alerts)
    assert all(alert["matched_information"] for alert in alerts)
    assert "packets=43, handler_errors=0" in output
    assert "rules=2" in output
    assert "matches=4" in output
    assert "detections=4" in output
