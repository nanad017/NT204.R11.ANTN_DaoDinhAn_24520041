import argparse
import logging
from pathlib import Path

from src.capture.live_capture import capture_live
from src.capture.pcap_reader import read_pcap
from src.config import ProcessingConfig
from src.core_engine.runtime import CoreEngineRuntime
from src.logger import prepare_output, write_event, write_flow, configure_logging
from src.pipeline import build_pipeline_handler

logger = logging.getLogger(__name__)


def build_parser():
    parser = argparse.ArgumentParser(description="Packet Capture & Parser for IDS")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="Network interface for live capture")
    source.add_argument("--pcap", help="Path to a PCAP file")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/events.jsonl"),
        help="JSON Lines output path",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the output file instead of appending to it",
    )
    parser.add_argument(
        "--flow-output",
        type=Path,
        help="Optional JSON Lines output path for finalized flow summaries",
    )
    parser.add_argument("--tcp-idle-timeout", type=float, default=300.0)
    parser.add_argument("--udp-idle-timeout", type=float, default=60.0)
    parser.add_argument("--max-active-flows", type=int, default=100000)
    parser.add_argument("--max-decoded-content-size", type=int, default=1048576)
    parser.add_argument(
        "--invalid-event-policy",
        choices=("retain", "skip"),
        default="retain",
    )
    parser.add_argument(
        "--unsupported-data-policy",
        choices=("retain", "skip"),
        default="retain",
    )
    parser.add_argument(
        "--rules",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Snort rule file; repeat to load multiple files",
    )
    parser.add_argument(
        "--disable-rule-file",
        action="append",
        type=Path,
        default=[],
        metavar="FILE",
        help="Disable a rule file by path; repeat as needed",
    )
    parser.add_argument(
        "--disable-sid",
        action="append",
        type=_positive_sid,
        default=[],
        metavar="SID",
        help="Disable a positive Snort SID; repeat as needed",
    )
    parser.add_argument(
        "--alert-output",
        type=Path,
        default=Path("output/alerts.jsonl"),
        help="JSON Lines output path for Detection Events",
    )
    return parser

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        configure_logging()
        output_file = prepare_output(args.output, truncate=args.overwrite)
        flow_output = (
            prepare_output(args.flow_output, truncate=args.overwrite)
            if args.flow_output
            else None
        )
        core_engine = (
            CoreEngineRuntime.from_rule_files(
                args.rules,
                disabled_files=args.disable_rule_file,
                disabled_sids=args.disable_sid,
            )
            if args.rules
            else None
        )
        alert_output = (
            prepare_output(args.alert_output, truncate=args.overwrite)
            if core_engine is not None
            else None
        )
        config = ProcessingConfig(
            tcp_idle_timeout=args.tcp_idle_timeout,
            udp_idle_timeout=args.udp_idle_timeout,
            max_active_flows=args.max_active_flows,
            max_decoded_content_size=args.max_decoded_content_size,
            invalid_event_policy=args.invalid_event_policy,
            unsupported_data_policy=args.unsupported_data_policy,
        )
    except OSError as exc:
        print(f"[ERROR] Could not prepare output: {exc}")
        return 2
    except ValueError as exc:
        print(f"[ERROR] Invalid processing configuration: {exc}")
        return 2

    source = "live" if args.interface else "pcap"
    if core_engine is not None:
        _log_rule_load(core_engine)
    pipeline_handler = build_pipeline_handler(
        source,
        lambda event: write_event(event, output_file),
        config=config,
        flow_handler=(lambda flow: write_flow(flow, flow_output)) if flow_output else None,
        core_engine=core_engine,
        detection_handler=(
            (lambda detection: write_event(detection, alert_output))
            if alert_output
            else None
        ),
    )
    if args.interface:
        stats = capture_live(args.interface, packet_handler=pipeline_handler)
    else:
        stats = read_pcap(args.pcap, packet_handler=pipeline_handler)
    pipeline_handler.flush()

    if stats.error:
        print(f"[ERROR] {stats.error}")
        return 1

    print(
        "Capture complete: "
        f"packets={stats.packets_seen}, handler_errors={stats.handler_errors}"
    )
    if core_engine is not None:
        statistics = core_engine.evaluator.statistics
        print(
            "Core Engine complete: "
            f"rules={core_engine.active_rule_count}, "
            f"events={statistics.events_evaluated}, "
            f"candidates={statistics.candidate_rules}, "
            f"matches={statistics.matches}, "
            f"detections={pipeline_handler.detections_generated}"
        )
    return 0


def _positive_sid(value):
    try:
        sid = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("SID must be a positive integer") from exc
    if sid <= 0:
        raise argparse.ArgumentTypeError("SID must be a positive integer")
    return sid


def _log_rule_load(core_engine):
    result = core_engine.load_result
    logger.info(
        "Rule load complete: files=%s loaded=%s active=%s invalid=%s "
        "unsupported=%s disabled=%s",
        result.files_seen,
        result.files_loaded,
        core_engine.active_rule_count,
        result.invalid_count,
        result.unsupported_count,
        result.disabled_count,
    )
    for diagnostic in core_engine.diagnostics:
        location = diagnostic.source_file
        if diagnostic.source_line is not None:
            location = f"{location}:{diagnostic.source_line}"
        logger.warning("Rule diagnostic at %s: %s", location, diagnostic.reason)


if __name__ == "__main__":
    raise SystemExit(main())
