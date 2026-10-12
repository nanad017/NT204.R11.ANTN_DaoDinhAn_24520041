import argparse
from pathlib import Path

from src.capture.live_capture import capture_live
from src.capture.pcap_reader import read_pcap
from src.config import ProcessingConfig
from src.logger import prepare_output, write_event, write_flow, configure_logging
from src.pipeline import build_pipeline_handler


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
    pipeline_handler = build_pipeline_handler(
        source,
        lambda event: write_event(event, output_file),
        config=config,
        flow_handler=(lambda flow: write_flow(flow, flow_output)) if flow_output else None,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
