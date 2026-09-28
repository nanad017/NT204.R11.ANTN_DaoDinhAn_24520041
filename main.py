import argparse
from pathlib import Path

from src.capture.live_capture import capture_live
from src.capture.pcap_reader import read_pcap
from src.logger import prepare_output, write_event, configure_logging
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
    return parser

def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        configure_logging()
        output_file = prepare_output(args.output, truncate=args.overwrite)
    except OSError as exc:
        print(f"[ERROR] Could not prepare output: {exc}")
        return 2

    source = "live" if args.interface else "pcap"
    pipeline_handler = build_pipeline_handler(
        source,
        lambda event: write_event(event, output_file),
    )
    if args.interface:
        stats = capture_live(args.interface, packet_handler=pipeline_handler)
    else:
        stats = read_pcap(args.pcap, packet_handler=pipeline_handler)

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
