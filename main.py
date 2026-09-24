import argparse
import os
import logging
from pathlib import Path

from src.capture.live_capture import capture_live
from src.capture.pcap_reader import read_pcap

Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    filename="logs/app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)

def build_parser():
    parser = argparse.ArgumentParser(
        description="Packet Capture & Parser for IDS"
    )

    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument(
        "--interface",
        type=str,
        help="Network interface for live packet capture"
    )

    group.add_argument(
        "--pcap",
        type=str,
        help="Path to PCAP file"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.interface:
        capture_live(args.interface)

    elif args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"[ERROR] PCAP file not found: {args.pcap}")
            return

        read_pcap(args.pcap)


if __name__ == "__main__":
    main()