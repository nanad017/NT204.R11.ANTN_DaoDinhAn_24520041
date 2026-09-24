from pathlib import Path
import logging

from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff

from src.capture.common import process_packet


logger = logging.getLogger(__name__)


def read_pcap(pcap_path):
    path = Path(pcap_path)

    if not path.is_file():
        print(f"[ERROR] PCAP file not found: {path}")
        logger.error("PCAP file not found: %s", path)
        return

    if path.stat().st_size == 0:
        print(f"[ERROR] PCAP file is empty: {path}")
        logger.error("PCAP file is empty: %s", path)
        return

    print(f"[INFO] Reading PCAP file: {path}")
    logger.info("Reading PCAP file: %s", path)

    try:
        sniff(
            offline=str(path),
            prn=process_packet,
            store=False,
        )

    except (OSError, Scapy_Exception) as exc:
        print(f"[ERROR] Could not read PCAP file '{path}': {exc}")
        logger.error(
            "Could not read PCAP file '%s': %s",
            path,
            exc,
        )

    finally:
        print(f"[INFO] PCAP read complete: {path}")
        logger.info("PCAP read complete: %s", path)