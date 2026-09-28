import logging
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff

from src.capture.common import CaptureStats, build_packet_callback

logger = logging.getLogger(__name__)


def read_pcap(
    pcap_path,
    packet_handler=None,
):
    stats = CaptureStats()
    path = Path(pcap_path)

    try:
        if not path.is_file():
            stats.error = "PCAP file not found"
            logger.error("%s: %s", stats.error, path)
            return stats
        if path.stat().st_size == 0:
            stats.error = "PCAP file is empty"
            logger.error("%s: %s", stats.error, path)
            return stats
    except OSError as exc:
        stats.error = f"Could not access PCAP file: {exc}"
        logger.error("%s", stats.error)
        return stats

    callback = build_packet_callback(packet_handler, stats)
    logger.info("Reading PCAP file: %s", path)
    try:
        sniff(offline=str(path), prn=callback, store=False)
    except (OSError, Scapy_Exception) as exc:
        stats.error = f"Could not read PCAP file: {exc}"
        logger.error("%s", stats.error)
    finally:
        logger.info(
            "PCAP read complete for %s: packets=%s handler_errors=%s",
            path,
            stats.packets_seen,
            stats.handler_errors,
        )

    return stats
