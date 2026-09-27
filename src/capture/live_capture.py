import logging

from scapy.error import Scapy_Exception
from scapy.sendrecv import sniff

from src.capture.common import CaptureStats, build_packet_callback

logger = logging.getLogger(__name__)


def capture_live(
    interface,
    packet_handler=None,
):
    stats = CaptureStats()
    if not interface or not interface.strip():
        stats.error = "Network interface is required"
        return stats

    callback = build_packet_callback(packet_handler, stats)
    logger.info("Starting live capture on interface: %s", interface)
    try:
        sniff(iface=interface, prn=callback, store=False)
    except KeyboardInterrupt:
        logger.info("Live capture stopped by user on interface: %s", interface)
    except (OSError, Scapy_Exception) as exc:
        stats.error = f"Could not capture from interface '{interface}': {exc}"
        logger.error("%s", stats.error)
    finally:
        logger.info(
            "Live capture complete on %s: packets=%s handler_errors=%s",
            interface,
            stats.packets_seen,
            stats.handler_errors,
        )

    return stats
