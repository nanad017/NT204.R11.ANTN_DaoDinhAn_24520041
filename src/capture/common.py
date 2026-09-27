import logging

logger = logging.getLogger(__name__)


class CaptureStats:
    def __init__(self, packets_seen=0, handler_errors=0, error=None):
        self.packets_seen = packets_seen
        self.handler_errors = handler_errors
        self.error = error


def display_packet(packet):
    logger.info("%s", packet.summary())


def build_packet_callback(
    packet_handler,
    stats,
):
    handler = packet_handler or display_packet

    def callback(packet):
        stats.packets_seen += 1
        try:
            handler(packet)
        except Exception as exc:
            stats.handler_errors += 1
            logger.exception(
                "Packet handler failed for packet %s: %s",
                stats.packets_seen,
                exc,
            )

    return callback
