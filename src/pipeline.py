import logging
from datetime import datetime, timezone

from src.detection.application_detector import detect_application
from src.parsers.dns import parse_dns
from src.parsers.http import parse_http
from src.parsers.network import parse_ipv4
from src.parsers.smtp import parse_smtp
from src.parsers.tcp import parse_tcp
from src.parsers.udp import parse_udp
from src.schema import PacketEvent

logger = logging.getLogger(__name__)


class PacketPipeline:
    def __init__(
        self,
        packet_source,
        event_handler=None,
    ):
        self.packet_source = packet_source
        self.event_handler = event_handler
        self.packet_count = 0

    def __call__(self, packet):
        self.packet_count += 1
        event = process_packet(
            packet,
            packet_number=self.packet_count,
            packet_source=self.packet_source,
        )
        if self.event_handler is not None:
            try:
                self.event_handler(event)
            except Exception as exc:
                event.parser.errors.append(f"Event handler failed: {exc}")
                _finalize_status(event)
                logger.exception("Event handler failed for packet %s", self.packet_count)
        return event


def build_pipeline_handler(
    packet_source,
    event_handler=None,
):
    return PacketPipeline(packet_source, event_handler)


def process_packet(
    packet,
    *,
    packet_number=None,
    packet_source=None,
):
    event = PacketEvent(
        timestamp=_packet_timestamp(packet),
        pcap_cnt=packet_number,
        pkt_src=packet_source,
    )

    try:
        parse_ipv4(packet, event)
    except Exception as exc:
        _record_stage_error(event, "network", exc)
        return _finalize_status(event)

    if event.ip is None:
        return _finalize_status(event)

    payload = b""
    if event.proto == "TCP":
        try:
            payload = parse_tcp(packet, event)
        except Exception as exc:
            _record_stage_error(event, "tcp", exc)
    elif event.proto == "UDP":
        try:
            payload = parse_udp(packet, event)
        except Exception as exc:
            _record_stage_error(event, "udp", exc)
    else:
        event.parser.warnings.append("Unsupported IPv4 transport protocol")
        return _finalize_status(event)

    try:
        event.app_proto = detect_application(
            payload,
            event.src_port,
            event.dest_port,
            packet,
        )
    except Exception as exc:
        _record_stage_error(event, "application detection", exc)
        return _finalize_status(event)

    try:
        if event.app_proto == "http":
            parse_http(payload, event)
        elif event.app_proto == "dns":
            parse_dns(packet, event)
        elif event.app_proto == "smtp":
            parse_smtp(payload, event)
    except Exception as exc:
        _record_stage_error(event, event.app_proto or "application", exc)

    return _finalize_status(event)


def _packet_timestamp(packet):
    packet_time = getattr(packet, "time", None)
    try:
        value = (
            float(packet_time)
            if packet_time is not None
            else datetime.now(tz=timezone.utc).timestamp()
        )
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OSError, OverflowError, TypeError, ValueError):
        logger.warning("Invalid packet timestamp; using current UTC time")
        return datetime.now(tz=timezone.utc).isoformat()


def _record_stage_error(event, stage, exc):
    event.parser.errors.append(f"{stage} parsing failed: {exc}")
    logger.debug("%s parsing failed", stage, exc_info=exc)


def _finalize_status(event):
    if event.parser.errors:
        event.parser.status = "partial" if _event_has_parsed_data(event) else "error"
    return event


def _event_has_parsed_data(event):
    return any(
        value is not None
        for value in (
            event.ether,
            event.ip,
            event.tcp,
            event.udp,
            event.http,
            event.dns,
            event.smtp,
        )
    )
