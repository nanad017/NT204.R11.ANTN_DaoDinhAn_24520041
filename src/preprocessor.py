from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit

from src.config import ProcessingConfig
from src.schema import PacketEvent, PreprocessInfo


class Preprocessor:
    def __init__(self, config: ProcessingConfig | None = None):
        self.config = config or ProcessingConfig()

    def process(self, event: PacketEvent) -> PacketEvent:
        result = PreprocessInfo()
        event.preprocess = result
        try:
            self._normalize(event, result)
            self._validate(event, result)
        except Exception as exc:
            result.status = "invalid"
            result.errors.append(f"preprocessing failed: {exc}")

        if result.status == "invalid":
            result.processing_action = self.config.invalid_event_policy
            if result.reason is None:
                result.reason = "; ".join(result.errors) or "invalid event"
        elif result.status == "partial" and event.proto not in {"TCP", "UDP"}:
            result.processing_action = self.config.unsupported_data_policy
            if result.reason is None:
                result.reason = "unsupported or incomplete transport data"
        return event

    preprocess = process

    def _normalize(self, event: PacketEvent, result: PreprocessInfo) -> None:
        if event.proto:
            normalized = str(event.proto).upper()
            if normalized != event.proto:
                result.original_values["proto"] = event.proto
            event.proto = normalized
        if event.app_proto:
            normalized = str(event.app_proto).lower()
            if normalized != event.app_proto:
                result.original_values["app_proto"] = event.app_proto
            event.app_proto = normalized

        for field_name in ("src_ip", "dest_ip"):
            value = getattr(event, field_name, None)
            if value is None:
                continue
            try:
                normalized = str(ip_address(str(value).strip()))
            except ValueError:
                continue
            if normalized != value:
                result.warnings.append(f"normalized {field_name}")
                result.original_values[field_name] = value
                setattr(event, field_name, normalized)

        if event.timestamp is not None:
            try:
                parsed = datetime.fromisoformat(str(event.timestamp).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                else:
                    parsed = parsed.astimezone(timezone.utc)
                if parsed.isoformat() != event.timestamp:
                    result.original_values["timestamp"] = event.timestamp
                event.timestamp = parsed.isoformat()
            except (TypeError, ValueError):
                pass

        if event.http is not None:
            if event.http.url is not None:
                event.http.normalized_url = _normalize_http_url(event.http.url)
            if event.http.hostname:
                normalized = _normalize_domain(event.http.hostname)
                if normalized != event.http.hostname:
                    result.original_values["http.hostname"] = event.http.hostname
                event.http.hostname = normalized
            for header in event.http.request_headers + event.http.response_headers:
                if header.original_name is None:
                    header.original_name = header.name
                if header.name.strip().lower() != header.name:
                    result.original_values[f"http.header:{header.name}"] = header.name
                header.name = header.name.strip().lower()

        if event.dns is not None:
            for query in event.dns.queries:
                normalized = _normalize_domain(query.rrname)
                if normalized != query.rrname:
                    result.original_values[f"dns.query:{query.rrname}"] = query.rrname
                query.rrname = normalized
            for record in event.dns.answers + event.dns.authorities + event.dns.additionals:
                record.rrname = _normalize_domain(record.rrname)
                if record.rrtype in {"CNAME", "NS", "PTR"} and record.rdata:
                    record.rdata = _normalize_domain(record.rdata)

    def _validate(self, event: PacketEvent, result: PreprocessInfo) -> None:
        errors: list[str] = []
        if not isinstance(event.timestamp, str):
            errors.append("timestamp is required")
        else:
            try:
                datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
            except ValueError:
                errors.append("timestamp is not ISO-8601")

        for field_name in ("src_ip", "dest_ip"):
            value = getattr(event, field_name, None)
            if value is None:
                errors.append(f"{field_name} is required")
            else:
                try:
                    ip_address(value)
                except ValueError:
                    errors.append(f"{field_name} is invalid")

        if event.proto is None:
            errors.append("transport protocol is missing")
        elif event.proto not in {"TCP", "UDP"}:
            result.warnings.append(f"unsupported transport protocol: {event.proto}")

        if event.proto in {"TCP", "UDP"}:
            for field_name in ("src_port", "dest_port"):
                port = getattr(event, field_name, None)
                if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
                    errors.append(f"{field_name} must be an integer in range 0..65535")

        if event.packet_length is not None and (
            not isinstance(event.packet_length, int) or event.packet_length < 0
        ):
            errors.append("packet_length must be a non-negative integer")

        if errors:
            result.errors.extend(errors)
            result.status = "invalid"
            result.reason = "; ".join(errors)
        elif result.warnings:
            result.status = "partial"


def _normalize_domain(value: str) -> str:
    return str(value).strip().rstrip(".").lower()


def _normalize_http_url(value: str) -> str:
    try:
        parts = urlsplit(str(value))
        return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, parts.fragment))
    except ValueError:
        return str(value)


def preprocess_event(
    event: PacketEvent,
    config: ProcessingConfig | None = None,
) -> PacketEvent:
    return Preprocessor(config).process(event)
