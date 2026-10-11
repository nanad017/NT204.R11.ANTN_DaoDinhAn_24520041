import base64
import binascii
import html
import quopri
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qsl, unquote, unquote_to_bytes, urlsplit

from src.config import ProcessingConfig
from src.schema import DecoderInfo, EmailInfo, PacketEvent


@dataclass
class _TextResult:
    text: str
    status: str = "success"
    error: str | None = None


class Decoder:
    def __init__(self, config: ProcessingConfig | None = None):
        self.config = config or ProcessingConfig()

    def decode_event(self, event: PacketEvent, payload: bytes | None = None) -> PacketEvent:
        info = DecoderInfo()
        event.decoder = info
        try:
            if event.http is not None:
                info.status = self.decode_http(event)
            elif event.smtp is not None or event.email is not None:
                info.status = self.decode_smtp(event, payload or b"")
            else:
                info.status = "not_applicable"
        except Exception as exc:
            info.status = "error"
            info.errors.append(str(exc))
        return event

    process = decode_event

    def decode_http(self, event: PacketEvent) -> str:
        http_info = event.http
        if http_info is None:
            return "not_applicable"

        info = event.decoder or DecoderInfo()
        event.decoder = info
        status = "success"

        raw_url = http_info.raw_url if http_info.raw_url is not None else http_info.url
        if raw_url is not None:
            http_info.raw_url = raw_url
            decoded = _percent_decode(raw_url)
            http_info.decoded_url = decoded.text
            status = _merge_status(status, decoded.status)
            if decoded.error:
                info.errors.append(f"HTTP URI: {decoded.error}")
            try:
                components = urlsplit(raw_url)
                path = _percent_decode(components.path)
                query = _percent_decode(components.query)
                http_info.decoded_path = path.text
                http_info.decoded_query = query.text
                status = _merge_status(status, path.status, query.status)
            except ValueError as exc:
                status = "partial"
                info.warnings.append(f"HTTP URI structure could not be split: {exc}")

        if http_info.body is not None:
            http_info.raw_body = http_info.body
            body = _bounded_text(http_info.body, self.config.max_decoded_content_size)
            http_info.decoded_body = body.text
            if body.status != "success":
                status = _merge_status(status, body.status)
                info.warnings.append("HTTP body exceeded decoder size limit")

            content_type = (http_info.http_content_type or "").lower()
            if content_type.startswith("application/x-www-form-urlencoded"):
                http_info.raw_form_data = http_info.body
                form_status, form = _decode_form(http_info.body)
                http_info.decoded_form = form
                status = _merge_status(status, form_status)

            if content_type.startswith("text/") or "&lt;" in http_info.body or "&#" in http_info.body:
                http_info.html_decoded_body = html.unescape(http_info.body)

        return status

    def decode_smtp(self, event: PacketEvent, payload: bytes) -> str:
        info = event.decoder or DecoderInfo()
        event.decoder = info
        if not payload or b"content-transfer-encoding" not in payload.lower():
            return "not_applicable"

        limited_payload, truncated = _limit_bytes(
            payload, self.config.max_decoded_content_size
        )
        try:
            message = BytesParser(policy=policy.default).parsebytes(limited_payload)
        except Exception as exc:
            info.errors.append(f"MIME parse failed: {exc}")
            return "error"

        parts = list(message.walk()) if message.is_multipart() else [message]
        statuses: list[str] = []
        target: EmailInfo | None = event.email
        if target is None:
            target = EmailInfo()
            event.email = target

        for part in parts:
            if part.is_multipart():
                continue
            transfer = part.get("Content-Transfer-Encoding")
            if not transfer:
                continue
            transfer = transfer.strip().lower()
            raw_part = part.get_payload(decode=False)
            raw_bytes = _payload_bytes(raw_part)
            target.raw_body = _safe_raw_text(raw_bytes)
            target.content_transfer_encoding = transfer
            target.charset = part.get_content_charset()

            decoded_bytes, decode_status, error = _decode_transfer(raw_bytes, transfer)
            statuses.append(decode_status)
            if error:
                info.errors.append(f"MIME {transfer}: {error}")
                continue
            target.decoded_size = len(decoded_bytes)
            content_type = (part.get_content_type() or "").lower()
            if content_type.startswith("text/") or target.charset:
                text_result = _decode_character_data(decoded_bytes, target.charset)
                statuses.append(text_result.status)
                if text_result.error:
                    info.errors.append(f"MIME character decoding: {text_result.error}")
                target.decoded_body = text_result.text
                target.decode_status = _merge_status("success", *statuses)
            else:
                target.decoded_body = None
                target.decode_status = decode_status

        if not statuses:
            info.warnings.append("MIME header found but no decodable body part")
            return "partial"
        if truncated:
            info.warnings.append("MIME payload exceeded decoder size limit")
            statuses.append("partial")
        return _merge_status("success", *statuses)


def _percent_decode(value: str) -> _TextResult:
    try:
        raw = unquote_to_bytes(value)
        return _decode_character_data(raw, "utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        return _TextResult(unquote(value), "partial", str(exc))


def _decode_form(value: str) -> tuple[str, dict[str, object]]:
    try:
        pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=False)
    except (TypeError, ValueError) as exc:
        return "partial", {"_error": str(exc)}
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            previous = result[key]
            result[key] = previous + [item] if isinstance(previous, list) else [previous, item]
        else:
            result[key] = item
    return "success", result


def _decode_transfer(raw: bytes, transfer: str) -> tuple[bytes, str, str | None]:
    try:
        if transfer == "base64":
            compact = b"".join(raw.split())
            return base64.b64decode(compact, validate=True), "success", None
        if transfer == "quoted-printable":
            return quopri.decodestring(raw), "success", None
        if transfer in {"7bit", "8bit", "binary"}:
            return raw, "success", None
        return b"", "unsupported", f"unsupported Content-Transfer-Encoding: {transfer}"
    except (binascii.Error, ValueError) as exc:
        return b"", "partial", str(exc)


def _decode_character_data(value: bytes, charset: str | None = None) -> _TextResult:
    encodings = [charset] if charset else []
    encodings.extend(["utf-8", "ascii"])
    seen: set[str] = set()
    for encoding in encodings:
        if not encoding or encoding.lower() in seen:
            continue
        seen.add(encoding.lower())
        try:
            return _TextResult(value.decode(encoding), "success")
        except (LookupError, UnicodeDecodeError):
            continue
    return _TextResult(value.decode("utf-8", errors="replace"), "partial", "invalid character sequence")


def _bounded_text(value: str, limit: int) -> _TextResult:
    raw = value.encode("utf-8", errors="replace")
    limited, truncated = _limit_bytes(raw, limit)
    result = _decode_character_data(limited, "utf-8")
    if truncated and result.status == "success":
        result.status = "partial"
    return result


def _limit_bytes(value: bytes, limit: int) -> tuple[bytes, bool]:
    return (value[:limit], True) if len(value) > limit else (value, False)


def _payload_bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("ascii", errors="replace")
    return b""


def _safe_raw_text(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


def _merge_status(initial: str, *statuses: str) -> str:
    values = {initial, *statuses}
    if "error" in values:
        return "error"
    if "partial" in values or "unsupported" in values:
        return "partial"
    return initial


def decode_event(
    event: PacketEvent,
    payload: bytes | None = None,
    config: ProcessingConfig | None = None,
) -> PacketEvent:
    return Decoder(config).decode_event(event, payload)


def decode_http(event: PacketEvent, config: ProcessingConfig | None = None) -> PacketEvent:
    decoder = Decoder(config)
    event.decoder = DecoderInfo()
    event.decoder.status = decoder.decode_http(event)
    return event


def decode_smtp(
    event: PacketEvent,
    payload: bytes,
    config: ProcessingConfig | None = None,
) -> PacketEvent:
    decoder = Decoder(config)
    event.decoder = DecoderInfo()
    event.decoder.status = decoder.decode_smtp(event, payload)
    return event
