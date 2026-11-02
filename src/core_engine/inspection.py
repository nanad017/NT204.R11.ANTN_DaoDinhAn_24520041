"""Inspection buffers consumed by the rule matching engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class InspectionBuffer:
    """A named byte buffer derived from a normalized packet event."""

    name: str
    data: bytes
    field: str | None = None


@dataclass(frozen=True)
class InspectionContext:
    """Packet event plus raw and normalized data available for inspection."""

    event: object
    buffers: tuple[InspectionBuffer, ...]

    @property
    def raw_payload(self) -> bytes:
        for buffer in self.buffers:
            if buffer.name == "transport" and buffer.field == "payload":
                return buffer.data
        return b""

    @classmethod
    def from_event(
        cls,
        event: object,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> InspectionContext:
        return InspectionContextBuilder().build(event, payload=payload)


class InspectionContextBuilder:
    """Build stable byte buffers without exposing Scapy objects to the engine."""

    def build(
        self,
        event: object,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> InspectionContext:
        raw_payload = _coerce_payload(
            getattr(event, "_application_payload", b"")
            if payload is None
            else payload
        )
        buffers = [
            InspectionBuffer(name="transport", field="payload", data=raw_payload)
        ]

        self._add_http_buffers(buffers, getattr(event, "http", None))
        self._add_dns_buffers(buffers, getattr(event, "dns", None))
        self._add_smtp_buffers(buffers, getattr(event, "smtp", None))
        self._add_email_buffers(buffers, getattr(event, "email", None))
        return InspectionContext(event=event, buffers=tuple(buffers))

    @staticmethod
    def _add_http_buffers(
        buffers: list[InspectionBuffer],
        http: object | None,
    ) -> None:
        if http is None:
            return
        for field in (
            "normalized_url",
            "decoded_url",
            "decoded_path",
            "decoded_query",
            "url",
            "raw_url",
            "hostname",
            "http_method",
            "raw_form_data",
            "body",
            "raw_body",
            "decoded_body",
            "html_decoded_body",
        ):
            _append_text_buffer(buffers, "http", field, getattr(http, field, None))

        for collection_name in ("request_headers", "response_headers"):
            for index, header in enumerate(getattr(http, collection_name, ()) or ()):
                name = getattr(header, "name", "")
                value = getattr(header, "value", "")
                _append_text_buffer(
                    buffers,
                    "http",
                    f"{collection_name}[{index}]",
                    f"{name}: {value}",
                )

    @staticmethod
    def _add_dns_buffers(
        buffers: list[InspectionBuffer],
        dns: object | None,
    ) -> None:
        if dns is None:
            return
        for index, query in enumerate(getattr(dns, "queries", ()) or ()):
            _append_text_buffer(
                buffers,
                "dns",
                f"queries[{index}].rrname",
                getattr(query, "rrname", None),
            )
        for collection_name in ("answers", "authorities", "additionals"):
            for index, record in enumerate(getattr(dns, collection_name, ()) or ()):
                _append_text_buffer(
                    buffers,
                    "dns",
                    f"{collection_name}[{index}].rrname",
                    getattr(record, "rrname", None),
                )
                _append_text_buffer(
                    buffers,
                    "dns",
                    f"{collection_name}[{index}].rdata",
                    getattr(record, "rdata", None),
                )

    @staticmethod
    def _add_smtp_buffers(
        buffers: list[InspectionBuffer],
        smtp: object | None,
    ) -> None:
        if smtp is None:
            return
        for field in (
            "helo",
            "mail_from",
            "command",
            "argument",
            "response",
        ):
            _append_text_buffer(buffers, "smtp", field, getattr(smtp, field, None))
        for index, recipient in enumerate(getattr(smtp, "rcpt_to", ()) or ()):
            _append_text_buffer(buffers, "smtp", f"rcpt_to[{index}]", recipient)

    @staticmethod
    def _add_email_buffers(
        buffers: list[InspectionBuffer],
        email: object | None,
    ) -> None:
        if email is None:
            return
        for field in (
            "from_address",
            "subject",
            "raw_body",
            "decoded_body",
        ):
            _append_text_buffer(buffers, "email", field, getattr(email, field, None))
        for index, recipient in enumerate(getattr(email, "to", ()) or ()):
            _append_text_buffer(buffers, "email", f"to[{index}]", recipient)


def build_inspection_context(
    event: object,
    payload: bytes | bytearray | memoryview | None = None,
) -> InspectionContext:
    return InspectionContextBuilder().build(event, payload=payload)


def _coerce_payload(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError("inspection payload must be bytes-like")


def _append_text_buffer(
    buffers: list[InspectionBuffer],
    name: str,
    field: str,
    value: object,
) -> None:
    if value is None:
        return
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = str(value).encode("utf-8")
    buffers.append(InspectionBuffer(name=name, field=field, data=data))
