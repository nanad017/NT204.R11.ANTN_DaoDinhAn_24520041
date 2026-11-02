"""Header, flow, packet and content matching for supported Snort rules."""

from __future__ import annotations

from ipaddress import IPv4Address, ip_address
from typing import Iterable

from src.core_engine.inspection import InspectionBuffer, InspectionContext
from src.core_engine.models import (
    ContentOption,
    DsizeOperator,
    DsizeOption,
    InternalRule,
    IPAddressSpec,
    MatchInformation,
    MatchStatus,
    PortSpec,
    RuleHeader,
    RuleMatch,
)


_FLAG_ALIASES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}
_FLAG_NAMES = frozenset(_FLAG_ALIASES.values())


class HeaderMatcher:
    def matches(self, header: RuleHeader, event: object) -> bool:
        protocol = getattr(event, "proto", None)
        if not isinstance(protocol, str) or protocol.strip().lower() != header.protocol:
            return False

        endpoints = (
            getattr(event, "src_ip", None),
            getattr(event, "src_port", None),
            getattr(event, "dest_ip", None),
            getattr(event, "dest_port", None),
        )
        if self._matches_direction(header, *endpoints):
            return True
        if header.direction == "<>":
            src_ip, src_port, dest_ip, dest_port = endpoints
            return self._matches_direction(
                header,
                dest_ip,
                dest_port,
                src_ip,
                src_port,
            )
        return False

    @staticmethod
    def _matches_direction(
        header: RuleHeader,
        src_ip: object,
        src_port: object,
        dest_ip: object,
        dest_port: object,
    ) -> bool:
        return (
            _ip_matches(header.source_ip, src_ip)
            and _port_matches(header.source_port, src_port)
            and _ip_matches(header.destination_ip, dest_ip)
            and _port_matches(header.destination_port, dest_port)
        )

    match = matches


class FlowMatcher:
    def matches(self, rule: InternalRule, event: object) -> bool:
        if not rule.flow:
            return True

        values = set(rule.flow)
        role = getattr(event, "flow_role", None)
        if "to_server" in values and role != "to_server":
            return False
        if "to_client" in values and role != "to_client":
            return False

        if values & {"established", "not_established"}:
            flow = getattr(event, "flow", None)
            established = getattr(flow, "established", None)
            if not isinstance(established, bool):
                return False
            if "established" in values and not established:
                return False
            if "not_established" in values and established:
                return False
        return True

    match = matches


class PacketMatcher:
    def matches(self, rule: InternalRule, event: object) -> bool:
        if _option_present(rule, "flags"):
            if str(getattr(event, "proto", "")).strip().lower() != "tcp":
                return False
            tcp = getattr(event, "tcp", None)
            if tcp is None or _normalize_flags(getattr(tcp, "flags", None)) != rule.flags:
                return False

        if rule.dsize is not None:
            payload_size = _transport_payload_size(event)
            if payload_size is None or not _dsize_matches(rule.dsize, payload_size):
                return False
        return True

    match = matches


class ContentMatcher:
    def match(
        self,
        contents: Iterable[ContentOption],
        context: InspectionContext,
    ) -> list[MatchInformation] | None:
        content_list = tuple(contents)
        if not content_list:
            return []
        for buffer in context.buffers:
            information = self._match_buffer(content_list, buffer)
            if information is not None:
                return information
        return None

    @staticmethod
    def _match_buffer(
        contents: tuple[ContentOption, ...],
        buffer: InspectionBuffer,
    ) -> list[MatchInformation] | None:
        previous_end = 0
        result: list[MatchInformation] = []
        for content in contents:
            bounds = _content_bounds(
                content,
                buffer_length=len(buffer.data),
                previous_end=previous_end,
            )
            if bounds is None:
                return None
            start, end = bounds
            haystack = buffer.data.lower() if content.nocase else buffer.data
            needle = content.pattern.lower() if content.nocase else content.pattern
            position = haystack.find(needle, start, end)
            if position < 0:
                return None
            match_end = position + len(content.pattern)
            result.append(
                MatchInformation(
                    kind="content",
                    buffer=buffer.name,
                    field=buffer.field,
                    content=content.raw,
                    start=position,
                    end=match_end,
                )
            )
            previous_end = match_end
        return result

    matches = match


class RuleMatcher:
    def __init__(
        self,
        *,
        header_matcher: HeaderMatcher | None = None,
        flow_matcher: FlowMatcher | None = None,
        packet_matcher: PacketMatcher | None = None,
        content_matcher: ContentMatcher | None = None,
    ) -> None:
        self.header_matcher = header_matcher or HeaderMatcher()
        self.flow_matcher = flow_matcher or FlowMatcher()
        self.packet_matcher = packet_matcher or PacketMatcher()
        self.content_matcher = content_matcher or ContentMatcher()

    def match(
        self,
        rule: InternalRule,
        event: object,
        context: InspectionContext | None = None,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> RuleMatch:
        if not isinstance(rule, InternalRule):
            raise TypeError("matcher only accepts InternalRule objects")
        if not rule.is_evaluable or rule.header is None:
            return _result(rule, MatchStatus.NO_MATCH, reason="rule is not evaluable")
        if not self.header_matcher.matches(rule.header, event):
            return _result(rule, MatchStatus.NO_MATCH, reason="header did not match")
        if not self.flow_matcher.matches(rule, event):
            return _result(rule, MatchStatus.NO_MATCH, reason="flow did not match")
        if not self.packet_matcher.matches(rule, event):
            return _result(rule, MatchStatus.NO_MATCH, reason="packet options did not match")
        if not rule.contents:
            return _result(rule, MatchStatus.MATCH)

        inspection = context or InspectionContext.from_event(event, payload)
        matched_information = self.content_matcher.match(rule.contents, inspection)
        if matched_information is None:
            return _result(rule, MatchStatus.NO_MATCH, reason="content did not match")
        return _result(
            rule,
            MatchStatus.MATCH,
            matched_information=matched_information,
        )

    evaluate = match


MatchingEngine = RuleMatcher


def match_rule(
    rule: InternalRule,
    event: object,
    context: InspectionContext | None = None,
    *,
    payload: bytes | bytearray | memoryview | None = None,
) -> RuleMatch:
    return RuleMatcher().match(rule, event, context, payload=payload)


def _result(
    rule: InternalRule,
    status: MatchStatus,
    *,
    matched_information: list[MatchInformation] | None = None,
    reason: str | None = None,
) -> RuleMatch:
    return RuleMatch(
        status=status,
        sid=rule.sid if isinstance(rule.sid, int) else 0,
        rev=rule.rev if isinstance(rule.rev, int) else 0,
        msg=rule.msg if isinstance(rule.msg, str) else "",
        matched_information=matched_information or [],
        reason=reason,
    )


def _ip_matches(spec: IPAddressSpec, value: object) -> bool:
    try:
        address = ip_address(value)
    except (TypeError, ValueError):
        return False
    if not isinstance(address, IPv4Address):
        return False
    return spec.is_any or address in spec.network


def _port_matches(spec: PortSpec, value: object) -> bool:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535:
        return False
    return spec.is_any or (
        spec.start is not None and spec.end is not None and spec.start <= value <= spec.end
    )


def _option_present(rule: InternalRule, keyword: str) -> bool:
    return any(option.keyword == keyword for option in rule.options)


def _normalize_flags(flags: object) -> frozenset[str]:
    if flags is None:
        return frozenset()
    values = (flags,) if isinstance(flags, str) else flags
    normalized: set[str] = set()
    try:
        for value in values:
            compact = str(value).strip().upper()
            if compact in _FLAG_NAMES:
                normalized.add(compact)
            else:
                normalized.update(
                    _FLAG_ALIASES[character]
                    for character in compact
                    if character in _FLAG_ALIASES
                )
    except TypeError:
        return frozenset()
    return frozenset(normalized)


def _transport_payload_size(event: object) -> int | None:
    protocol = str(getattr(event, "proto", "")).strip().lower()
    transport = getattr(event, protocol, None) if protocol in {"tcp", "udp"} else None
    value = getattr(transport, "payload_length", None)
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _dsize_matches(option: DsizeOption, payload_size: int) -> bool:
    if option.operator == DsizeOperator.EQUAL:
        return payload_size == option.value
    if option.operator == DsizeOperator.LESS_THAN:
        return payload_size < option.value
    if option.operator == DsizeOperator.GREATER_THAN:
        return payload_size > option.value
    if option.operator == DsizeOperator.RANGE and option.upper is not None:
        return option.value < payload_size < option.upper
    return False


def _content_bounds(
    content: ContentOption,
    *,
    buffer_length: int,
    previous_end: int,
) -> tuple[int, int] | None:
    if content.distance is not None or content.within is not None:
        start = previous_end + (content.distance or 0)
        end = (
            min(buffer_length, start + content.within)
            if content.within is not None
            else buffer_length
        )
    else:
        absolute_start = content.offset or 0
        start = absolute_start
        end = (
            min(buffer_length, absolute_start + content.depth)
            if content.depth is not None
            else buffer_length
        )
    if start < 0 or end < start or end - start < len(content.pattern):
        return None
    return start, end
