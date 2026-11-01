"""Parser for the Snort rule subset required by Assignment 3."""

from __future__ import annotations

import re
from dataclasses import replace
from ipaddress import IPv4Network, ip_network

from src.core_engine.models import (
    ContentOption,
    DiagnosticKind,
    DsizeOperator,
    DsizeOption,
    IPAddressSpec,
    InternalRule,
    PortSpec,
    RuleDiagnostic,
    RuleHeader,
    RuleOption,
    RuleStatus,
)
from src.core_engine.validator import RuleValidator


_INTEGER = re.compile(r"\d+")
_DSIZE_RANGE = re.compile(r"(\d+)\s*<>\s*(\d+)")
_TCP_FLAG_NAMES = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}
_CONTENT_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}
_SINGLE_OPTIONS = {
    "msg",
    "sid",
    "rev",
    "flags",
    "dsize",
    "flow",
    "classtype",
    "priority",
}


class RuleSyntaxError(ValueError):
    def __init__(
        self,
        reason: str,
        *,
        position: int | None = None,
        keyword: str | None = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.position = position
        self.keyword = keyword


class SnortRuleParser:
    def __init__(self, validator: RuleValidator | None = None) -> None:
        self.validator = validator or RuleValidator()

    def parse(
        self,
        rule_text: str,
        *,
        source_file: str | None = None,
        source_line: int | None = None,
    ) -> InternalRule:
        rule = InternalRule(
            raw_text=str(rule_text),
            status=RuleStatus.INVALID,
            source_file=source_file,
            source_line=source_line,
        )

        try:
            header_text, options_text, options_offset = _split_rule(rule.raw_text)
            rule.header = _parse_header(header_text)
            self._parse_options(rule, options_text, options_offset)
        except RuleSyntaxError as exc:
            rule.diagnostics.append(
                RuleDiagnostic(
                    kind=DiagnosticKind.INVALID,
                    reason=exc.reason,
                    position=exc.position,
                    keyword=exc.keyword,
                )
            )

        return self.validator.validate(rule)

    def _parse_options(
        self,
        rule: InternalRule,
        options_text: str,
        options_offset: int,
    ) -> None:
        seen: set[str] = set()
        content_modifiers: list[set[str]] = []

        for option_text, relative_position in _split_options(options_text):
            position = options_offset + relative_position
            keyword, value = _split_option(option_text)
            keyword = keyword.lower()
            rule.options.append(RuleOption(keyword=keyword, value=value))

            if keyword in _SINGLE_OPTIONS:
                if keyword in seen:
                    _invalid(
                        rule,
                        f"duplicate option: {keyword}",
                        position=position,
                        keyword=keyword,
                    )
                    continue
                seen.add(keyword)

            try:
                self._apply_option(
                    rule,
                    keyword,
                    value,
                    position,
                    content_modifiers,
                )
            except RuleSyntaxError as exc:
                _invalid(
                    rule,
                    exc.reason,
                    position=exc.position if exc.position is not None else position,
                    keyword=exc.keyword or keyword,
                )

    def _apply_option(
        self,
        rule: InternalRule,
        keyword: str,
        value: str | None,
        position: int,
        content_modifiers: list[set[str]],
    ) -> None:
        if keyword == "msg":
            rule.msg = _parse_quoted_text(_require_value(keyword, value))
        elif keyword == "sid":
            rule.sid = _parse_integer(keyword, value, minimum=1)
        elif keyword == "rev":
            rule.rev = _parse_integer(keyword, value, minimum=1)
        elif keyword == "content":
            content, unsupported_negation = _parse_content(
                _require_value(keyword, value)
            )
            rule.contents.append(content)
            content_modifiers.append(set())
            if unsupported_negation:
                rule.diagnostics.append(
                    RuleDiagnostic(
                        kind=DiagnosticKind.UNSUPPORTED,
                        reason="negated content is outside the supported subset",
                        position=position,
                        keyword="content",
                    )
                )
        elif keyword in _CONTENT_MODIFIERS:
            self._apply_content_modifier(
                rule,
                keyword,
                value,
                content_modifiers,
            )
        elif keyword == "flags":
            rule.flags = _parse_flags(_require_value(keyword, value))
        elif keyword == "dsize":
            rule.dsize = _parse_dsize(_require_value(keyword, value))
        elif keyword == "flow":
            rule.flow = _parse_flow(_require_value(keyword, value))
        elif keyword == "classtype":
            rule.classtype = _parse_bare_value(keyword, value)
        elif keyword == "priority":
            rule.priority = _parse_integer(keyword, value, minimum=1)
        else:
            rule.diagnostics.append(
                RuleDiagnostic(
                    kind=DiagnosticKind.UNSUPPORTED,
                    reason=f"unsupported keyword: {keyword}",
                    position=position,
                    keyword=keyword,
                )
            )

    @staticmethod
    def _apply_content_modifier(
        rule: InternalRule,
        keyword: str,
        value: str | None,
        content_modifiers: list[set[str]],
    ) -> None:
        if not rule.contents:
            raise RuleSyntaxError(f"{keyword} requires a preceding content option")
        if keyword in content_modifiers[-1]:
            raise RuleSyntaxError(f"duplicate content modifier: {keyword}")
        content_modifiers[-1].add(keyword)

        current = rule.contents[-1]
        if keyword == "nocase":
            if value not in (None, ""):
                raise RuleSyntaxError("nocase does not accept a value")
            rule.contents[-1] = replace(current, nocase=True)
            return

        minimum = 1 if keyword in {"depth", "within"} else 0
        number = _parse_integer(keyword, value, minimum=minimum)
        rule.contents[-1] = replace(current, **{keyword: number})


RuleParser = SnortRuleParser


def parse_rule(
    rule_text: str,
    *,
    source_file: str | None = None,
    source_line: int | None = None,
) -> InternalRule:
    return SnortRuleParser().parse(
        rule_text,
        source_file=source_file,
        source_line=source_line,
    )


def _split_rule(rule_text: str) -> tuple[str, str, int]:
    text = rule_text.strip()
    if not text:
        raise RuleSyntaxError("rule text is empty", position=0)

    opening = text.find("(")
    if opening < 0:
        raise RuleSyntaxError("rule options opening parenthesis is missing")

    in_quote = False
    escaped = False
    depth = 0
    closing: int | None = None
    for index in range(opening, len(text)):
        character = text[index]
        if escaped:
            escaped = False
            continue
        if character == "\\" and in_quote:
            escaped = True
            continue
        if character == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break

    if closing is None:
        raise RuleSyntaxError("rule options closing parenthesis is missing")
    if text[closing + 1 :].strip():
        raise RuleSyntaxError(
            "unexpected text after rule options",
            position=closing + 1,
        )

    header_text = text[:opening].strip()
    if not header_text:
        raise RuleSyntaxError("rule header is missing", position=0)
    return header_text, text[opening + 1 : closing], opening + 1


def _parse_header(header_text: str) -> RuleHeader:
    parts = header_text.split()
    if len(parts) != 7:
        raise RuleSyntaxError(
            "rule header must contain action, protocol, source IP/port, "
            "direction and destination IP/port"
        )

    action, protocol, source_ip, source_port, direction, dest_ip, dest_port = parts
    if direction not in {"->", "<>"}:
        raise RuleSyntaxError(f"invalid rule direction: {direction}")
    return RuleHeader(
        action=action.lower(),
        protocol=protocol.lower(),
        source_ip=_parse_ip(source_ip),
        source_port=_parse_port(source_port),
        direction=direction,
        destination_ip=_parse_ip(dest_ip),
        destination_port=_parse_port(dest_port),
    )


def _parse_ip(value: str) -> IPAddressSpec:
    if value.lower() == "any":
        return IPAddressSpec.match_any()
    try:
        network = ip_network(value, strict=False)
    except ValueError as exc:
        raise RuleSyntaxError(f"invalid IPv4 address or CIDR: {value}") from exc
    if not isinstance(network, IPv4Network):
        raise RuleSyntaxError(f"only IPv4 addresses are supported: {value}")
    return IPAddressSpec(raw=value, network=network)


def _parse_port(value: str) -> PortSpec:
    if value.lower() == "any":
        return PortSpec.match_any()
    if ":" in value:
        parts = value.split(":")
        if len(parts) != 2 or not all(_INTEGER.fullmatch(item) for item in parts):
            raise RuleSyntaxError(f"invalid port range: {value}")
        try:
            return PortSpec.range(int(parts[0]), int(parts[1]))
        except ValueError as exc:
            raise RuleSyntaxError(str(exc)) from exc
    if not _INTEGER.fullmatch(value):
        raise RuleSyntaxError(f"invalid port: {value}")
    try:
        return PortSpec.single(int(value))
    except ValueError as exc:
        raise RuleSyntaxError(str(exc)) from exc


def _split_options(options_text: str) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    start = 0
    in_quote = False
    escaped = False

    for index, character in enumerate(options_text):
        if escaped:
            escaped = False
            continue
        if character == "\\" and in_quote:
            escaped = True
            continue
        if character == '"':
            in_quote = not in_quote
            continue
        if character == ";" and not in_quote:
            _append_option(result, options_text, start, index)
            start = index + 1

    if in_quote:
        raise RuleSyntaxError("unterminated quoted option value")
    _append_option(result, options_text, start, len(options_text))
    return result


def _append_option(
    result: list[tuple[str, int]],
    options_text: str,
    start: int,
    end: int,
) -> None:
    raw = options_text[start:end]
    stripped = raw.strip()
    if stripped:
        result.append((stripped, start + len(raw) - len(raw.lstrip())))


def _split_option(option_text: str) -> tuple[str, str | None]:
    if ":" not in option_text:
        keyword = option_text.strip()
        if not keyword:
            raise RuleSyntaxError("empty rule option")
        return keyword, None
    keyword, value = option_text.split(":", 1)
    keyword = keyword.strip()
    if not keyword:
        raise RuleSyntaxError("rule option keyword is empty")
    return keyword, value.strip()


def _parse_quoted_text(value: str) -> str:
    body = _quoted_body(value)
    output: list[str] = []
    escaped = False
    for character in body:
        if escaped:
            output.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            output.append(character)
    if escaped:
        raise RuleSyntaxError("quoted value ends with an incomplete escape")
    return "".join(output)


def _parse_content(value: str) -> tuple[ContentOption, bool]:
    stripped = value.strip()
    negated = stripped.startswith("!")
    if negated:
        stripped = stripped[1:].lstrip()
    body = _quoted_body(stripped)

    pattern = bytearray()
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\":
            index += 1
            if index >= len(body):
                raise RuleSyntaxError("content ends with an incomplete escape")
            pattern.extend(body[index].encode("utf-8"))
        elif character == "|":
            closing = body.find("|", index + 1)
            if closing < 0:
                raise RuleSyntaxError("content hex block is not closed")
            hex_text = body[index + 1 : closing].strip()
            octets = hex_text.split()
            if not octets or any(not re.fullmatch(r"[0-9A-Fa-f]{2}", item) for item in octets):
                raise RuleSyntaxError("content hex block must contain two-digit octets")
            pattern.extend(int(item, 16) for item in octets)
            index = closing
        else:
            pattern.extend(character.encode("utf-8"))
        index += 1

    return ContentOption(pattern=bytes(pattern), raw=body), negated


def _quoted_body(value: str) -> str:
    stripped = value.strip()
    if len(stripped) < 2 or not stripped.startswith('"') or not stripped.endswith('"'):
        raise RuleSyntaxError("option value must be enclosed in double quotes")
    return stripped[1:-1]


def _parse_flags(value: str) -> frozenset[str]:
    compact = "".join(value.split()).upper()
    if compact == "0":
        return frozenset()
    if not compact:
        raise RuleSyntaxError("flags value cannot be empty")
    if any(character not in _TCP_FLAG_NAMES for character in compact):
        raise RuleSyntaxError(f"invalid or unsupported TCP flags: {value}")
    return frozenset(_TCP_FLAG_NAMES[character] for character in compact)


def _parse_dsize(value: str) -> DsizeOption:
    compact = value.strip()
    range_match = _DSIZE_RANGE.fullmatch(compact)
    if range_match:
        try:
            return DsizeOption(
                DsizeOperator.RANGE,
                int(range_match.group(1)),
                int(range_match.group(2)),
            )
        except ValueError as exc:
            raise RuleSyntaxError(str(exc)) from exc
    if compact.startswith(">"):
        return DsizeOption(
            DsizeOperator.GREATER_THAN,
            _parse_integer("dsize", compact[1:], minimum=0),
        )
    if compact.startswith("<"):
        return DsizeOption(
            DsizeOperator.LESS_THAN,
            _parse_integer("dsize", compact[1:], minimum=0),
        )
    return DsizeOption(
        DsizeOperator.EQUAL,
        _parse_integer("dsize", compact, minimum=0),
    )


def _parse_flow(value: str) -> tuple[str, ...]:
    values = tuple(item.strip().lower() for item in value.split(",") if item.strip())
    if not values:
        raise RuleSyntaxError("flow requires at least one value")
    if len(values) != len(set(values)):
        raise RuleSyntaxError("flow contains duplicate values")
    return values


def _parse_integer(keyword: str, value: str | None, *, minimum: int) -> int:
    text = _require_value(keyword, value).strip()
    if not _INTEGER.fullmatch(text):
        raise RuleSyntaxError(f"{keyword} must be an integer")
    number = int(text)
    if number < minimum:
        raise RuleSyntaxError(f"{keyword} must be at least {minimum}")
    return number


def _parse_bare_value(keyword: str, value: str | None) -> str:
    text = _require_value(keyword, value).strip().lower()
    if not text or any(character.isspace() for character in text):
        raise RuleSyntaxError(f"{keyword} requires a non-empty token")
    return text


def _require_value(keyword: str, value: str | None) -> str:
    if value is None or value == "":
        raise RuleSyntaxError(f"{keyword} requires a value")
    return value


def _invalid(
    rule: InternalRule,
    reason: str,
    *,
    position: int | None = None,
    keyword: str | None = None,
) -> None:
    rule.diagnostics.append(
        RuleDiagnostic(
            kind=DiagnosticKind.INVALID,
            reason=reason,
            position=position,
            keyword=keyword,
        )
    )
