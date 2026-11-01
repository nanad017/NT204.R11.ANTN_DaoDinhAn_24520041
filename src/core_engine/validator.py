"""Semantic validation for the supported Snort rule subset."""

from __future__ import annotations

from src.core_engine.models import (
    DiagnosticKind,
    InternalRule,
    RuleDiagnostic,
    RuleStatus,
)


SUPPORTED_ACTIONS = frozenset({"alert"})
SUPPORTED_PROTOCOLS = frozenset({"tcp", "udp"})
SUPPORTED_DIRECTIONS = frozenset({"->", "<>"})
SUPPORTED_FLOW_VALUES = frozenset(
    {"to_server", "to_client", "established", "not_established"}
)


class RuleValidator:
    def validate(self, rule: InternalRule) -> InternalRule:
        self._validate_header(rule)
        self._validate_identification(rule)
        self._validate_content(rule)
        self._validate_packet_options(rule)
        self._validate_flow(rule)
        self._validate_classification(rule)
        rule.status = _status_from_diagnostics(rule.diagnostics)
        return rule

    def _validate_header(self, rule: InternalRule) -> None:
        header = rule.header
        if header is None:
            _add_diagnostic(rule, DiagnosticKind.INVALID, "rule header is required")
            return

        if header.action not in SUPPORTED_ACTIONS:
            _add_diagnostic(
                rule,
                DiagnosticKind.UNSUPPORTED,
                f"unsupported rule action: {header.action}",
                keyword=header.action,
            )
        if header.protocol not in SUPPORTED_PROTOCOLS:
            _add_diagnostic(
                rule,
                DiagnosticKind.UNSUPPORTED,
                f"unsupported protocol: {header.protocol}",
                keyword=header.protocol,
            )
        if header.direction not in SUPPORTED_DIRECTIONS:
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                f"invalid rule direction: {header.direction}",
            )

    def _validate_identification(self, rule: InternalRule) -> None:
        if not isinstance(rule.msg, str) or not rule.msg:
            _add_diagnostic(rule, DiagnosticKind.INVALID, "msg is required", keyword="msg")
        if not _positive_integer(rule.sid):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "sid must be a positive integer",
                keyword="sid",
            )
        if not _positive_integer(rule.rev):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "rev must be a positive integer",
                keyword="rev",
            )

    def _validate_content(self, rule: InternalRule) -> None:
        for index, content in enumerate(rule.contents):
            if not content.pattern:
                _add_diagnostic(
                    rule,
                    DiagnosticKind.INVALID,
                    "content pattern cannot be empty",
                    keyword="content",
                )
            absolute = content.offset is not None or content.depth is not None
            relative = content.distance is not None or content.within is not None
            if absolute and relative:
                _add_diagnostic(
                    rule,
                    DiagnosticKind.INVALID,
                    "content cannot mix offset/depth with distance/within",
                    keyword="content",
                )
            if index == 0 and relative:
                _add_diagnostic(
                    rule,
                    DiagnosticKind.INVALID,
                    "first content cannot use distance or within",
                    keyword="content",
                )

    def _validate_packet_options(self, rule: InternalRule) -> None:
        if rule.flags and rule.header is not None and rule.header.protocol != "tcp":
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "flags can only be used with TCP rules",
                keyword="flags",
            )

    def _validate_flow(self, rule: InternalRule) -> None:
        values = set(rule.flow)
        for value in values - SUPPORTED_FLOW_VALUES:
            _add_diagnostic(
                rule,
                DiagnosticKind.UNSUPPORTED,
                f"unsupported flow value: {value}",
                keyword="flow",
            )
        if {"to_server", "to_client"}.issubset(values):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "flow cannot contain both to_server and to_client",
                keyword="flow",
            )
        if {"established", "not_established"}.issubset(values):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "flow cannot contain both established and not_established",
                keyword="flow",
            )
        if (
            values & {"established", "not_established"}
            and rule.header is not None
            and rule.header.protocol != "tcp"
        ):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "established flow state requires a TCP rule",
                keyword="flow",
            )

    def _validate_classification(self, rule: InternalRule) -> None:
        if rule.classtype is not None and not rule.classtype:
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "classtype cannot be empty",
                keyword="classtype",
            )
        if rule.priority is not None and not _positive_integer(rule.priority):
            _add_diagnostic(
                rule,
                DiagnosticKind.INVALID,
                "priority must be a positive integer",
                keyword="priority",
            )


def _positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _add_diagnostic(
    rule: InternalRule,
    kind: DiagnosticKind,
    reason: str,
    *,
    keyword: str | None = None,
) -> None:
    if any(
        item.kind == kind and item.reason == reason and item.keyword == keyword
        for item in rule.diagnostics
    ):
        return
    rule.diagnostics.append(
        RuleDiagnostic(kind=kind, reason=reason, keyword=keyword)
    )


def _status_from_diagnostics(diagnostics: list[RuleDiagnostic]) -> RuleStatus:
    kinds = {item.kind for item in diagnostics}
    if DiagnosticKind.INVALID in kinds:
        return RuleStatus.INVALID
    if DiagnosticKind.UNSUPPORTED in kinds:
        return RuleStatus.UNSUPPORTED
    return RuleStatus.VALID
