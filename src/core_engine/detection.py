"""Convert successful rule evaluations into unified detection events."""

from __future__ import annotations

import json
from ipaddress import IPv4Address, ip_address

from src.core_engine.evaluator import EvaluationResult, RuleEvaluation
from src.core_engine.models import (
    DetectionEvent,
    InternalRule,
    MatchInformation,
    RuleMatch,
)


class DetectionEventGenerationError(ValueError):
    """Raised when a matched rule cannot produce a valid detection event."""


class DetectionEventGenerator:
    """Create output-neutral detection events without logging side effects."""

    def generate(
        self,
        event: object,
        rule: InternalRule,
        match: RuleMatch,
    ) -> DetectionEvent | None:
        if not match.matched:
            return None
        self._validate_rule_match(rule, match)

        timestamp = _required_text(event, "timestamp")
        src_ip = _required_ipv4(event, "src_ip")
        dest_ip = _required_ipv4(event, "dest_ip")
        src_port = _required_port(event, "src_port")
        dest_port = _required_port(event, "dest_port")
        protocol = _required_protocol(event)
        flow_id = _required_flow_id(event)

        application_protocol = getattr(event, "app_proto", None)
        if not isinstance(application_protocol, str) or not application_protocol.strip():
            application_protocol = "unknown"
        else:
            application_protocol = application_protocol.strip().lower()

        matched_information = list(match.matched_information)
        if not matched_information:
            matched_information.append(
                MatchInformation(kind="rule", field="header/options")
            )

        return DetectionEvent(
            timestamp=timestamp,
            sid=match.sid,
            rev=match.rev,
            msg=match.msg,
            src_ip=src_ip,
            src_port=src_port,
            dest_ip=dest_ip,
            dest_port=dest_port,
            protocol=protocol,
            priority=rule.priority,
            classtype=rule.classtype,
            application_protocol=application_protocol,
            flow_id=flow_id,
            flow_direction=_optional_text(event, "flow_direction"),
            flow_role=_optional_text(event, "flow_role"),
            matched_information=matched_information,
        )

    def generate_for_evaluation(
        self,
        event: object,
        evaluation: RuleEvaluation,
    ) -> DetectionEvent | None:
        return self.generate(event, evaluation.rule, evaluation.match)

    def generate_from_result(
        self,
        result: EvaluationResult,
    ) -> tuple[DetectionEvent, ...]:
        events: list[DetectionEvent] = []
        for evaluation in result.matched_evaluations:
            detection = self.generate_for_evaluation(result.event, evaluation)
            if detection is not None:
                events.append(detection)
        return tuple(events)

    generate_all = generate_from_result

    @staticmethod
    def _validate_rule_match(rule: InternalRule, match: RuleMatch) -> None:
        if not rule.is_evaluable:
            raise DetectionEventGenerationError("matched rule is not evaluable")
        if (rule.sid, rule.rev, rule.msg) != (match.sid, match.rev, match.msg):
            raise DetectionEventGenerationError(
                "rule and match identity do not agree"
            )


def generate_detection_events(
    result: EvaluationResult,
) -> tuple[DetectionEvent, ...]:
    return DetectionEventGenerator().generate_from_result(result)


def detection_event_to_json(
    event: DetectionEvent,
    *,
    ensure_ascii: bool = False,
) -> str:
    if not isinstance(event, DetectionEvent):
        raise TypeError("event must be a DetectionEvent")
    return json.dumps(
        event.to_dict(),
        ensure_ascii=ensure_ascii,
        separators=(",", ":"),
    )


def _required_text(event: object, field: str) -> str:
    value = getattr(event, field, None)
    if not isinstance(value, str) or not value.strip():
        raise DetectionEventGenerationError(f"event.{field} is required")
    return value.strip()


def _optional_text(event: object, field: str) -> str | None:
    value = getattr(event, field, None)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DetectionEventGenerationError(
            f"event.{field} must be a non-empty string when provided"
        )
    return value.strip()


def _required_ipv4(event: object, field: str) -> str:
    value = _required_text(event, field)
    try:
        address = ip_address(value)
    except ValueError as exc:
        raise DetectionEventGenerationError(
            f"event.{field} must be a valid IPv4 address"
        ) from exc
    if not isinstance(address, IPv4Address):
        raise DetectionEventGenerationError(
            f"event.{field} must be a valid IPv4 address"
        )
    return str(address)


def _required_port(event: object, field: str) -> int:
    value = getattr(event, field, None)
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535:
        raise DetectionEventGenerationError(
            f"event.{field} must be an integer in range 0..65535"
        )
    return value


def _required_protocol(event: object) -> str:
    protocol = _required_text(event, "proto").upper()
    if protocol not in {"TCP", "UDP"}:
        raise DetectionEventGenerationError(
            "event.proto must be TCP or UDP"
        )
    return protocol


def _required_flow_id(event: object) -> int:
    value = getattr(event, "flow_id", None)
    if value is None:
        value = getattr(getattr(event, "flow", None), "flow_id", None)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise DetectionEventGenerationError(
            "event.flow_id is required and must be a positive integer"
        )
    return value
