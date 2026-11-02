"""Candidate rule evaluation and aggregate matching statistics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from src.core_engine.inspection import InspectionContext, InspectionContextBuilder
from src.core_engine.matcher import RuleMatcher
from src.core_engine.models import EvaluationStatistics, InternalRule, RuleMatch
from src.core_engine.repository import RuleRepository


class EvaluationRepositoryProtocol(Protocol):
    def candidates_for_event(self, event: object) -> list[InternalRule]: ...


class EvaluationMatcherProtocol(Protocol):
    def match(
        self,
        rule: InternalRule,
        event: object,
        context: InspectionContext | None = None,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> RuleMatch: ...


class InspectionBuilderProtocol(Protocol):
    def build(
        self,
        event: object,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> InspectionContext: ...


@dataclass(frozen=True)
class RuleEvaluation:
    rule: InternalRule
    match: RuleMatch

    @property
    def matched(self) -> bool:
        return self.match.matched


@dataclass(frozen=True)
class RuleEvaluationError:
    sid: int | None
    rev: int | None
    reason: str
    error_type: str
    source_file: str | None = None
    source_line: int | None = None


@dataclass(frozen=True)
class EvaluationResult:
    event: object
    candidates: tuple[InternalRule, ...] = ()
    evaluations: tuple[RuleEvaluation, ...] = ()
    errors: tuple[RuleEvaluationError, ...] = ()

    @property
    def candidate_count(self) -> int:
        return len(self.candidates)

    @property
    def rules_evaluated(self) -> int:
        return len(self.evaluations) + len(self.errors)

    @property
    def matches(self) -> tuple[RuleMatch, ...]:
        return tuple(item.match for item in self.evaluations if item.matched)

    @property
    def matched_evaluations(self) -> tuple[RuleEvaluation, ...]:
        return tuple(item for item in self.evaluations if item.matched)

    @property
    def matched_rules(self) -> tuple[InternalRule, ...]:
        return tuple(item.rule for item in self.matched_evaluations)

    @property
    def match_count(self) -> int:
        return len(self.matches)


class RuleEvaluationEngine:
    """Evaluate every repository candidate while isolating per-rule errors."""

    def __init__(
        self,
        repository: EvaluationRepositoryProtocol | None = None,
        *,
        matcher: EvaluationMatcherProtocol | None = None,
        inspection_builder: InspectionBuilderProtocol | None = None,
        statistics: EvaluationStatistics | None = None,
    ) -> None:
        self.repository = repository if repository is not None else RuleRepository()
        self.matcher = matcher if matcher is not None else RuleMatcher()
        self.inspection_builder = (
            inspection_builder
            if inspection_builder is not None
            else InspectionContextBuilder()
        )
        self.statistics = (
            statistics if statistics is not None else EvaluationStatistics()
        )

    def evaluate(
        self,
        event: object,
        context: InspectionContext | None = None,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> EvaluationResult:
        candidates = tuple(self.repository.candidates_for_event(event))
        evaluations: list[RuleEvaluation] = []
        errors: list[RuleEvaluationError] = []

        inspection = context
        inspection_attempted = context is not None
        inspection_error: Exception | None = None

        for rule in candidates:
            try:
                if rule.contents and inspection is None:
                    if not inspection_attempted:
                        inspection_attempted = True
                        try:
                            inspection = self.inspection_builder.build(
                                event,
                                payload=payload,
                            )
                        except Exception as exc:
                            inspection_error = exc
                    if inspection_error is not None:
                        raise inspection_error

                match = self.matcher.match(
                    rule,
                    event,
                    inspection,
                    payload=payload if inspection is None else None,
                )
                if not isinstance(match, RuleMatch):
                    raise TypeError("matcher must return a RuleMatch")
                evaluations.append(RuleEvaluation(rule=rule, match=match))
            except Exception as exc:
                errors.append(_evaluation_error(rule, exc))

        match_count = sum(item.matched for item in evaluations)
        self.statistics.record(
            candidate_rules=len(candidates),
            rules_evaluated=len(candidates),
            matches=match_count,
        )
        return EvaluationResult(
            event=event,
            candidates=candidates,
            evaluations=tuple(evaluations),
            errors=tuple(errors),
        )

    def evaluate_matches(
        self,
        event: object,
        context: InspectionContext | None = None,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> tuple[RuleMatch, ...]:
        return self.evaluate(event, context, payload=payload).matches

    def reset_statistics(self) -> None:
        self.statistics.events_evaluated = 0
        self.statistics.candidate_rules = 0
        self.statistics.rules_evaluated = 0
        self.statistics.matches = 0

    __call__ = evaluate


EvaluationEngine = RuleEvaluationEngine


def evaluate_event(
    repository: EvaluationRepositoryProtocol,
    event: object,
    context: InspectionContext | None = None,
    *,
    payload: bytes | bytearray | memoryview | None = None,
) -> EvaluationResult:
    return RuleEvaluationEngine(repository).evaluate(
        event,
        context,
        payload=payload,
    )


def _evaluation_error(
    rule: InternalRule,
    error: Exception,
) -> RuleEvaluationError:
    reason = str(error).strip() or error.__class__.__name__
    return RuleEvaluationError(
        sid=rule.sid,
        rev=rule.rev,
        reason=reason,
        error_type=error.__class__.__name__,
        source_file=rule.source_file,
        source_line=rule.source_line,
    )
