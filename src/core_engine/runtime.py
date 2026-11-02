"""Runtime composition for loading rules and inspecting normalized events."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from src.core_engine.detection import DetectionEventGenerator
from src.core_engine.evaluator import EvaluationResult, RuleEvaluationEngine
from src.core_engine.loader import (
    RuleLoadDiagnostic,
    RuleLoadResult,
    RuleLoader,
    RuleLoaderConfig,
)
from src.core_engine.models import DetectionEvent, DiagnosticKind, InternalRule
from src.core_engine.parser import SnortRuleParser
from src.core_engine.repository import RuleRepository


@dataclass(frozen=True)
class CoreInspectionResult:
    evaluation: EvaluationResult
    detections: tuple[DetectionEvent, ...] = ()


class CoreEngineRuntime:
    """Ready-to-use repository, evaluator and detection generator."""

    def __init__(
        self,
        repository: RuleRepository,
        *,
        load_result: RuleLoadResult | None = None,
        evaluator: RuleEvaluationEngine | None = None,
        detection_generator: DetectionEventGenerator | None = None,
        duplicate_sids: Iterable[int] = (),
    ) -> None:
        self.repository = repository
        self.load_result = load_result or RuleLoadResult()
        self.evaluator = evaluator or RuleEvaluationEngine(repository)
        self.detection_generator = detection_generator or DetectionEventGenerator()
        self.duplicate_sids = tuple(sorted(set(duplicate_sids)))

    @property
    def active_rule_count(self) -> int:
        return len(self.repository)

    @property
    def diagnostics(self) -> tuple[RuleLoadDiagnostic, ...]:
        return tuple(self.load_result.diagnostics)

    def inspect(
        self,
        event: object,
        *,
        payload: bytes | bytearray | memoryview | None = None,
    ) -> CoreInspectionResult:
        evaluation = self.evaluator.evaluate(event, payload=payload)
        detections = self.detection_generator.generate_from_result(evaluation)
        return CoreInspectionResult(
            evaluation=evaluation,
            detections=detections,
        )

    @classmethod
    def from_rule_files(
        cls,
        paths: Iterable[str | Path] | str | Path,
        *,
        disabled_files: Iterable[str | Path] = (),
        disabled_sids: Iterable[int] = (),
    ) -> CoreEngineRuntime:
        config = RuleLoaderConfig(
            disabled_files=frozenset(str(path) for path in disabled_files),
            disabled_sids=frozenset(disabled_sids),
        )
        load_result = RuleLoader(SnortRuleParser(), config).load_files(paths)
        duplicate_sids = _disable_duplicate_sids(load_result)
        repository = RuleRepository(load_result.active_rules)
        return cls(
            repository,
            load_result=load_result,
            duplicate_sids=duplicate_sids,
        )


def _disable_duplicate_sids(load_result: RuleLoadResult) -> set[int]:
    groups: dict[int, list[tuple[int, InternalRule]]] = {}
    for index, rule in enumerate(load_result.rules):
        if rule.is_evaluable and rule.sid is not None:
            groups.setdefault(rule.sid, []).append((index, rule))

    duplicates: set[int] = set()
    for sid, entries in groups.items():
        if len(entries) < 2:
            continue
        duplicates.add(sid)
        _, winner = max(
            entries,
            key=lambda item: (item[1].rev or 0, -item[0]),
        )
        for _, rule in entries:
            if rule is winner:
                continue
            rule.enabled = False
            load_result.diagnostics.append(
                RuleLoadDiagnostic(
                    kind=DiagnosticKind.WARNING,
                    reason=(
                        f"duplicate SID {sid} disabled; using revision "
                        f"{winner.rev} from {winner.source_file or '<unknown>'}"
                    ),
                    source_file=rule.source_file or "<unknown>",
                    source_line=rule.source_line,
                )
            )
    return duplicates
