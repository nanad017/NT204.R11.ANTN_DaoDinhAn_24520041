"""Load Snort rules from files without coupling the loader to parser logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

from src.core_engine.models import (
    DiagnosticKind,
    InternalRule,
    RuleDiagnostic,
    RuleStatus,
)


@runtime_checkable
class RuleParserProtocol(Protocol):
    """Interface implemented by the Rule Parser in Assignment 3 phase 3."""

    def parse(
        self,
        rule_text: str,
        *,
        source_file: str | None = None,
        source_line: int | None = None,
    ) -> InternalRule: ...


@dataclass(frozen=True)
class RuleLoaderConfig:
    """Enable/disable policy applied after a rule has been parsed."""

    disabled_files: frozenset[str] = field(default_factory=frozenset)
    disabled_sids: frozenset[int] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        normalized_files = frozenset(_normalize_path(item) for item in self.disabled_files)
        normalized_sids = frozenset(self.disabled_sids)
        if any(
            not isinstance(sid, int) or isinstance(sid, bool) or sid <= 0
            for sid in normalized_sids
        ):
            raise ValueError("disabled SIDs must be positive integers")
        object.__setattr__(self, "disabled_files", normalized_files)
        object.__setattr__(self, "disabled_sids", normalized_sids)

    def is_file_enabled(self, path: str | Path) -> bool:
        return _normalize_path(path) not in self.disabled_files

    def is_sid_enabled(self, sid: int | None) -> bool:
        return sid is None or sid not in self.disabled_sids


@dataclass(frozen=True)
class RuleLoadDiagnostic:
    kind: DiagnosticKind
    reason: str
    source_file: str
    source_line: int | None = None
    position: int | None = None
    keyword: str | None = None


@dataclass
class RuleLoadResult:
    rules: list[InternalRule] = field(default_factory=list)
    diagnostics: list[RuleLoadDiagnostic] = field(default_factory=list)
    files_seen: int = 0
    files_loaded: int = 0
    files_skipped: int = 0
    rule_lines_seen: int = 0

    @property
    def valid_count(self) -> int:
        return self._count_status(RuleStatus.VALID)

    @property
    def invalid_count(self) -> int:
        return self._count_status(RuleStatus.INVALID)

    @property
    def unsupported_count(self) -> int:
        return self._count_status(RuleStatus.UNSUPPORTED)

    @property
    def disabled_count(self) -> int:
        return sum(not rule.enabled for rule in self.rules)

    @property
    def active_rules(self) -> list[InternalRule]:
        return [rule for rule in self.rules if rule.is_evaluable]

    def _count_status(self, status: RuleStatus) -> int:
        return sum(rule.status == status for rule in self.rules)


class RuleLoader:
    def __init__(
        self,
        parser: RuleParserProtocol,
        config: RuleLoaderConfig | None = None,
    ) -> None:
        if not isinstance(parser, RuleParserProtocol):
            raise TypeError("parser must provide a parse method")
        self.parser = parser
        self.config = config or RuleLoaderConfig()

    def load_file(self, path: str | Path) -> RuleLoadResult:
        return self.load_files([path])

    def load_files(
        self,
        paths: Iterable[str | Path] | str | Path,
    ) -> RuleLoadResult:
        if isinstance(paths, (str, Path)):
            paths = [paths]

        result = RuleLoadResult()
        for item in paths:
            self._load_path(Path(item), result)
        return result

    def _load_path(self, path: Path, result: RuleLoadResult) -> None:
        result.files_seen += 1
        source_file = str(path)

        if not self.config.is_file_enabled(path):
            result.files_skipped += 1
            result.diagnostics.append(
                RuleLoadDiagnostic(
                    kind=DiagnosticKind.WARNING,
                    reason="rule file disabled by configuration",
                    source_file=source_file,
                )
            )
            return

        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            result.diagnostics.append(
                RuleLoadDiagnostic(
                    kind=DiagnosticKind.INVALID,
                    reason=f"could not read rule file: {exc}",
                    source_file=source_file,
                )
            )
            return

        result.files_loaded += 1
        for source_line, rule_text in _iter_rule_texts(content.splitlines()):
            result.rule_lines_seen += 1
            rule = self._parse_rule(rule_text, source_file, source_line, result)
            if not self.config.is_sid_enabled(rule.sid):
                rule.enabled = False
                result.diagnostics.append(
                    RuleLoadDiagnostic(
                        kind=DiagnosticKind.WARNING,
                        reason=f"rule SID {rule.sid} disabled by configuration",
                        source_file=source_file,
                        source_line=source_line,
                    )
                )
            result.rules.append(rule)

    def _parse_rule(
        self,
        rule_text: str,
        source_file: str,
        source_line: int,
        result: RuleLoadResult,
    ) -> InternalRule:
        try:
            rule = self.parser.parse(
                rule_text,
                source_file=source_file,
                source_line=source_line,
            )
            if not isinstance(rule, InternalRule):
                raise TypeError("parser did not return InternalRule")
        except Exception as exc:
            reason = f"rule parser failed: {exc}"
            diagnostic = RuleDiagnostic(
                kind=DiagnosticKind.INVALID,
                reason=reason,
            )
            result.diagnostics.append(
                RuleLoadDiagnostic(
                    kind=diagnostic.kind,
                    reason=diagnostic.reason,
                    source_file=source_file,
                    source_line=source_line,
                )
            )
            return InternalRule(
                raw_text=rule_text,
                status=RuleStatus.INVALID,
                diagnostics=[diagnostic],
                source_file=source_file,
                source_line=source_line,
            )

        rule.source_file = source_file
        rule.source_line = source_line
        self._collect_rule_diagnostics(rule, result)
        return rule

    @staticmethod
    def _collect_rule_diagnostics(
        rule: InternalRule,
        result: RuleLoadResult,
    ) -> None:
        for diagnostic in rule.diagnostics:
            result.diagnostics.append(
                RuleLoadDiagnostic(
                    kind=diagnostic.kind,
                    reason=diagnostic.reason,
                    source_file=rule.source_file or "<unknown>",
                    source_line=rule.source_line,
                    position=diagnostic.position,
                    keyword=diagnostic.keyword,
                )
            )


def _iter_rule_texts(lines: Iterable[str]) -> Iterable[tuple[int, str]]:
    """Yield rule text and its first line, supporting backslash continuation."""

    fragments: list[str] = []
    first_line: int | None = None

    for line_number, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if first_line is None:
            first_line = line_number

        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        fragments.append(fragment)

        if continued:
            continue

        yield first_line, " ".join(fragments)
        fragments = []
        first_line = None

    if fragments and first_line is not None:
        yield first_line, " ".join(fragments)


def _normalize_path(path: str | Path) -> str:
    return str(Path(path).expanduser().resolve(strict=False))
