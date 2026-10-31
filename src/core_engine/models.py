"""Internal data model shared by the Core Engine components.

The models in this module intentionally depend only on the Python standard
library.  Rule loading, parsing, indexing and matching can therefore consume
normalized IDS events without importing or receiving Scapy packets.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from ipaddress import IPv4Network
from typing import Any


class RuleStatus(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"


class DiagnosticKind(str, Enum):
    INVALID = "invalid"
    UNSUPPORTED = "unsupported"
    WARNING = "warning"


class MatchStatus(str, Enum):
    MATCH = "match"
    NO_MATCH = "no_match"


class DsizeOperator(str, Enum):
    EQUAL = "equal"
    LESS_THAN = "less_than"
    GREATER_THAN = "greater_than"
    RANGE = "range"


@dataclass(frozen=True)
class IPAddressSpec:
    """Normalized IPv4 header address.

    A ``None`` network represents Snort's ``any`` address. Invalid input is
    retained in a RuleDiagnostic instead of being represented by this class.
    """

    raw: str
    network: IPv4Network | None = None

    @property
    def is_any(self) -> bool:
        return self.network is None

    @classmethod
    def match_any(cls) -> IPAddressSpec:
        return cls(raw="any")


@dataclass(frozen=True)
class PortSpec:
    """Normalized Snort port selector; ``None`` bounds represent ``any``."""

    raw: str
    start: int | None = None
    end: int | None = None

    def __post_init__(self) -> None:
        if (self.start is None) != (self.end is None):
            raise ValueError("port range must define both start and end")
        if self.start is None:
            return
        if not 0 <= self.start <= self.end <= 65535:
            raise ValueError("port range must be within 0..65535")

    @property
    def is_any(self) -> bool:
        return self.start is None

    @property
    def is_single(self) -> bool:
        return self.start is not None and self.start == self.end

    @classmethod
    def match_any(cls) -> PortSpec:
        return cls(raw="any")

    @classmethod
    def single(cls, value: int) -> PortSpec:
        return cls(raw=str(value), start=value, end=value)

    @classmethod
    def range(cls, start: int, end: int) -> PortSpec:
        return cls(raw=f"{start}:{end}", start=start, end=end)


@dataclass(frozen=True)
class RuleHeader:
    action: str
    protocol: str
    source_ip: IPAddressSpec
    source_port: PortSpec
    direction: str
    destination_ip: IPAddressSpec
    destination_port: PortSpec


@dataclass(frozen=True)
class RuleOption:
    """A parsed option that is not represented by a dedicated model."""

    keyword: str
    value: Any = None


@dataclass(frozen=True)
class ContentOption:
    pattern: bytes
    raw: str
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    distance: int | None = None
    within: int | None = None


@dataclass(frozen=True)
class DsizeOption:
    operator: DsizeOperator
    value: int
    upper: int | None = None

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ValueError("dsize cannot be negative")
        if self.operator == DsizeOperator.RANGE:
            if self.upper is None or self.upper < self.value:
                raise ValueError("dsize range requires an upper bound >= value")
        elif self.upper is not None:
            raise ValueError("upper is only valid for a dsize range")


@dataclass(frozen=True)
class RuleDiagnostic:
    kind: DiagnosticKind
    reason: str
    position: int | None = None
    keyword: str | None = None


@dataclass
class InternalRule:
    """Unified representation exchanged by parser, repository and matcher."""

    raw_text: str
    status: RuleStatus
    header: RuleHeader | None = None
    msg: str | None = None
    sid: int | None = None
    rev: int | None = None
    contents: list[ContentOption] = field(default_factory=list)
    flow: tuple[str, ...] = ()
    flags: frozenset[str] = field(default_factory=frozenset)
    dsize: DsizeOption | None = None
    classtype: str | None = None
    priority: int | None = None
    options: list[RuleOption] = field(default_factory=list)
    diagnostics: list[RuleDiagnostic] = field(default_factory=list)
    source_file: str | None = None
    source_line: int | None = None
    enabled: bool = True

    @property
    def is_evaluable(self) -> bool:
        return (
            self.enabled
            and self.status == RuleStatus.VALID
            and self.header is not None
            and self.msg is not None
            and self.sid is not None
            and self.rev is not None
        )


@dataclass(frozen=True)
class MatchInformation:
    kind: str
    buffer: str | None = None
    field: str | None = None
    content: str | None = None
    start: int | None = None
    end: int | None = None


@dataclass
class RuleMatch:
    status: MatchStatus
    sid: int
    rev: int
    msg: str
    matched_information: list[MatchInformation] = field(default_factory=list)
    reason: str | None = None

    @property
    def matched(self) -> bool:
        return self.status == MatchStatus.MATCH


@dataclass
class EvaluationStatistics:
    events_evaluated: int = 0
    candidate_rules: int = 0
    rules_evaluated: int = 0
    matches: int = 0

    def record(
        self,
        *,
        candidate_rules: int,
        rules_evaluated: int,
        matches: int,
    ) -> None:
        if min(candidate_rules, rules_evaluated, matches) < 0:
            raise ValueError("evaluation counters cannot be negative")
        if rules_evaluated > candidate_rules:
            raise ValueError("rules_evaluated cannot exceed candidate_rules")
        if matches > rules_evaluated:
            raise ValueError("matches cannot exceed rules_evaluated")
        self.events_evaluated += 1
        self.candidate_rules += candidate_rules
        self.rules_evaluated += rules_evaluated
        self.matches += matches


@dataclass
class DetectionEvent:
    timestamp: str
    sid: int
    rev: int
    msg: str
    src_ip: str
    dest_ip: str
    protocol: str
    event_type: str = field(default="detection", init=False)
    src_port: int | None = None
    dest_port: int | None = None
    priority: int | None = None
    classtype: str | None = None
    application_protocol: str | None = None
    flow_id: int | None = None
    flow_direction: str | None = None
    flow_role: str | None = None
    matched_information: list[MatchInformation] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


def _clean(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            cleaned = _clean(item)
            if cleaned is None or cleaned == {} or cleaned == []:
                continue
            result[key] = cleaned
        return result
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value]
    return value
