"""Validated rule repository and protocol/port candidate index."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from src.core_engine.models import InternalRule, PortSpec


class CandidateEventProtocol(Protocol):
    proto: str | None
    src_port: int | None
    dest_port: int | None


@dataclass(frozen=True)
class RepositoryUpdateResult:
    added: int = 0
    skipped: int = 0
    duplicates: int = 0


@dataclass(frozen=True)
class RepositoryStatistics:
    rules_indexed: int = 0
    rules_skipped: int = 0
    duplicate_additions: int = 0
    candidate_queries: int = 0
    candidates_returned: int = 0


class RuleRepository:
    """Store evaluable rules and select candidates before full matching.

    Exact single ports are indexed directly. Rules that use ``any`` or ranges
    on both relevant endpoints are kept in a small protocol-specific flexible
    bucket and receive a final port check during lookup. IP/CIDR matching is
    deliberately left to the Header Matcher in phase 5.
    """

    def __init__(self, rules: Iterable[InternalRule] | None = None) -> None:
        self._rules: dict[int, InternalRule] = {}
        self._object_keys: dict[int, int] = {}
        self._next_key = 1
        self._protocol_index: dict[str, set[int]] = {}
        self._forward_destination_index: dict[tuple[str, int], set[int]] = {}
        self._forward_source_index: dict[tuple[str, int], set[int]] = {}
        self._bidirectional_port_index: dict[tuple[str, int], set[int]] = {}
        self._flexible_port_index: dict[str, set[int]] = {}
        self._rules_skipped = 0
        self._duplicate_additions = 0
        self._candidate_queries = 0
        self._candidates_returned = 0
        if rules is not None:
            self.add_many(rules)

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[InternalRule, ...]:
        return tuple(self._rules.values())

    @property
    def statistics(self) -> RepositoryStatistics:
        return RepositoryStatistics(
            rules_indexed=len(self._rules),
            rules_skipped=self._rules_skipped,
            duplicate_additions=self._duplicate_additions,
            candidate_queries=self._candidate_queries,
            candidates_returned=self._candidates_returned,
        )

    def add(self, rule: InternalRule) -> bool:
        if not isinstance(rule, InternalRule):
            raise TypeError("repository only accepts InternalRule objects")
        if not rule.is_evaluable:
            self._rules_skipped += 1
            return False

        object_id = id(rule)
        if object_id in self._object_keys:
            self._duplicate_additions += 1
            return False

        key = self._next_key
        self._next_key += 1
        self._rules[key] = rule
        self._object_keys[object_id] = key
        self._index_rule(key, rule)
        return True

    def add_many(self, rules: Iterable[InternalRule]) -> RepositoryUpdateResult:
        added = 0
        skipped = 0
        duplicates = 0
        for rule in rules:
            was_duplicate = isinstance(rule, InternalRule) and id(rule) in self._object_keys
            if self.add(rule):
                added += 1
            elif was_duplicate:
                duplicates += 1
            else:
                skipped += 1
        return RepositoryUpdateResult(
            added=added,
            skipped=skipped,
            duplicates=duplicates,
        )

    def rebuild(self, rules: Iterable[InternalRule]) -> RepositoryUpdateResult:
        self.clear()
        return self.add_many(rules)

    def clear(self) -> None:
        self._rules.clear()
        self._object_keys.clear()
        self._next_key = 1
        self._protocol_index.clear()
        self._forward_destination_index.clear()
        self._forward_source_index.clear()
        self._bidirectional_port_index.clear()
        self._flexible_port_index.clear()
        self._rules_skipped = 0
        self._duplicate_additions = 0
        self._candidate_queries = 0
        self._candidates_returned = 0

    def candidates_for_event(
        self,
        event: CandidateEventProtocol,
    ) -> list[InternalRule]:
        return self.get_candidates(
            getattr(event, "proto", None),
            getattr(event, "src_port", None),
            getattr(event, "dest_port", None),
        )

    def get_candidates(
        self,
        protocol: str | None,
        src_port: int | None,
        dest_port: int | None,
    ) -> list[InternalRule]:
        self._candidate_queries += 1
        normalized_protocol = _normalize_protocol(protocol)
        if (
            normalized_protocol is None
            or not _valid_port(src_port)
            or not _valid_port(dest_port)
        ):
            return []

        keys = set(self._flexible_port_index.get(normalized_protocol, ()))
        keys.update(
            self._forward_destination_index.get(
                (normalized_protocol, dest_port), ()
            )
        )
        keys.update(
            self._forward_source_index.get((normalized_protocol, src_port), ())
        )
        keys.update(
            self._bidirectional_port_index.get(
                (normalized_protocol, src_port), ()
            )
        )
        keys.update(
            self._bidirectional_port_index.get(
                (normalized_protocol, dest_port), ()
            )
        )

        candidates = [
            self._rules[key]
            for key in sorted(keys)
            if self._rules[key].is_evaluable
            and _ports_match(self._rules[key], src_port, dest_port)
        ]
        self._candidates_returned += len(candidates)
        return candidates

    query = get_candidates

    def protocol_rule_count(self, protocol: str) -> int:
        normalized = _normalize_protocol(protocol)
        return len(self._protocol_index.get(normalized or "", ()))

    def _index_rule(self, key: int, rule: InternalRule) -> None:
        header = rule.header
        if header is None:
            return
        protocol = header.protocol.lower()
        self._protocol_index.setdefault(protocol, set()).add(key)

        if header.direction == "->":
            if header.destination_port.is_single:
                self._add_port_index(
                    self._forward_destination_index,
                    protocol,
                    header.destination_port.start,
                    key,
                )
            elif header.source_port.is_single:
                self._add_port_index(
                    self._forward_source_index,
                    protocol,
                    header.source_port.start,
                    key,
                )
            else:
                self._flexible_port_index.setdefault(protocol, set()).add(key)
            return

        if header.direction == "<>":
            exact_ports = {
                port.start
                for port in (header.source_port, header.destination_port)
                if port.is_single
            }
            if exact_ports:
                for port in exact_ports:
                    self._add_port_index(
                        self._bidirectional_port_index,
                        protocol,
                        port,
                        key,
                    )
            else:
                self._flexible_port_index.setdefault(protocol, set()).add(key)
            return

        self._flexible_port_index.setdefault(protocol, set()).add(key)

    @staticmethod
    def _add_port_index(
        index: dict[tuple[str, int], set[int]],
        protocol: str,
        port: int | None,
        key: int,
    ) -> None:
        if port is not None:
            index.setdefault((protocol, port), set()).add(key)


RuleIndexer = RuleRepository


def _normalize_protocol(protocol: str | None) -> str | None:
    if not isinstance(protocol, str):
        return None
    normalized = protocol.strip().lower()
    return normalized if normalized else None


def _valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535


def _port_contains(spec: PortSpec, port: int) -> bool:
    return spec.is_any or (
        spec.start is not None
        and spec.end is not None
        and spec.start <= port <= spec.end
    )


def _ports_match(rule: InternalRule, src_port: int, dest_port: int) -> bool:
    header = rule.header
    if header is None:
        return False
    forward = _port_contains(header.source_port, src_port) and _port_contains(
        header.destination_port, dest_port
    )
    if header.direction == "->":
        return forward
    if header.direction == "<>":
        reverse = _port_contains(header.source_port, dest_port) and _port_contains(
            header.destination_port, src_port
        )
        return forward or reverse
    return False
