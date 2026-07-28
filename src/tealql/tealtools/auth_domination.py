"""Flags sensitive sinks that no auth-shaped path predicate dominates.

A sink is clean iff some predicate at its BB matches some matcher; new sink
families / guard patterns are appended to ``sinks`` / ``matchers``.

HAZARD: guards are recognised by walking ``defined_by`` chains, so this needs
the default phi-preserving, def-use-intact SSA. On a mutated IR a real guard
reads as absent and the sink is reported unguarded.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .ssa import (
    Assignment,
    SSAProgram,
    SSAVar,
    const_byte_length,
    is_field_var,
)
from .path_predicates import (
    BranchCondition,
    PathPredicateAnalysis,
)
from .avm import STATE_MUTATING_OPS as _STATE_MUTATING_OPS


# -- pluggable sink and matcher types ---------------------------------------


@dataclass(frozen=True)
class AuthSink:
    """A class of "sensitive" assignment that requires guard domination."""

    name: str
    matches: Callable[[Assignment], bool]


@dataclass(frozen=True)
class AuthMatcher:
    """Recogniser for one auth-guard pattern over a :class:`BranchCondition`."""

    name: str
    matches: Callable[[BranchCondition, SSAProgram], bool]


# -- built-in sinks ---------------------------------------------------------


# Narrow a detector with its own ``sinks`` list, never by editing the shared
# canonical set in ``avm``.
STATE_MUTATION_SINK = AuthSink(
    name="state-mutating op",
    matches=lambda a: a.op in _STATE_MUTATING_OPS,
)


DEFAULT_SINKS: list[AuthSink] = [STATE_MUTATION_SINK]


# -- built-in matchers ------------------------------------------------------


def _is_txn_sender(op) -> bool:
    """True if ``op`` is the SSAVar produced by ``txn Sender``."""
    return is_field_var(op, "txn", "Sender")


def _is_addr_const(op) -> bool:
    """True if ``op`` is a 32-byte address-shaped constant.

    HAZARD: an Algorand address is exactly 32 bytes, so ``txn Sender == "admin"``
    can never hold — accepting a shorter/longer literal would read a vacuous
    comparison as a real guard."""
    return const_byte_length(op) == 32


def _matches_sender_eq_const(cond: BranchCondition, prog: SSAProgram) -> bool:
    """Pattern: ``(txn Sender) == <bytes-const>`` checked truthy (kind ``nonzero``).

    Under-approximates: ``!=`` checks and hash-mediated equality aren't matched,
    so such a guard reads as absent — errs toward reporting, never toward clean.
    """
    if cond.kind != "nonzero":
        return False
    v = cond.value
    if not isinstance(v, SSAVar) or v.defined_by is None:
        return False
    a = v.defined_by
    if a.op != "==":
        return False
    if len(a.inputs) != 2:
        return False
    a0, a1 = a.inputs
    return (
        (_is_txn_sender(a0) and _is_addr_const(a1))
        or
        (_is_txn_sender(a1) and _is_addr_const(a0))
    )


SENDER_EQ_CONST_MATCHER = AuthMatcher(
    name="txn Sender == <const>",
    matches=_matches_sender_eq_const,
)


DEFAULT_MATCHERS: list[AuthMatcher] = [SENDER_EQ_CONST_MATCHER]


# -- violation + detector ---------------------------------------------------


@dataclass
class AuthViolation:
    sink: Assignment
    sink_class: str
    # What did hold at the sink, so an analyst sees why it wasn't a guard
    # ("X is checked, but X isn't admin"). Empty when nothing dominates.
    dominating_predicates: list[BranchCondition]

    @property
    def file(self) -> str:
        return self.sink.location.file

    @property
    def line(self) -> int:
        # Structured anchor for machine output.
        return self.sink.location.line

    def pretty(self) -> str:
        body = ", ".join(repr(p) for p in self.dominating_predicates) or "<no guard>"
        return f"{self.sink.op}@{self.sink.location}  ({self.sink_class})  preds: {body}"

    def to_dict(self) -> dict:
        from ._utils.serialize import assignment_ref
        return {
            "sink": {"class": self.sink_class, **assignment_ref(self.sink)},
            "dominating_predicates": [repr(p) for p in self.dominating_predicates],
        }

    def __repr__(self) -> str:
        return f"AuthViolation({self.pretty()})"


class AuthDominationDetector:
    """Flags sensitive assignments no matcher-recognised guard dominates."""

    def __init__(
        self,
        prog: SSAProgram,
        *,
        sinks: Optional[Iterable[AuthSink]] = None,
        matchers: Optional[Iterable[AuthMatcher]] = None,
        path_predicates: Optional[PathPredicateAnalysis] = None,
    ):
        self.prog = prog
        self.sinks: list[AuthSink] = (
            list(sinks) if sinks is not None else list(DEFAULT_SINKS)
        )
        self.matchers: list[AuthMatcher] = (
            list(matchers) if matchers is not None else list(DEFAULT_MATCHERS)
        )
        self.path_predicates = path_predicates or PathPredicateAnalysis(prog)

    def detect(self) -> list[AuthViolation]:
        violations: list[AuthViolation] = []
        for a in self.prog.assignments:
            sink = self._classify_sink(a)
            if sink is None:
                continue
            preds = self.path_predicates.predicates_at(
                file=a.location.file, line=a.location.line
            )
            if any(self._matches_any(p) for p in preds):
                continue
            violations.append(AuthViolation(
                sink=a, sink_class=sink.name,
                dominating_predicates=sorted(
                    preds, key=lambda c: (c.kind, repr(c.value)),
                ),
            ))
        return violations

    # -- internals ------------------------------------------------------

    def _classify_sink(self, a: Assignment) -> Optional[AuthSink]:
        for sink in self.sinks:
            if sink.matches(a):
                return sink
        return None

    def _matches_any(self, cond: BranchCondition) -> bool:
        return any(m.matches(cond, self.prog) for m in self.matchers)
