"""Auth-dominates-sink detector.

For each "sensitive" sink in a TEAL program (state mutations, inner
transactions, …), checks that *some* auth-shaped predicate
dominates it via :class:`tealtools.path_predicates.PathPredicateAnalysis`.
Sinks reachable along a path that lacks the auth predicate get
flagged.

    from tealtools.ssa import SSAProgram
    from tealtools.auth_domination import (
        AuthDominationDetector,
        DEFAULT_SINKS, DEFAULT_MATCHERS,
    )

    prog = SSAProgram("path/to/contract.teal")
    prog.propagate_constants()
    for v in AuthDominationDetector(prog).detect():
        print(v.pretty())

Pluggable
---------

- :class:`AuthSink` — predicate that picks out which assignments
  count as "sensitive" (default: state-mutating ops).
- :class:`AuthMatcher` — recogniser for a guard pattern over a
  :class:`tealtools.path_predicates.BranchCondition` (default: ``txn
  Sender == <const>`` style admin checks).

A sink is *not* flagged if at least one path-predicate at the
sink's BB matches at least one matcher. Adding new sink families
or guard patterns is a matter of appending to ``sinks`` /
``matchers`` — no detector internals need to change.

Preconditions
-------------

Path predicates trace back through ``defined_by`` chains, so this needs the
standard (phi-preserving, def-use-intact) SSA representation that
:class:`tealtools.ssa.SSAProgram` produces by default — the same as
:class:`tealtools.inner_txn_report.InnerTxnReport`.
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
from .opsets import STATE_MUTATING_OPS as _STATE_MUTATING_OPS


# ---------------------------------------------------------------------------
# Pluggable sink and matcher types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthSink:
    """A class of "sensitive" assignment that requires guard domination."""

    name: str
    matches: Callable[[Assignment], bool]


@dataclass(frozen=True)
class AuthMatcher:
    """Recogniser for a guard pattern.

    ``matches(cond, prog)`` returns True if ``cond`` (a single
    :class:`BranchCondition`) represents the kind of auth-shaped
    check the matcher is looking for. The intent is "cheap pattern
    matching against the SSA shape" — anything more involved
    (range reasoning, value-flow) lives in the consumer.
    """

    name: str
    matches: Callable[[BranchCondition, SSAProgram], bool]


# ---------------------------------------------------------------------------
# Built-in sinks
# ---------------------------------------------------------------------------


# State-mutating opcodes that should typically only run on a guard-dominated
# path — the canonical set (``tealtools.opsets.STATE_MUTATING_OPS``, imported
# above). Restrict a detector by passing a narrower ``sinks`` list, not by
# editing the shared set.
STATE_MUTATION_SINK = AuthSink(
    name="state-mutating op",
    matches=lambda a: a.op in _STATE_MUTATING_OPS,
)


DEFAULT_SINKS: list[AuthSink] = [STATE_MUTATION_SINK]


# ---------------------------------------------------------------------------
# Built-in matchers
# ---------------------------------------------------------------------------


def _is_txn_sender(op) -> bool:
    """True if ``op`` is the SSAVar produced by ``txn Sender``."""
    return is_field_var(op, "txn", "Sender")


def _is_addr_const(op) -> bool:
    """True if ``op`` is a 32-byte address-shaped constant. An Algorand address
    is exactly 32 bytes, so a sender check against a shorter/longer bytes literal
    (e.g. ``txn Sender == "admin"``) can never hold and is NOT a real guard —
    requiring 32 bytes rejects those vacuous comparisons."""
    return const_byte_length(op) == 32


def _matches_sender_eq_const(cond: BranchCondition, prog: SSAProgram) -> bool:
    """Pattern: ``(txn Sender) == <bytes-const>`` checked truthy.

    Triggered on a :class:`BranchCondition` of kind ``"nonzero"``
    whose ``value`` is an SSAVar produced by an ``==`` op consuming
    one ``txn Sender`` and one bytes constant. Covers the canonical
    admin-address check shape:

        txn Sender
        addr ADMIN
        ==
        assert       (or: bnz l_admin / b...)

    Doesn't catch ``!=`` checks or pseudo-equality through hashes —
    those are separate matchers worth adding later.
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


# ---------------------------------------------------------------------------
# Violation + detector
# ---------------------------------------------------------------------------


@dataclass
class AuthViolation:
    sink: Assignment
    sink_class: str
    # Path predicates that hold at the sink, for the analyst to see
    # *what* dominated it (frequently helpful — "well, X is checked,
    # but X isn't admin"). Empty list when nothing dominates.
    dominating_predicates: list[BranchCondition]

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
    """Flags sensitive assignments that aren't dominated by any
    matcher-recognised guard.

    Construction takes ``sinks`` and ``matchers`` lists; both default
    to the module's ``DEFAULT_*`` lists. Pass custom lists to extend
    or restrict the analysis.
    """

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
