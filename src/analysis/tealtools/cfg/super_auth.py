"""Caller-guard-bypass detector — a worked example of a detector that *consumes*
the cross-contract super-CFG (:class:`tealtools.cfg.SuperCFG`), and a sound use
of interprocedural super-dominance.

The naive idea "a caller's ``txn Sender == ADMIN`` guard that dominates an
appcall also protects the callee's sink" is UNSOUND, for two reasons that both
come down to the inner-transaction boundary:

1. ``txn Sender`` inside the callee is the *caller application's address*, not
   the human admin — sender-auth doesn't compose across an inner txn.
2. The super-CFG models only the calls the caller *makes*. A deployed callee is
   independently invocable: an attacker can call it DIRECTLY, bypassing the
   caller and its guard entirely. Super-dominance in the modelled graph says
   "guarded"; reality says "bypassable".

That gap is the bug. A caller-side guard over an appcall is only real if the
callee restricts WHO may call it — and the primitive that *is* well-defined at
the inner boundary is ``global CallerApplicationID`` (the immediate calling
app). So the finding is:

    a callee sink is super-dominated by a caller-side auth guard (the caller
    intends to gate it), but no ``CallerApplicationID`` check dominates the sink
    inside the callee  ⇒  the guard is bypassable by calling the callee directly
    ⇒  privilege escalation.

This is exactly where the super-CFG earns its keep: the "caller guard dominates
the callee sink" half is interprocedural super-dominance across the appcall
boundary; the "callee pins its caller" half is ordinary intra-program dominance.
Recognises ``assert``-form guards (the dominant pattern); branch-form guards are
a straightforward extension via :class:`PathPredicateAnalysis`.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional

from ..auth_domination import AuthMatcher, DEFAULT_MATCHERS
from ..path_predicates import BranchCondition
from ..ssa import Assignment, BasicBlock, SSAProgram, SSAVar
from .supercfg import SuperBlock, SuperCFG


@dataclass(frozen=True)
class CallerGuardBypassFinding:
    """A callee sink that a caller-side guard super-dominates, but which the
    callee does not protect with a ``CallerApplicationID`` check — so the guard
    is bypassable by invoking the callee directly."""

    app_id: int                 # the callee the sink lives in
    sink: Assignment
    sink_class: str
    guard_app_id: Optional[int]  # contract whose guard (falsely) appears to gate it
    guard: Assignment            # the caller-side auth assert

    def pretty(self) -> str:
        loc = self.sink.location
        g = "root" if self.guard_app_id is None else f"app{self.guard_app_id}"
        gloc = self.guard.location
        return (
            f"app{self.app_id}: {self.sink.op}@{loc.file}:{loc.line} ({self.sink_class}) "
            f"is gated only by {g}'s guard @{gloc.file}:{gloc.line} — callee does not "
            f"check CallerApplicationID, so the guard is bypassable by a direct call"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref
        return {
            "app_id": self.app_id,
            "sink": {"class": self.sink_class, **assignment_ref(self.sink)},
            "guard_app_id": self.guard_app_id,
            "guard": assignment_ref(self.guard),
        }


# Sensitive callee sinks worth protecting (value movement / state). Reuses the
# spirit of auth_domination's sinks but narrowed to what a bypass actually buys
# an attacker in a callee.
_SINKS: dict[str, str] = {
    "itxn_submit": "inner transaction",
    "app_global_put": "global-state write",
    "app_global_del": "global-state delete",
    "app_local_put": "local-state write",
    "app_local_del": "local-state delete",
    "box_put": "box write",
    "box_create": "box write",
    "box_del": "box delete",
}


def _asserted_conditions(bb: BasicBlock) -> Iterator[object]:
    """The condition operand of each ``assert`` in ``bb`` (assert ends a BB, so
    such a guard dominates the block's whole successor region)."""
    for a in bb.assignments:
        if a.op == "assert" and a.inputs:
            yield a.inputs[0]


def _guard_assert(bb: BasicBlock, prog: SSAProgram, matchers: list[AuthMatcher]) -> Optional[Assignment]:
    """The ``assert`` assignment in ``bb`` whose condition matches an auth
    matcher (``txn Sender == <const>``), or ``None``."""
    for a in bb.assignments:
        if a.op != "assert" or not a.inputs:
            continue
        cond = BranchCondition(value=a.inputs[0], kind="nonzero", args=())
        if any(m.matches(cond, prog) for m in matchers):
            return a
    return None


def _is_caller_app_id(op: object) -> bool:
    return (
        isinstance(op, SSAVar)
        and op.defined_by is not None
        and op.defined_by.op == "global"
        and op.defined_by.immediates.strip() == "CallerApplicationID"
    )


def _pins_caller(cond: object) -> bool:
    """True if asserting ``cond`` constrains ``global CallerApplicationID`` —
    either ``assert(CallerApplicationID)`` (called by *some* app, != 0) or
    ``CallerApplicationID ==/!= x``."""
    if _is_caller_app_id(cond):
        return True
    if isinstance(cond, SSAVar) and cond.defined_by is not None:
        a = cond.defined_by
        if a.op in ("==", "!=") and len(a.inputs) == 2:
            return any(_is_caller_app_id(i) for i in a.inputs)
    return False


def _bb_pins_caller(bb: BasicBlock) -> bool:
    return any(_pins_caller(c) for c in _asserted_conditions(bb))


def caller_guard_bypass_findings(
    sc: SuperCFG,
    *,
    matchers: Optional[Iterable[AuthMatcher]] = None,
) -> list[CallerGuardBypassFinding]:
    """Flag callee sinks gated only by a caller-side auth guard, with no
    ``CallerApplicationID`` check inside the callee — bypassable by a direct
    call. ``matchers`` default to :data:`auth_domination.DEFAULT_MATCHERS`."""
    match_list = list(matchers) if matchers is not None else list(DEFAULT_MATCHERS)

    # Auth-guard super-blocks (txn Sender == const asserts) keyed for lookup,
    # plus caller-pin (CallerApplicationID) super-blocks, across every contract.
    guard_assert: dict[SuperBlock, Assignment] = {}
    pin_blocks: set[SuperBlock] = set()
    for app_id, cfg in sc.cfgs.items():
        for bb in cfg.blocks:
            ga = _guard_assert(bb, cfg.prog, match_list)
            if ga is not None:
                guard_assert[SuperBlock(app_id, bb)] = ga
            if _bb_pins_caller(bb):
                pin_blocks.add(SuperBlock(app_id, bb))

    findings: list[CallerGuardBypassFinding] = []
    for app_id, cfg in sc.cfgs.items():
        if app_id is None:
            continue  # only callees can be invoked directly to bypass a caller
        for a in cfg.prog.assignments:
            cls = _SINKS.get(a.op)
            if cls is None:
                continue
            bb = cfg.prog.block_containing(a.location.file, a.location.line)
            if bb is None:
                continue
            sb = SuperBlock(app_id, bb)
            doms = sc.dominators(sb)
            # A guard in ANOTHER contract that super-dominates this sink = the
            # caller's intended gate.
            cross_guard = next(
                ((g.app_id, guard_assert[g]) for g in doms
                 if g in guard_assert and g.app_id != app_id),
                None,
            )
            if cross_guard is None:
                continue  # not relying on a cross-contract guard; out of scope
            # Sound iff the callee pins its caller (CallerApplicationID) on every
            # path to the sink — i.e. a pin super-block (same contract) dominates.
            if any(p.app_id == app_id and p in doms for p in pin_blocks):
                continue
            guard_app_id, guard = cross_guard
            findings.append(CallerGuardBypassFinding(
                app_id=app_id, sink=a, sink_class=cls,
                guard_app_id=guard_app_id, guard=guard,
            ))
    findings.sort(key=lambda f: (f.app_id, f.sink.location.file, f.sink.location.line))
    return findings


def render_caller_guard_bypass(findings: list[CallerGuardBypassFinding]) -> str:
    if not findings:
        return "(no caller-guard-bypass findings)"
    return "\n".join(f.pretty() for f in findings)
