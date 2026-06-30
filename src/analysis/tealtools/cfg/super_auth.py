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

Both halves read guards out of :class:`PathPredicateAnalysis`, so ``assert``-
*and* branch-form (``bnz`` / ``bz``) guards are recognised uniformly (the same
machinery the single-program :class:`AuthDominationDetector` uses) — the
super-CFG only contributes the cross-contract dominance. Context-insensitive,
inheriting the super-CFG's call/return-mismatch over-approximation (documented
on :class:`SuperCFG`) — sound for this "is it guarded on every path" question.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..auth_domination import AuthMatcher, DEFAULT_MATCHERS
from ..opsets import STATE_MUTATING_OPS
from ..path_predicates import BranchCondition, PathPredicateAnalysis
from ..ssa import Assignment, SSAVar, is_field_var
from .supercfg import SuperBlock, SuperCFG


@dataclass(frozen=True)
class CallerGuardBypassFinding:
    """A callee sink that a caller-side guard super-dominates, but which the
    callee does not protect with a ``CallerApplicationID`` check — so the guard
    is bypassable by invoking the callee directly."""

    app_id: int                       # the callee the sink lives in
    sink: Assignment
    sink_class: str
    guard_app_id: Optional[int]       # contract whose guard (falsely) appears to gate it
    guard_site: tuple[str, int]       # (file, line) of the gating call site
    guard_predicates: tuple[BranchCondition, ...]  # the auth preds holding there

    def pretty(self) -> str:
        g = "root" if self.guard_app_id is None else f"app{self.guard_app_id}"
        gf, gl = self.guard_site
        preds = ", ".join(repr(p) for p in self.guard_predicates)
        return (
            f"app{self.app_id}: {self.sink.op}@{self.sink.location} ({self.sink_class}) "
            f"is gated only by {g}'s guard at the call site {gf}:{gl} [{preds}] — callee "
            f"does not check CallerApplicationID, so the guard is bypassable by a direct call"
        )

    def to_dict(self) -> dict:
        from .._utils.serialize import assignment_ref
        return {
            "app_id": self.app_id,
            "sink": {"class": self.sink_class, **assignment_ref(self.sink)},
            "guard_app_id": self.guard_app_id,
            "guard_site": {"file": self.guard_site[0], "line": self.guard_site[1]},
            "guard_predicates": [repr(p) for p in self.guard_predicates],
        }


# Sensitive callee sinks worth protecting (value movement / state). The SET is
# the canonical STATE_MUTATING_OPS (so we don't silently drop box_replace /
# box_splice / box_resize as a hand-rolled list once did); the values are just
# display labels, with the op name as a fallback.
_SINK_LABELS: dict[str, str] = {
    "itxn_submit": "inner transaction",
    "app_global_put": "global-state write",
    "app_global_del": "global-state delete",
    "app_local_put": "local-state write",
    "app_local_del": "local-state delete",
    "box_put": "box write",
    "box_create": "box write",
    "box_replace": "box write",
    "box_splice": "box write",
    "box_resize": "box write",
    "box_del": "box delete",
}
_SINKS: dict[str, str] = {op: _SINK_LABELS.get(op, op) for op in STATE_MUTATING_OPS}


def _is_caller_app_id(op: object) -> bool:
    return is_field_var(op, "global", "CallerApplicationID")


def _pred_pins_caller(p: BranchCondition) -> bool:
    """True if predicate ``p`` constrains ``global CallerApplicationID`` —
    e.g. ``assert(CallerApplicationID)`` (bare ``nonzero`` over the global) or
    a decomposed ``CallerApplicationID ==/!= x``. Works for assert- and
    branch-form pins alike, since both surface as such a predicate."""
    if _is_caller_app_id(p.value):
        return True
    if isinstance(p.value, SSAVar) and p.value.defined_by is not None:
        a = p.value.defined_by
        if a.op in ("==", "!=") and len(a.inputs) == 2:
            return any(_is_caller_app_id(i) for i in a.inputs)
    return False


def caller_guard_bypass_findings(
    sc: SuperCFG,
    *,
    matchers: Optional[Iterable[AuthMatcher]] = None,
) -> list[CallerGuardBypassFinding]:
    """Flag callee sinks gated only by a caller-side auth guard, with no
    ``CallerApplicationID`` check inside the callee — bypassable by a direct
    call. ``matchers`` default to :data:`auth_domination.DEFAULT_MATCHERS`."""
    match_list = list(matchers) if matchers is not None else list(DEFAULT_MATCHERS)

    _ppa: dict[Optional[int], PathPredicateAnalysis] = {}

    def ppa(app_id: Optional[int]) -> PathPredicateAnalysis:
        if app_id not in _ppa:
            _ppa[app_id] = PathPredicateAnalysis(sc.cfgs[app_id].prog)
        return _ppa[app_id]

    # 1. Guard super-blocks: a call site (submit BB) whose appcall is auth-gated
    #    in its caller — an auth predicate holds at the submit line. Recognises
    #    assert- and bnz-form guards uniformly (predicates come from PPA).
    guard_blocks: dict[SuperBlock, tuple[BranchCondition, ...]] = {}
    for e in sc.inter_edges:
        if e.kind != "call":
            continue
        caller_id = e.src.app_id
        prog = sc.cfgs[caller_id].prog
        preds = ppa(caller_id).predicates_at(e.site.file, e.site.submit_line)
        matched = tuple(p for p in preds if any(m.matches(p, prog) for m in match_list))
        if matched:
            guard_blocks[e.src] = matched

    # 2. Each sensitive callee sink: cross-guarded iff a guard super-block in
    #    ANOTHER contract super-dominates it; flagged unless the callee pins its
    #    caller (a CallerApplicationID predicate holds at the sink).
    findings: list[CallerGuardBypassFinding] = []
    for app_id, cfg in sc.cfgs.items():
        if app_id is None:
            continue  # only callees can be invoked directly to bypass a caller
        callee_ppa = ppa(app_id)
        for a in cfg.prog.assignments:
            cls = _SINKS.get(a.op)
            if cls is None:
                continue
            bb = cfg.prog.block_containing(a.location.file, a.location.line)
            if bb is None:
                continue
            sb = SuperBlock(app_id, bb)
            doms = sc.dominators(sb)
            cross = next(
                ((g, guard_blocks[g]) for g in doms
                 if g in guard_blocks and g.app_id != app_id),
                None,
            )
            if cross is None:
                continue  # not relying on a cross-contract guard; out of scope
            # Pinned? A CallerApplicationID predicate holds on every path to the
            # sink inside the callee (assert- or branch-form).
            sink_preds = callee_ppa.predicates_at(a.location.file, a.location.line)
            if any(_pred_pins_caller(p) for p in sink_preds):
                continue
            guard_sb, guard_preds = cross
            findings.append(CallerGuardBypassFinding(
                app_id=app_id, sink=a, sink_class=cls,
                guard_app_id=guard_sb.app_id,
                guard_site=(guard_sb.bb.file, guard_sb.bb.last_line),
                guard_predicates=guard_preds,
            ))
    findings.sort(key=lambda f: (f.app_id, f.sink.location.file, f.sink.location.line))
    return findings
