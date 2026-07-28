"""Caller-guard-bypass detector over the cross-contract :class:`SuperCFG`: a
callee sink super-dominated by a caller-side auth guard, with no
``CallerApplicationID`` check inside the callee ⇒ privilege escalation.

HAZARD: a caller-side guard that super-dominates a callee sink does NOT protect
it. The super-CFG models only the calls the caller MAKES, while a deployed callee
is independently invocable — an attacker calls it directly, bypassing the guard;
and ``txn Sender`` inside the callee is the caller APP's address, not the human
admin (sender-auth does not compose across an inner txn). Only the callee's own
``global CallerApplicationID`` check is well-defined at that boundary, so its
absence is the finding.

Guards come from :class:`PathPredicateAnalysis`, so ``assert``- and branch-form
(``bnz`` / ``bz``) guards count alike. Context-insensitive, inheriting the
super-CFG's call/return over-approximation — sound for "guarded on every path".
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from ..auth_domination import AuthMatcher, DEFAULT_MATCHERS
from ..avm import STATE_MUTATING_OPS
from ..path_predicates import BranchCondition, PathPredicateAnalysis
from ..ssa import Assignment, SSAVar, is_field_var
from .supercfg import SuperBlock, SuperCFG


@dataclass(frozen=True)
class CallerGuardBypassFinding:
    """A callee sink super-dominated by a caller-side guard but unprotected by a
    ``CallerApplicationID`` check — bypassable by invoking the callee directly."""

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


# Display labels only — the sink SET is the canonical STATE_MUTATING_OPS, so a
# newly-added state op is never silently dropped. Op name is the fallback label.
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
    """True if ``p`` constrains ``global CallerApplicationID`` — a bare nonzero
    over the global, or a decomposed ``==``/``!=`` against it."""
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
    """Flag callee sinks gated only by a caller-side auth guard; ``matchers``
    default to :data:`auth_domination.DEFAULT_MATCHERS`."""
    match_list = list(matchers) if matchers is not None else list(DEFAULT_MATCHERS)

    _ppa: dict[Optional[int], PathPredicateAnalysis] = {}

    def ppa(app_id: Optional[int]) -> PathPredicateAnalysis:
        if app_id not in _ppa:
            _ppa[app_id] = PathPredicateAnalysis(sc.cfgs[app_id].prog)
        return _ppa[app_id]

    # 1. Guard super-blocks: call sites (submit BBs) where an auth predicate
    #    holds at the submit line in the caller.
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
    #    caller.
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
            # Pinned: a CallerApplicationID predicate holds on every path to the
            # sink inside the callee.
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
