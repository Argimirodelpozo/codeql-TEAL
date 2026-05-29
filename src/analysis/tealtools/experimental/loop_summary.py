"""Per-loop static summary.

For each :class:`LoopR` in the program, computes:

- ``body_cost``: total per-iteration opcode cost (sum of body BBs'
  op costs, with nested loops contributing their max-iter
  contribution).
- ``submits_per_iter``: inner-txn submissions per iteration.
- ``max_iters_budget``: how many iterations the AVM opcode budget
  allows, assuming a fresh ``(0, 0)`` entry state.
- ``max_iters_inner_cap``: how many iterations the 256-inner-txn
  protocol cap allows (``∞`` if the loop emits no submits).
- ``binding_cap``: whichever cap binds first — useful for "why does
  this loop terminate from the AVM's perspective?".
- ``location``: the loop header's ``(file, line)``.

A flat list of these is much easier to skim than the full control
tree when reviewing a contract for DoS / iteration risk.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..control_tree import LoopR, build_control_tree
from ..cost_analysis import (
    _body_summary, _max_iters_full, ASSUMED_GROUP_SIZE, MAX_INNER_TXNS,
)
from ..ssa import SSAProgram


@dataclass
class LoopReport:
    file: str
    line: int
    body_cost: int
    submits_per_iter: int
    max_iters_budget: Optional[int]
    max_iters_inner_cap: Optional[int]
    binding_cap: str
    body_bb_count: int
    is_reducible: bool

    def pretty(self) -> str:
        return (
            f"{self.file}:L{self.line}  body={self.body_cost}, "
            f"submits/iter={self.submits_per_iter}, "
            f"max_iters={self._effective_max():>6}  "
            f"({self.binding_cap}, {self.body_bb_count} BBs, "
            f"reducible={self.is_reducible})"
        )

    def _effective_max(self) -> int:
        caps = [c for c in (self.max_iters_budget, self.max_iters_inner_cap) if c is not None]
        return min(caps) if caps else MAX_INNER_TXNS


def analyze(prog: SSAProgram, group_size: int = ASSUMED_GROUP_SIZE) -> list[LoopReport]:
    """Returns one :class:`LoopReport` per :class:`LoopR` in the tree."""
    tree = build_control_tree(prog)
    reports: list[LoopReport] = []
    for region in tree.walk():
        if not isinstance(region, LoopR):
            continue
        body_cost, submits_per_iter = _body_summary(region.body)
        # Budget bound (fresh-entry assumption — most permissive).
        budget_iters = _max_iters_full(
            0, 0, body_cost, submits_per_iter, group_size
        ) if body_cost > 0 else MAX_INNER_TXNS
        # Inner-cap bound.
        inner_iters: Optional[int]
        if submits_per_iter > 0:
            inner_iters = MAX_INNER_TXNS // submits_per_iter
        else:
            inner_iters = None  # no cap from this constraint
        if inner_iters is None:
            binding = "budget"
        elif inner_iters < budget_iters:
            binding = "inner-cap"
        elif budget_iters < inner_iters:
            binding = "budget"
        else:
            binding = "tie"
        first_bb = next(iter(region.loop.nodes))
        if first_bb.assignments:
            loc = first_bb.assignments[0].location
            f, ln = loc.file, loc.line
        else:
            f, ln = "?", 0
        reports.append(LoopReport(
            file=f, line=ln,
            body_cost=body_cost,
            submits_per_iter=submits_per_iter,
            max_iters_budget=budget_iters,
            max_iters_inner_cap=inner_iters,
            binding_cap=binding,
            body_bb_count=len(region.loop.nodes),
            is_reducible=region.loop.is_reducible(),
        ))
    return sorted(reports, key=lambda r: (r.file, r.line))


def render(prog: SSAProgram) -> str:
    reports = analyze(prog)
    if not reports:
        return "(no loops)"
    header = "Loop report:"
    lines = [header] + [f"  {r.pretty()}" for r in reports]
    return "\n".join(lines)
