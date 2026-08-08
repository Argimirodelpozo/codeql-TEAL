"""Execution-COST analyses: what a program spends, and what that bounds.

The AVM meters execution, by TWO non-interchangeable models. An application call
draws on a POOLED opcode budget (:data:`MAX_POOLED_OPCODE_BUDGET` — every app
call in the group contributes, and so does every inner app call they spawn); a
logic signature has its own total-cost limit instead
(:data:`MAX_POOLED_LOGICSIG_COST`). Either dies past :data:`MAX_STACK_DEPTH`
stack. Nothing else in the toolkit models any of this, which leaves a class of
questions unaskable: is a sink even reachable inside the budget, can an attacker
spin a loop until the program dies, does a path need more than one transaction's
budget to finish. Per-op costs come from puya's langspec, the same source the
metadata drift tests already pin.

HAZARD: everything here yields UPPER BOUNDS on what the AVM PERMITS, never
predictions. A loop bounded at thousands of iterations usually runs three times;
the bound says only that the runtime kills it beyond that. Reading a bound as a
trip count invents facts about the program.

HAZARD: the ceilings are deliberately the CONSERVATIVE maxima — a full group of
app calls plus every inner call they could spawn. A contract cannot know its own
group shape at analysis time, and bounding against one transaction's 700 makes
every bound ~272x too tight, which does not merely lose precision: it converts a
bound into a claim the program can violate. Tighten by passing ``budget=`` once
group shape and inner-call count are known.

Unlike :mod:`..cfg`, this package sits wholly ABOVE ``ssa`` — every module here
consumes a built ``SSAProgram`` — so the re-exports below are eager; there is no
tier to keep apart.
"""
from .loop_bounds import (  # noqa: F401
    APP_CALL_OPCODE_BUDGET,
    LOGICSIG_MAX_COST,
    MAX_GROUP_APP_CALLS,
    MAX_GROUP_LOGICSIGS,
    MAX_INNER_APP_CALLS,
    MAX_POOLED_LOGICSIG_COST,
    MAX_POOLED_OPCODE_BUDGET,
    MAX_STACK_DEPTH,
    LoopBound,
    analyze_loops,
    block_cost,
    block_stack_delta,
    default_budget,
    draw,
    op_cost,
    program_mode,
    render,
    to_dot,
)

__all__ = [
    "APP_CALL_OPCODE_BUDGET",
    "LOGICSIG_MAX_COST",
    "MAX_GROUP_APP_CALLS",
    "MAX_GROUP_LOGICSIGS",
    "MAX_INNER_APP_CALLS",
    "MAX_POOLED_LOGICSIG_COST",
    "MAX_POOLED_OPCODE_BUDGET",
    "MAX_STACK_DEPTH",
    "LoopBound",
    "analyze_loops",
    "block_cost",
    "block_stack_delta",
    "default_budget",
    "draw",
    "op_cost",
    "program_mode",
    "render",
    "to_dot",
]
