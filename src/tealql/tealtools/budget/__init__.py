"""Execution-COST analyses: what a program spends, and what that bounds.

The AVM meters execution — an application call gets :data:`APP_OPCODE_BUDGET`
opcode budget (pooled across the group) and dies past :data:`MAX_STACK_DEPTH`
stack. Nothing else in the toolkit models that, which leaves a class of
questions unaskable: is a sink even reachable inside the budget, can an attacker
spin a loop until the program dies, does a path need more than one transaction's
budget to finish. Per-op costs come from puya's langspec, the same source the
metadata drift tests already pin.

HAZARD: everything here yields UPPER BOUNDS on what the AVM PERMITS, never
predictions. A loop bounded at 700 iterations usually runs three times. Reading
a bound as a trip count invents facts about the program.

Unlike :mod:`..cfg`, this package sits wholly ABOVE ``ssa`` — every module here
consumes a built ``SSAProgram`` — so the re-exports below are eager; there is no
tier to keep apart.
"""
from .loop_bounds import (  # noqa: F401
    APP_OPCODE_BUDGET,
    MAX_STACK_DEPTH,
    LoopBound,
    analyze_loops,
    block_cost,
    block_stack_delta,
    op_cost,
    render,
)

__all__ = [
    "APP_OPCODE_BUDGET",
    "MAX_STACK_DEPTH",
    "LoopBound",
    "analyze_loops",
    "block_cost",
    "block_stack_delta",
    "op_cost",
    "render",
]
