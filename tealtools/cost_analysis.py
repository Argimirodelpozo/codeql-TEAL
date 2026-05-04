"""Per-line and per-path opcode cost analysis for TEAL programs.

For each line in a program, computes:

- ``op_cost``: the AVM opcode-budget cost of the single instruction.
- ``cumulative``: the *worst-case* cumulative cost from program entry
  to that line, taken as the max across all paths that reach it.

Loops show up as ``"unbounded"``. A BB is considered to be in a
loop when it can reach itself via the CFG; any BB in a loop, or
reachable from one, gets ``unbounded`` for cumulative cost.

Cost table is intentionally partial — well-known expensive ops
(crypto verifies, hashes, EC) are listed; everything else defaults
to 1, which is correct for the vast majority of TEAL opcodes.
Extend :data:`OPCODE_COSTS` for ops you care about that aren't
already there.

Limitations:

- ``callsub`` is counted as a single opcode (cost 1). The called
  subroutine's body is its own BBs and is accounted for via the
  CFG edges if those edges exist; if the SSA layer doesn't connect
  call sites to subroutine entries, subroutine costs aren't
  amortised onto the caller. Worth re-checking on a real fixture.
- Loops are treated as ``unbounded``. There's no bounded-loop
  analysis here — that would need induction-variable / iteration-
  count inference.
- Box / state ops are charged 1 each. The AVM actually scales box
  costs with size; for accurate budget accounting on box-heavy
  contracts, refine the table.
"""
from __future__ import annotations

from typing import Optional, Union

from .ssa import BasicBlock, SSAProgram


# Crypto / EC / hash ops with non-default costs. TEAL v10.
OPCODE_COSTS: dict[str, int] = {
    "sha256": 35,
    "keccak256": 130,
    "sha512_256": 45,
    "sha3_256": 130,
    "ed25519verify": 1900,
    "ed25519verify_bare": 1900,
    "ecdsa_verify": 1700,
    "ecdsa_pk_decompress": 650,
    "ecdsa_pk_recover": 2000,
    "vrf_verify": 5700,
    "ec_add": 13,
    "ec_scalar_mul": 970,
    "ec_pairing_check": 8700,
    "ec_multi_scalar_mul": 970,
    "ec_subgroup_check": 1850,
    "ec_map_to": 2300,
    "expw": 10,
    "bsqrt": 40,
    "divw": 4,
}
DEFAULT_COST = 1

UNBOUNDED = "unbounded"
Cost = Union[int, str]  # int or "unbounded"


def opcode_cost(op: str) -> int:
    """AVM opcode-budget cost for ``op``. Defaults to 1 for unknown
    opcodes (correct for the bulk of TEAL ops)."""
    return OPCODE_COSTS.get(op, DEFAULT_COST)


def bb_cost(bb: BasicBlock) -> int:
    """Sum of opcode costs for every assignment in ``bb``."""
    return sum(opcode_cost(a.op) for a in bb.assignments)


def _bb_on_cycle(prog: SSAProgram) -> set[BasicBlock]:
    """BBs that are part of a CFG cycle (can reach themselves).

    Quadratic in the number of BBs but TEAL programs are tiny — a
    proper Tarjan-SCC pass is overkill at this scale.
    """
    on_cycle: set[BasicBlock] = set()
    for start in prog.blocks.values():
        stack = list(start.successors)
        seen: set[int] = set()
        while stack:
            bb = stack.pop()
            if bb is start:
                on_cycle.add(start)
                break
            if id(bb) in seen:
                continue
            seen.add(id(bb))
            stack.extend(bb.successors)
    return on_cycle


def _unbounded_set(prog: SSAProgram) -> set[BasicBlock]:
    """BBs whose cumulative cost is unbounded — in a cycle or
    reachable from one."""
    on_cycle = _bb_on_cycle(prog)
    if not on_cycle:
        return set()
    result = set(on_cycle)
    stack = list(on_cycle)
    seen = {id(bb) for bb in stack}
    while stack:
        bb = stack.pop()
        for s in bb.successors:
            if id(s) in seen:
                continue
            seen.add(id(s))
            result.add(s)
            stack.append(s)
    return result


def bb_entry_costs(prog: SSAProgram) -> dict[BasicBlock, Cost]:
    """Max cumulative cost from program entry to the *start* of each
    BB. Returns ``"unbounded"`` for BBs in or reachable from a loop.
    """
    unbounded = _unbounded_set(prog)
    cost: dict[BasicBlock, Cost] = {}
    for bb in prog.blocks.values():
        if bb in unbounded:
            cost[bb] = UNBOUNDED
        elif not bb.predecessors:
            cost[bb] = 0
        else:
            cost[bb] = -1  # sentinel: not yet computed

    changed = True
    while changed:
        changed = False
        for bb in prog.blocks.values():
            if cost[bb] == UNBOUNDED:
                continue
            if not bb.predecessors:
                continue
            preds_done = all(cost[p] != -1 for p in bb.predecessors)
            if not preds_done:
                continue
            best = -1
            saw_unbounded = False
            for p in bb.predecessors:
                pc = cost[p]
                if pc == UNBOUNDED:
                    saw_unbounded = True
                    break
                assert isinstance(pc, int)
                candidate = pc + bb_cost(p)
                if candidate > best:
                    best = candidate
            new_cost: Cost = UNBOUNDED if saw_unbounded else best
            if cost[bb] != new_cost:
                cost[bb] = new_cost
                changed = True
    # Replace any leftover sentinel with 0 (unreachable BBs default to 0).
    for bb, c in list(cost.items()):
        if c == -1:
            cost[bb] = 0
    return cost


def per_line_costs(prog: SSAProgram) -> dict[tuple[str, int], tuple[str, int, Cost]]:
    """Per-line ``(op_name, op_cost, cumulative)`` map.

    Key is ``(file, line)``. ``cumulative`` is the worst-case sum of
    opcode costs from entry up to and including this line.
    """
    entry = bb_entry_costs(prog)
    out: dict[tuple[str, int], tuple[str, int, Cost]] = {}
    for bb in prog.blocks.values():
        running = entry[bb]
        for a in bb.assignments:
            oc = opcode_cost(a.op)
            if running == UNBOUNDED:
                cum: Cost = UNBOUNDED
            else:
                assert isinstance(running, int)
                running = running + oc
                cum = running
            out[(a.location.file, a.location.line)] = (a.op, oc, cum)
    return out


def render(prog: SSAProgram) -> str:
    """Per-line cost table, sorted by (file, line)."""
    lines = per_line_costs(prog)
    if not lines:
        return "(no instructions)"
    out: list[str] = []
    op_w = max(len(op) for op, _, _ in lines.values())
    for (f, ln), (op, oc, cum) in sorted(lines.items()):
        cum_str = str(cum)
        out.append(
            f"{f}:L{ln:<3}  {op.ljust(op_w)}  op_cost={oc:<4}  cum={cum_str}"
        )
    return "\n".join(out)
