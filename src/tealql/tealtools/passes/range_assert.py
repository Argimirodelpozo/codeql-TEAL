"""Assert-based range refinement — tighten :class:`IntRange` annotations
using the contract's own ``assert`` guards.

A TEAL ``assert`` halts the program when its operand is 0, so on every path
that *continues past* the assert the asserted condition holds. When that
condition is a comparison ``X op Y`` — or a bare truthiness ``assert(X)``,
i.e. ``X != 0`` — the operand ranges can be tightened: ``assert(x < 100)``
proves ``x ∈ [0, 99]`` downstream; ``assert(amount >= 100000)`` proves the
floor; ``assert(txn.TypeEnum == appl)`` collapses ``[0, 6]`` to ``[1, 1]``.

Soundness is **flow-sensitive**. An ``assert`` constrains its operands only
on the paths it *dominates*; a use of ``x`` reachable *without* passing the
assert is unconstrained. Since :class:`IntRange` is a single per-SSAVar fact
(read at every use), we may tighten ``x`` globally ONLY when every non-test
use of ``x`` is dominated by the assert — otherwise a detector reading the
tightened range on a bypassing path could miss a finding (a false negative).

We approximate dominance by reachability: block ``A`` dominates block ``U``
iff ``U`` is unreachable from the program entry once ``A`` is removed. On the
raw interprocedural CFG (``callsub`` → sub-entry, ``retsub`` → every return
site) this *over*-approximates reachability — spurious return edges only ever
make "U reachable without A" *more* often — so the dominance test is
**conservative**: a refinement is at worst skipped, never applied unsoundly.
A use in the assert's own block counts as dominated only when it is strictly
after the assert in source (== execution) order. (Operands are top-first,
``inputs[1] op inputs[0]`` — see ``reference_ssa_inputs_top_first``.)

Runs in :func:`tealql.tealtools.passes.run_all_passes` as Phase B step 7, right
after :func:`propagate_range_arithmetic` so const / arithmetic bounds exist
before the guards refine them (it lazily trips that pass — hence
``propagate_ranges`` — when called standalone). Iterates to a fixed point so
chained guards (``assert(a < b); assert(b < 100)``) compose. Re-running finds
no further tightening (``_apply`` only ever narrows), so it is idempotent.
"""
from __future__ import annotations

from typing import Optional

from ..ssa import IntRange, SSAProgram, SSAVar
from ..avm import U64_CMP_OPS
from .range_arith import (
    _UINT64_MAX,
    _operand_range,
    _set_range,
    propagate_range_arithmetic,
)

# uint64 comparison ops. ``<`` ``<=`` ``>`` ``>=`` are uint64-only in the AVM
# (bytes use the ``b``-prefixed forms), so they need no type guard; ``==`` /
# ``!=`` are polymorphic and are guarded against bytes operands below.
_CMP = U64_CMP_OPS
# Relation as seen with the *other* operand on the left (X is the right
# operand): rewrite ``Y op X`` as ``X op' Y``.
_SWAP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _all_blocks(prog: SSAProgram) -> set:
    """Every :class:`BasicBlock` reachable through ``predecessors`` /
    ``successors`` from any block that owns an assignment or phi."""
    seed = set()
    for a in prog.assignments:
        if a.basic_block is not None:
            seed.add(a.basic_block)
    for ph in prog.phis.values():
        bb = getattr(ph, "basic_block", None)
        if bb is not None:
            seed.add(bb)
    allb = set(seed)
    stack = list(seed)
    while stack:
        b = stack.pop()
        for nb in (*b.predecessors, *b.successors):
            if nb not in allb:
                allb.add(nb)
                stack.append(nb)
    return allb


def _reachable_avoiding(entries: list, avoid) -> set:
    """Blocks reachable from ``entries`` over CFG ``successors`` *without*
    passing through ``avoid``. A block ``U`` is dominated by ``avoid`` iff
    ``U`` is reachable normally but absent from this set."""
    seen = {e for e in entries if e is not avoid}
    stack = list(seen)
    while stack:
        b = stack.pop()
        for s in b.successors:
            if s is avoid or s in seen:
                continue
            seen.add(s)
            stack.append(s)
    return seen


def _start_range(x: SSAVar) -> Optional[IntRange]:
    """The range to refine *from*: the var's own range, else its const
    singleton, else the full uint64 domain (a bare inequality/truthiness
    guard proves a uint64 operand). ``None`` only for a non-uint64 var with
    no numeric evidence."""
    if x.range is not None:
        return x.range
    r = _operand_range(x)
    if r is not None:
        return r
    if getattr(x.type, "kind", None) in (None, "uint64"):
        return IntRange(0, _UINT64_MAX)
    return None


def _apply(rel: str, x: IntRange, y: IntRange) -> tuple[int, int]:
    """Tighten X's ``(lo, hi)`` under the proven fact ``X rel Y`` (Y the
    other operand's known range). Only ever narrows toward the centre, so
    the result is always ⊆ ``x``."""
    lo, hi = x.lo, x.hi
    if rel == "<":
        hi = min(hi, y.hi - 1)
    elif rel == "<=":
        hi = min(hi, y.hi)
    elif rel == ">":
        lo = max(lo, y.lo + 1)
    elif rel == ">=":
        lo = max(lo, y.lo)
    elif rel == "==":
        lo = max(lo, y.lo)
        hi = min(hi, y.hi)
    elif rel == "!=" and y.lo == y.hi and lo < hi:
        # ``X != c`` only narrows when c sits on a range boundary (an
        # interior hole isn't representable as an interval).
        if y.lo == lo:
            lo += 1
        elif y.hi == hi:
            hi -= 1
    return lo, hi


def propagate_assert_ranges(prog: SSAProgram) -> int:
    """Refine SSAVar / Phi ranges from ``assert`` guards, flow-sensitively.
    Returns the number of ranges newly tightened.

    Lazily trips :func:`propagate_range_arithmetic` first so const and
    arithmetic bounds are in place to refine; iterates to a fixed point so
    guards that depend on one another compose."""
    if not getattr(prog, "_range_arith_propagated", False):
        propagate_range_arithmetic(prog)

    entries = [b for b in _all_blocks(prog) if not b.predecessors]
    if not entries:
        return 0

    # (assert assignment, condition value) for every assert with an operand.
    guards = [(a, a.inputs[0]) for a in prog.assignments
              if a.op == "assert" and a.inputs]
    if not guards:
        return 0

    # Values that flow into a phi. The dominance soundness check below only sees
    # ``x.uses`` (op uses), NOT phi consumers -- and a phi arg comes from a
    # SPECIFIC predecessor edge that may bypass the assert, so tightening such a
    # value globally is unsound. Be conservative: never tighten a phi-fed value.
    phi_fed = {id(arg) for ph in prog.phis.values() for arg in ph.args
               if isinstance(arg, SSAVar)}

    dom_cache: dict = {}  # assert-block -> reachable-without-it (static CFG)

    def _dominates(block_a, use, assert_line: int) -> bool:
        ub = use.basic_block
        if ub is None:
            return False
        if ub is block_a:
            # same block: dominated only if strictly after the assert.
            return use.location.line > assert_line
        reach = dom_cache.get(block_a)
        if reach is None:
            reach = dom_cache[block_a] = _reachable_avoiding(entries, block_a)
        return ub not in reach

    changed_overall = 0
    changed = True
    while changed:
        changed = False
        for a, cond in guards:
            block_a = a.basic_block
            if block_a is None:
                continue
            d = getattr(cond, "defined_by", None)

            # Build (var-to-refine, relation, other-operand-range, test-op)
            # constraints. ``test`` is the assignment that merely *reads* the
            # var to guard it — excluded from the dominance check.
            cons = []
            if d is not None and d.op in _CMP and len(d.inputs) == 2:
                lhs, rhs = d.inputs[1], d.inputs[0]  # top-first: in1 op in0
                if isinstance(lhs, SSAVar):
                    yb = _operand_range(rhs)
                    if yb is not None:
                        cons.append((lhs, d.op, yb, d))
                if isinstance(rhs, SSAVar):
                    yb = _operand_range(lhs)
                    if yb is not None:
                        cons.append((rhs, _SWAP[d.op], yb, d))
            elif isinstance(cond, SSAVar):
                cons.append((cond, "!=", IntRange(0, 0), a))  # truthiness

            for x, rel, yb, test in cons:
                if rel in ("==", "!=") and getattr(x.type, "kind", None) == "bytes":
                    continue
                if id(x) in phi_fed:
                    continue                       # phi-fed: dominance is edge-specific
                xr = _start_range(x)
                if xr is None:
                    continue
                if not all(
                    _dominates(block_a, u, a.location.line)
                    for u in x.uses if u is not test
                ):
                    continue
                lo, hi = _apply(rel, xr, yb)
                if (lo > xr.lo or hi < xr.hi) and _set_range(x, lo, hi):
                    changed_overall += 1
                    changed = True

    return changed_overall
