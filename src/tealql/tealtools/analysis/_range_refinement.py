"""Tighten :class:`IntRange` annotations from the contract's own ``assert`` guards.

HAZARD: :class:`IntRange` is ONE per-SSAVar fact read at every use, but an
assert constrains only the paths it dominates. Tightening ``x`` when some use
can be reached without passing the assert makes a detector read a bound that
does not hold there and MISS a finding. So refine only when every non-test use
is dominated. Dominance is approximated by reachability on the interprocedural
CFG, which over-approximates "reachable without A" — the test therefore errs
toward skipping a refinement, never toward applying one unsoundly.

Operands are top-first, so a comparison reads ``inputs[1] op inputs[0]``."""
from __future__ import annotations

from typing import Optional

from ..ssa import IntRange, SSAProgram, SSAVar, binary_operands
from ..cfg.dominance import AssertDominance
from ..language.avm import U64_CMP_OPS
from ._range_arithmetic import (
    _UINT64_MAX,
    _operand_range,
    _set_range,
    propagate_range_arithmetic,
)

# ``<`` ``<=`` ``>`` ``>=`` are uint64-only in the AVM (bytes use the
# ``b``-prefixed forms) so they need no type guard, but ``==`` / ``!=`` are
# polymorphic and must be guarded against bytes operands below.
_CMP = U64_CMP_OPS
# Rewrite ``Y op X`` as ``X op' Y`` to refine the right-hand operand.
_SWAP = {"<": ">", ">": "<", "<=": ">=", ">=": "<=", "==": "==", "!=": "!="}


def _start_range(x: SSAVar) -> Optional[IntRange]:
    """The range to refine from: own range, else const singleton, else the full
    uint64 domain; ``None`` for a non-uint64 var with no numeric evidence."""
    if x.range is not None:
        return x.range
    r = _operand_range(x)
    if r is not None:
        return r
    if getattr(x.type, "kind", None) in (None, "uint64"):
        return IntRange(0, _UINT64_MAX)
    return None


def _apply(rel: str, x: IntRange, y: IntRange) -> tuple[int, int]:
    """Tighten X's ``(lo, hi)`` under the proven fact ``X rel Y``.

    HAZARD: must only ever narrow, so the result stays ⊆ ``x``. Any rule that
    widens turns a sound bound into a claim the program does not guarantee."""
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
        # ``X != c`` narrows only when c sits on a boundary — an interior
        # hole is not representable as an interval.
        if y.lo == lo:
            lo += 1
        elif y.hi == hi:
            hi -= 1
    return lo, hi


def propagate_assert_ranges(prog: SSAProgram) -> int:
    """Refine SSAVar / Phi ranges from ``assert`` guards; returns how many tightened.

    HAZARD: this makes the range annotations ASSERT-CONDITIONAL rather than pure
    value facts, so any consumer asking "is this guard redundant?" now reads a
    bound the guard itself created and calls the guard dead. Such consumers must
    check ``prog._assert_ranges_applied`` and refuse to run."""
    if not getattr(prog, "_range_arith_propagated", False):
        propagate_range_arithmetic(prog)
    try:
        prog._assert_ranges_applied = True
    except AttributeError:          # only if SSAProgram ever gains __slots__
        pass

    guards = [(a, a.inputs[0]) for a in prog.assignments
              if a.op == "assert" and a.inputs]
    if not guards:
        return 0

    dom = AssertDominance(prog)

    changed_overall = 0
    changed = True
    while changed:
        changed = False
        for a, cond in guards:
            block_a = a.basic_block
            if block_a is None:
                continue
            d = getattr(cond, "defined_by", None)

            # (var-to-refine, relation, other-operand-range, test-op). ``test``
            # merely READS the var to guard it, so it is excluded from the
            # dominance check — counting it would block every refinement.
            cons = []
            if d is not None and d.op in _CMP and len(d.inputs) == 2:
                lhs, rhs = binary_operands(d)
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
                xr = _start_range(x)
                if xr is None:
                    continue
                if not dom.narrowing_is_sound(x, block_a, a.location.line,
                                              exclude=test):
                    continue
                lo, hi = _apply(rel, xr, yb)
                if (lo > xr.lo or hi < xr.hi) and _set_range(x, lo, hi):
                    changed_overall += 1
                    changed = True

    return changed_overall
