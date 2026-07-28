"""Compose :class:`IntRange` annotations through arithmetic, bitwise and shift
ops, which the seeding pass leaves unranged.

HAZARD: every bound here is derived under the assumption that execution REACHED
the next instruction, so the AVM's halting cases are excluded from the range
(``+`` / ``-`` / ``*`` halt on overflow / underflow, ``/`` / ``%`` on a zero
divisor, the shifts above 63). A rule that instead models the halt as producing
a value would put states in the range that no live execution can be in."""
from __future__ import annotations

from typing import Optional

from ..ssa import Const, IntRange, SSAProgram, SSAVar, TealType, const_int


_UINT64_MAX = (1 << 64) - 1
_UINT64 = TealType("uint64")


def _operand_range(operand) -> Optional[IntRange]:
    """Best-known integer range for an operand, lifting a const to a singleton."""
    if isinstance(operand, Const):
        n = const_int(operand)
        if n is not None and 0 <= n <= _UINT64_MAX:
            return IntRange(n, n)
        return None
    r = getattr(operand, "range", None)
    if r is not None:
        return r
    cv = getattr(operand, "const_value", None)
    if cv is not None:
        n = const_int(cv)
        if n is not None and 0 <= n <= _UINT64_MAX:
            return IntRange(n, n)
    return None


def _arith_result_range(
    op: str, ra: IntRange, rb: IntRange,
) -> Optional[tuple[int, int]]:
    """Output ``(lo, hi)`` of ``A op B`` from the operand ranges — ``ra`` is A,
    the DEEPER operand. ``None`` if the op always halts here, or is unsupported.

    Clamping to ``[0, 2^64-1]`` is the caller's job, so branches may overflow it."""
    if op == "+":
        return (ra.lo + rb.lo, ra.hi + rb.hi)
    if op == "-":
        # Halts on underflow, so the survivors are ≥ 0 even when every pair
        # could underflow — clamping the floor to 0 stays sound.
        lo = max(0, ra.lo - rb.hi)
        hi = ra.hi - rb.lo
        if hi < lo:
            return None  # impossible — no successful execution reaches here
        return (lo, hi)
    if op == "*":
        return (ra.lo * rb.lo, ra.hi * rb.hi)
    if op == "/":
        if rb.hi == 0:
            return None
        # A successful execution had divisor ≥ 1.
        div_lo = max(rb.lo, 1)
        return (ra.lo // rb.hi, ra.hi // div_lo)
    if op == "%":
        if rb.hi == 0:
            return None
        # Result is < divisor and ≤ dividend.
        div_hi_minus_1 = max(rb.hi - 1, 0)
        return (0, min(ra.hi, div_hi_minus_1))
    if op == "&":
        # AND only clears bits — result ≤ each operand.
        return (0, min(ra.hi, rb.hi))
    if op == "|":
        # OR only sets bits — floor is the larger floor, ceiling is all bits
        # set up to the wider operand's bit-length.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (max(ra.lo, rb.lo), hi)
    if op == "^":
        # ``a ^ a == 0`` so the floor is 0; same all-bits-set ceiling as OR.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (0, hi)
    if op == "<<":
        # ``A * 2^B mod 2^64``: the RESULT wraps but the op FAILS for B > 63,
        # so discarding those pairs would also be legal; widening to the full
        # domain is the more conservative choice and sound either way.
        if rb.hi >= 64:
            return (0, _UINT64_MAX)
        hi = ra.hi << rb.hi
        if hi > _UINT64_MAX:
            return (0, _UINT64_MAX)
        return (ra.lo << rb.lo, hi)
    if op == ">>":
        # ``A // 2^B``: monotonic (larger shift => smaller result), and the
        # ``min(.., 64)`` clamps only widen the result, so the bound stays sound.
        return (ra.lo >> min(rb.hi, 64), ra.hi >> min(rb.lo, 64))
    return None


def _unary_result_range(op: str, ra: IntRange) -> Optional[tuple[int, int]]:
    """Output ``(lo, hi)`` of a one-input AVM op, or ``None`` if unsupported."""
    if op == "~":
        # uint64 NOT is ``(2^64-1) - a``, so the bounds SWAP.
        return (_UINT64_MAX - ra.hi, _UINT64_MAX - ra.lo)
    return None


def _clamp_uint64(lo: int, hi: int) -> tuple[int, int]:
    if lo < 0:
        lo = 0
    if hi > _UINT64_MAX:
        hi = _UINT64_MAX
    return lo, hi


def _set_range(obj, lo: int, hi: int) -> bool:
    """Install ``IntRange(lo, hi)`` on ``obj``, returning True if it changed."""
    if lo > hi:
        return False
    existing = getattr(obj, "range", None)
    if existing is not None and existing.lo == lo and existing.hi == hi:
        return False
    obj.range = IntRange(lo, hi)
    if obj.type is None:
        obj.type = _UINT64
    return True


def propagate_range_arithmetic(prog: SSAProgram) -> int:
    """Compose ranges to a fixed point; returns how many were newly set or widened."""
    if not getattr(prog, "_ranges_propagated", False):
        prog.propagate_ranges()

    _BINARY_OPS = {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"}
    _UNARY_OPS = {"~"}

    changed_overall = 0

    # A const-folded literal N has the exact range [N, N] EVERYWHERE it is used
    # — a constant is flow-insensitive, so this is unconditionally sound. The
    # seeding pass keys on op / field shape, not const-prop, so it misses these.
    def _seed_const(obj) -> None:
        if obj.range is None:
            n = const_int(getattr(obj, "const_value", None))
            if n is not None and 0 <= n <= _UINT64_MAX and _set_range(obj, n, n):
                nonlocal changed_overall
                changed_overall += 1

    for a in prog.assignments:
        for o in a.outputs:
            if isinstance(o, SSAVar):
                _seed_const(o)
    for ph in prog.phis.values():
        _seed_const(ph)

    changed = True
    while changed:
        changed = False

        for a in prog.assignments:
            if len(a.outputs) != 1:
                continue
            out = a.outputs[0]
            if not isinstance(out, SSAVar) or out.range is not None:
                continue
            if a.op in _BINARY_OPS and len(a.inputs) == 2:
                # HAZARD: inputs are TOP-FIRST (inputs[0] = topmost popped) but
                # _arith_result_range takes ``A op B`` deepest-first, so
                # A = inputs[1], B = inputs[0]. Drop this swap and every
                # non-commutative op (-, /, %, shifts) is computed backwards.
                ra = _operand_range(a.inputs[1])
                rb = _operand_range(a.inputs[0])
                if ra is None or rb is None:
                    continue
                result = _arith_result_range(a.op, ra, rb)
            elif a.op in _UNARY_OPS and len(a.inputs) == 1:
                ra = _operand_range(a.inputs[0])
                if ra is None:
                    continue
                result = _unary_result_range(a.op, ra)
            else:
                continue
            if result is None:
                continue
            lo, hi = _clamp_uint64(*result)
            if _set_range(out, lo, hi):
                changed_overall += 1
                changed = True

        # Re-union phis so arms newly ranged by the arithmetic above feed the
        # join. Unlike the seeding pass this WIDENS an existing phi range.
        for ph in prog.phis.values():
            if not ph.args:
                continue
            arg_ranges = [_operand_range(arg) for arg in ph.args]
            if any(r is None for r in arg_ranges):
                continue
            lo = min(r.lo for r in arg_ranges)
            hi = max(r.hi for r in arg_ranges)
            if _set_range(ph, lo, hi):
                # Type unifies to uint64 only when every arg agrees.
                arg_types = [getattr(arg, "type", None) for arg in ph.args]
                if all(t is not None and t.kind == "uint64" for t in arg_types):
                    ph.type = _UINT64
                changed_overall += 1
                changed = True

    prog._range_arith_propagated = True
    return changed_overall
