"""Forward range arithmetic — flow :class:`IntRange` annotations
through arithmetic ops that :meth:`tealtools.ssa.SSAProgram.propagate_ranges`
leaves untouched.

The stdlib pass seeds ranges from op-alone bounds (boolean-shaped
comparisons → ``[0..1]``, ``getbyte`` → ``[0..255]``, txn enum
fields, …) and then unions through phis at a fixed point. It does
*not* compute ``a + b`` from ``range(a)`` and ``range(b)`` — so
chains of arithmetic over ranged inputs (e.g. ``getbyte(x) + 1``)
end up unranged even though the bound is statically derivable.

This pass layers on top:

  - Seeds ranges from ``const_value`` (a literal int has the
    singleton range ``[N..N]``) for any operand the stdlib didn't
    cover.
  - Propagates ranges through the binary arithmetic ops ``+``,
    ``-``, ``*``, ``/``, ``%``, the binary bitwise / shift ops
    ``&``, ``|``, ``^``, ``<<``, ``>>``, and the unary ``~``, using
    AVM semantics (``+`` / ``-`` / ``*`` halt on overflow /
    underflow, ``/`` / ``%`` halt on divide-by-zero, ``<<`` wraps
    mod 2^64 — so a successful execution reaches the next
    instruction).
  - Re-unions phi ranges from scratch each iteration so that arms
    whose ranges only become known via arithmetic widen the join.

Opt-in (not in :func:`tealtools.passes.run_all_passes`).
Idempotent: a second call walks the fixed point again and finds
nothing further to add. Lazily trips
:meth:`SSAProgram.propagate_ranges` if it hasn't run, so seeding from
the stdlib tables happens first.

``sqrt`` / ``exp`` / ``expw`` aren't covered — rare, and ``expw``
produces a two-word result that doesn't fit the single-output
shape here.
"""
from __future__ import annotations

from typing import Optional

from ..ssa import Const, IntRange, SSAProgram, SSAVar, TealType


_UINT64_MAX = (1 << 64) - 1
_UINT64 = TealType("uint64")


def _const_int(c: Optional[Const]) -> Optional[int]:
    if c is None or c.kind != "int":
        return None
    try:
        return int(c.value)
    except (TypeError, ValueError):
        return None


def _operand_range(operand) -> Optional[IntRange]:
    """Best-known integer range for an input operand. Pulls directly
    from ``operand.range`` if set; otherwise lifts a singleton range
    from ``const_value`` (or the literal value of a ``Const``)."""
    if isinstance(operand, Const):
        n = _const_int(operand)
        if n is not None and 0 <= n <= _UINT64_MAX:
            return IntRange(n, n)
        return None
    r = getattr(operand, "range", None)
    if r is not None:
        return r
    cv = getattr(operand, "const_value", None)
    if cv is not None:
        n = _const_int(cv)
        if n is not None and 0 <= n <= _UINT64_MAX:
            return IntRange(n, n)
    return None


def _arith_result_range(
    op: str, ra: IntRange, rb: IntRange,
) -> Optional[tuple[int, int]]:
    """Compute the output ``(lo, hi)`` of a two-input AVM arithmetic op
    given its operand ranges. Returns ``None`` if the op halts
    unconditionally on this range (e.g. divide-by-zero with both
    operands certainly zero) or isn't supported.

    All clamping to ``[0, 2^64-1]`` is done in the caller.
    """
    if op == "+":
        # Halts on overflow; cap the upper bound at the uint64 ceiling.
        return (ra.lo + rb.lo, ra.hi + rb.hi)
    if op == "-":
        # Halts on underflow; if every (a, b) pair *could* underflow we
        # still know the survivors are ≥ 0, so clamp the lower bound to 0.
        lo = max(0, ra.lo - rb.hi)
        hi = ra.hi - rb.lo
        if hi < lo:
            return None  # impossible — no successful execution reaches here
        return (lo, hi)
    if op == "*":
        return (ra.lo * rb.lo, ra.hi * rb.hi)
    if op == "/":
        # Halts on divisor == 0; if rb is certainly zero, give up.
        if rb.hi == 0:
            return None
        # Successful execution requires divisor ≥ 1, so the smallest
        # divisor we can reason about is max(rb.lo, 1).
        div_lo = max(rb.lo, 1)
        return (ra.lo // rb.hi, ra.hi // div_lo)
    if op == "%":
        # Same divide-by-zero guard. Result is < divisor and ≤ dividend.
        if rb.hi == 0:
            return None
        div_hi_minus_1 = max(rb.hi - 1, 0)
        return (0, min(ra.hi, div_hi_minus_1))
    if op == "&":
        # Bitwise AND clears bits — result ≤ each operand.
        return (0, min(ra.hi, rb.hi))
    if op == "|":
        # Bitwise OR only sets bits — result ≥ each operand, so the
        # floor is the larger operand's floor. Ceiling: every bit set
        # up to the wider operand's bit-length.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (max(ra.lo, rb.lo), hi)
    if op == "^":
        # XOR: ``a ^ a == 0`` so the floor is 0; ceiling is the same
        # all-bits-set bound as OR.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (0, hi)
    if op == "<<":
        # AVM ``<<`` is ``A * 2^B mod 2^64`` — it wraps, never halts.
        # If any (a, b) pair can overflow uint64 the wrapped result is
        # unconstrained; otherwise the shift is monotonic in both args.
        if rb.hi >= 64:
            return (0, _UINT64_MAX)
        hi = ra.hi << rb.hi
        if hi > _UINT64_MAX:
            return (0, _UINT64_MAX)
        return (ra.lo << rb.lo, hi)
    if op == ">>":
        # ``>>`` is ``A // 2^B`` — never overflows, monotonic (larger
        # shift ⇒ smaller result). A shift ≥ 64 zeroes the value.
        return (ra.lo >> min(rb.hi, 64), ra.hi >> min(rb.lo, 64))
    return None


def _unary_result_range(op: str, ra: IntRange) -> Optional[tuple[int, int]]:
    """Compute the output ``(lo, hi)`` of a one-input AVM op given its
    operand range. Returns ``None`` for unsupported ops."""
    if op == "~":
        # uint64 bitwise NOT: ``~a == (2^64-1) - a``.
        return (_UINT64_MAX - ra.hi, _UINT64_MAX - ra.lo)
    return None


def _clamp_uint64(lo: int, hi: int) -> tuple[int, int]:
    if lo < 0:
        lo = 0
    if hi > _UINT64_MAX:
        hi = _UINT64_MAX
    return lo, hi


def _set_range(obj, lo: int, hi: int) -> bool:
    """Install ``IntRange(lo, hi)`` on ``obj`` and tag it as uint64.
    Returns True when this is a new range or strictly different from
    the previous one (to drive the fixed-point loop)."""
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
    """Walk ``prog`` to a fixed point, propagating ``IntRange``
    annotations through the arithmetic ops (``+`` ``-`` ``*`` ``/``
    ``%``), the bitwise / shift ops (``&`` ``|`` ``^`` ``<<`` ``>>``
    ``~``) over operands whose ranges are already known. Returns the
    number of SSAVars / Phis whose range was newly set (or widened
    during a phi re-union).

    Lazy-trips :meth:`SSAProgram.propagate_ranges` first so the
    stdlib seeds (boolean comparisons, txn enum fields, …) are in
    place before arithmetic chains start composing them.
    """
    if not getattr(prog, "_ranges_propagated", False):
        prog.propagate_ranges()

    _BINARY_OPS = {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"}
    _UNARY_OPS = {"~"}

    changed_overall = 0
    changed = True
    while changed:
        changed = False

        # Arithmetic assignments: compute output range from inputs.
        for a in prog.assignments:
            if len(a.outputs) != 1:
                continue
            out = a.outputs[0]
            if not isinstance(out, SSAVar) or out.range is not None:
                continue
            if a.op in _BINARY_OPS and len(a.inputs) == 2:
                ra = _operand_range(a.inputs[0])
                rb = _operand_range(a.inputs[1])
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

        # Re-union phis: arms whose ranges only just became known
        # (via the arithmetic pass above) need to feed the join. Unlike
        # propagate_ranges' phi loop, this *widens* an existing range
        # when new arg info would extend it.
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

    return changed_overall
