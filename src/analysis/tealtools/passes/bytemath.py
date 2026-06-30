"""Bytemath range propagation — flow ``IntRange`` annotations over
the bytes-as-big-endian-unsigned-bigint abstraction the AVM's
bytemath family (``b+`` ``b-`` ``b*`` ``b/`` ``b%`` ``b&`` ``b|``
``b^``) operates over.

Why this is a separate pass rather than an extension of
:mod:`tealtools.range_arith`:

  - Different storage. The uint64 value range lives on
    :attr:`tealtools.ssa.SSAVar.range`; the bigint value range lives
    on :attr:`tealtools.ssa.TealType.int_value_range` (so a single
    bytes SSAVar can carry both ``byte_length_range`` *and* a value
    range, distinguishing "how many bytes" from "what number").
  - Different bounds. Python ints are arbitrary precision, so a
    bytemath ``b*`` chain can legitimately produce ranges whose
    upper bounds exceed ``2^64-1``. No clamping to uint64.
  - Cross-pollination with the uint64 side. ``itob X`` and
    ``btoi X`` bridge the two value spaces — itob's bytes-output
    bigint value equals its uint64 input, and a successful btoi's
    uint64 output equals its bytes-input bigint value. Handled
    inline here so the bridge stays in one place.

Forward rules:

  - ``Const("bytes", "0x..")``        → singleton bigint range from
                                        ``int.from_bytes(..., "big")``.
  - ``itob X``                        → ``X.range`` (carried across
                                        the uint64/bytes boundary).
  - ``b+ a b``                        → ``[a.lo+b.lo, a.hi+b.hi]``.
  - ``b- a b``                        → AVM halts on underflow, so
                                        result clamped to ``≥ 0``.
  - ``b* a b``                        → ``[a.lo*b.lo, a.hi*b.hi]``.
  - ``b/ a b``                        → AVM halts on divisor 0, so
                                        smallest divisor is
                                        ``max(b.lo, 1)``.
  - ``b% a b``                        → ``[0, min(a.hi, b.hi-1)]``.
  - ``b& a b``                        → ``[0, min(a.hi, b.hi)]``.
  - ``b| a b``                        → ``[max(a.lo, b.lo),
                                        all-bits-set]``.
  - ``b^ a b``                        → ``[0, all-bits-set]``.

Cross-pollination into uint64 land (writes :attr:`SSAVar.range`):

  - ``btoi X``                        → ``X.int_value_range``
                                        (assuming the call succeeds —
                                        which also implies
                                        ``len(X) ∈ [1, 8]``, a
                                        constraint that
                                        :mod:`tealtools.byte_length_prop`
                                        already installs).

Phi union iterates to fixed point, but the iteration counter is
capped: bigint ranges can grow without bound in a cyclic CFG (no
``2^64`` natural ceiling), so we bail with a warning rather than
spinning forever. In practice convergence is fast — bytemath
loops are rare and the cap is hit only on programs that need
proper widening operators (an abstract-interpretation topic
out of scope here).

``b~`` (bitwise complement) and ``bsqrt`` are deferred: ``b~``
flips every bit of a byte-string, so its bigint value depends on
the operand's *byte length* — which this value-range pass doesn't
track (``byte_length_prop`` does). TEAL has no byte-shift ops, so
there's no ``b<<`` / ``b>>`` analogue. Comparison ops (``b<`` /
``b>`` / …) already get their ``[0..1]`` range from
:meth:`SSAProgram.propagate_ranges`' ``_OP_RANGE_SEEDS`` so they're
not duplicated here.

Opt-in. Lazily trips :meth:`SSAProgram.propagate_constants` and
:meth:`SSAProgram.propagate_ranges` first so the bytes-const and
uint64-range seeds are in place before bytemath composes them.
"""
from __future__ import annotations

import functools
import logging
from collections import deque
from typing import Optional

from ..ssa import (
    Assignment, Const, IntRange, SSAProgram, SSAVar, TealType, operand_const,
)

logger = logging.getLogger("tealtools.passes.bytemath")


_BYTES_OP_RULES = ("b+", "b-", "b*", "b/", "b%", "b&", "b|", "b^")

# Safety net: bigint phi widening with no natural ceiling could
# in principle loop forever. Bail before that. ``_PASS_ITER_CAP``
# is intentionally generous — real programs converge in <10 passes.
_PASS_ITER_CAP = 1000


@functools.lru_cache(maxsize=None)
def _bytes_to_int(hex_value: str) -> Optional[int]:
    # Cached: a constant's bigint value is immutable, but the naive bytemath
    # fixpoint re-derives it for every operand on every iteration (~4M fromhex
    # re-parses on folks-v3). Pure function of the hex string -> identical result.
    h = hex_value
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    if len(h) % 2 != 0:
        return None
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return None
    return int.from_bytes(b, "big") if b else 0


def _const_bigint(c: Optional[Const]) -> Optional[int]:
    if c is None or c.kind != "bytes":
        return None
    return _bytes_to_int(c.value)


def _operand_bigint_range(operand) -> Optional[IntRange]:
    """Best-known bigint range for an operand. Looks at (a) its
    :attr:`TealType.int_value_range`, (b) its ``const_value``
    treated as a bigint, (c) the operand itself if it's a bytes
    :class:`Const`."""
    t = getattr(operand, "type", None)
    if t is not None and t.kind == "bytes" and t.int_value_range is not None:
        return t.int_value_range
    n = _const_bigint(operand_const(operand))
    if n is not None:
        return IntRange(n, n)
    return None


def _bytemath_result(
    op: str, ra: IntRange, rb: IntRange,
) -> Optional[tuple[int, int]]:
    """Compute the ``(lo, hi)`` of a bytemath two-input op given its
    operand bigint ranges. Returns ``None`` when the op halts
    unconditionally on this range (e.g. ``b/`` with ``b`` certainly
    zero) or isn't supported here."""
    if op == "b+":
        return (ra.lo + rb.lo, ra.hi + rb.hi)
    if op == "b-":
        lo = max(0, ra.lo - rb.hi)
        hi = ra.hi - rb.lo
        if hi < lo:
            return None
        return (lo, hi)
    if op == "b*":
        return (ra.lo * rb.lo, ra.hi * rb.hi)
    if op == "b/":
        if rb.hi == 0:
            return None
        return (ra.lo // rb.hi, ra.hi // max(rb.lo, 1))
    if op == "b%":
        if rb.hi == 0:
            return None
        return (0, min(ra.hi, max(rb.hi - 1, 0)))
    if op == "b&":
        # Bitwise AND clears bits — result ≤ each operand.
        return (0, min(ra.hi, rb.hi))
    if op == "b|":
        # Bitwise OR only sets bits — result ≥ each operand. Ceiling:
        # every bit set up to the wider operand's bit-length. Bigints,
        # so no uint64 cap.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (max(ra.lo, rb.lo), hi)
    if op == "b^":
        # XOR: ``a ^ a == 0`` so the floor is 0; ceiling as for b|.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (0, hi)
    return None


def _set_int_value_range(obj, lo: int, hi: int) -> bool:
    """Install / tighten ``int_value_range`` on ``obj``. Preserves
    existing ``byte_length`` and ``byte_length_range`` so the three
    fields can coexist on one TealType."""
    if lo > hi:
        return False
    existing = getattr(obj, "type", None)
    if existing is not None and existing.kind == "bytes":
        if existing.int_value_range is not None:
            old = existing.int_value_range
            new_lo = max(old.lo, lo)
            new_hi = min(old.hi, hi)
            if new_lo > new_hi:
                return False
            if new_lo == old.lo and new_hi == old.hi:
                return False
            lo, hi = new_lo, new_hi
        obj.type = TealType(
            "bytes",
            byte_length=existing.byte_length,
            byte_length_range=existing.byte_length_range,
            int_value_range=IntRange(lo, hi),
        )
    else:
        # No existing TealType (or it's uint64 — shouldn't happen on a
        # bytemath output, but be defensive).
        obj.type = TealType("bytes", int_value_range=IntRange(lo, hi))
    return True


_UINT64 = TealType("uint64")


def _set_uint64_range(obj, lo: int, hi: int) -> bool:
    """Install / widen :attr:`SSAVar.range` on ``obj``. Used for the
    ``btoi`` bridge that lifts a bigint range from bytes-land back
    into uint64-land."""
    if lo < 0 or hi > (1 << 64) - 1 or lo > hi:
        return False
    existing = getattr(obj, "range", None)
    if existing is not None and existing.lo == lo and existing.hi == hi:
        return False
    obj.range = IntRange(lo, hi)
    if obj.type is None:
        obj.type = _UINT64
    return True


def propagate_bytemath_ranges(prog: SSAProgram) -> int:
    """Walk ``prog`` to a fixed point. Each iteration:

      1. Seed bigint ranges from bytes constants on operand sources
         (``Const`` operands, ``const_value`` on producers).
      2. Forward-propagate through bytemath arithmetic ops.
      3. Cross-pollinate ``itob`` (uint64 ↦ bytes) and ``btoi``
         (bytes ↦ uint64).
      4. Union arg bigint ranges through phis.

    Returns the cumulative count of range installations / tightenings.
    Capped at :data:`_PASS_ITER_CAP` iterations to prevent runaway
    growth on cyclic CFGs with bytemath loops."""
    if not getattr(prog, "_consts_propagated", False):
        prog.propagate_constants()
    if not getattr(prog, "_ranges_propagated", False):
        prog.propagate_ranges()

    tagged = 0

    # Worklist instead of re-walking all ~assignments + phis each round: a value
    # flows only to the assignments that use it (.uses) and the phis that take it
    # as an arg, so when an operand's range / int_value_range changes only its
    # consumers are re-evaluated. _set_int_value_range only intersects (and the
    # phi union's grown bounding is intersected away), so the lattice is
    # monotonic and the final type state is identical -- just reached without the
    # redundant re-walks. A defensive pop cap stands in for the old iteration cap.
    phis = list(prog.phis.values())
    phi_consumers: dict = {}
    for ph in phis:
        for arg in ph.args:
            phi_consumers.setdefault(id(arg), []).append(ph)

    work: deque = deque()
    queued: set = set()

    def enqueue(item) -> None:
        if id(item) not in queued:
            queued.add(id(item))
            work.append(item)

    def fan_out(v) -> None:
        for u in v.uses:
            enqueue(u)
        for ph in phi_consumers.get(id(v), ()):
            enqueue(ph)

    def do_assignment(a) -> None:
        nonlocal tagged
        if len(a.outputs) != 1:
            return
        out = a.outputs[0]
        if not isinstance(out, SSAVar):
            return
        op = a.op

        # itob X (uint64 → bytes): output bigint value == input uint64.
        if op == "itob":
            if len(a.inputs) != 1:
                return
            r = getattr(a.inputs[0], "range", None)
            if r is None:
                cv = getattr(a.inputs[0], "const_value", None) \
                    or (a.inputs[0] if isinstance(a.inputs[0], Const) else None)
                if cv is not None and cv.kind == "int":
                    try:
                        n = int(cv.value)
                        r = IntRange(n, n)
                    except (TypeError, ValueError):
                        r = None
            if r is None:
                return
            if _set_int_value_range(out, r.lo, r.hi):
                tagged += 1
                fan_out(out)
            return

        # btoi X (bytes → uint64): output uint64 == input bigint (rejected by
        # _set_uint64_range if the bigint range doesn't fit in uint64).
        if op == "btoi":
            if len(a.inputs) != 1:
                return
            r = _operand_bigint_range(a.inputs[0])
            if r is None:
                return
            if _set_uint64_range(out, r.lo, r.hi):
                tagged += 1
                fan_out(out)
            return

        # Bytemath arithmetic.
        if op in _BYTES_OP_RULES:
            if len(a.inputs) != 2:
                return
            ra = _operand_bigint_range(a.inputs[0])
            rb = _operand_bigint_range(a.inputs[1])
            if ra is None or rb is None:
                return
            result = _bytemath_result(op, ra, rb)
            if result is None:
                return
            if _set_int_value_range(out, *result):
                tagged += 1
                fan_out(out)
            return

        # Single-output bytes constants: seed singleton range from the literal.
        if a.const is not None and a.const.kind == "bytes":
            n = _bytes_to_int(a.const.value)
            if n is not None and _set_int_value_range(out, n, n):
                tagged += 1
                fan_out(out)

    def do_phi(ph) -> None:
        nonlocal tagged
        if not ph.args:
            return
        ranges = [_operand_bigint_range(arg) for arg in ph.args]
        if any(r is None for r in ranges):
            return
        lo = min(r.lo for r in ranges)  # type: ignore[union-attr]
        hi = max(r.hi for r in ranges)  # type: ignore[union-attr]
        if _set_int_value_range(ph, lo, hi):
            tagged += 1
            fan_out(ph)

    for a in prog.assignments:
        enqueue(a)
    for ph in phis:
        enqueue(ph)
    cap = _PASS_ITER_CAP * (len(prog.assignments) + len(phis) + 1)
    pops = 0
    while work and pops < cap:
        pops += 1
        item = work.popleft()
        queued.discard(id(item))
        if isinstance(item, Assignment):
            do_assignment(item)
        else:
            do_phi(item)
    if pops >= cap:
        logger.warning(
            "propagate_bytemath_ranges hit iteration cap (%d) after %d pops; "
            "ranges may not have converged. This usually means a bytemath "
            "loop needs proper widening.", cap, pops,
        )
    return tagged
