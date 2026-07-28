"""Range propagation over the bytes-as-big-endian-unsigned-bigint view the AVM's
bytemath family (``b+`` ``b-`` ``b*`` ``b/`` ``b%`` ``b&`` ``b|`` ``b^``) takes.

Separate from the uint64 pass because it uses different storage and different
bounds: the bigint range lives on ``TealType.int_value_range`` (letting one
bytes SSAVar carry "how many bytes" and "what number" at once), and Python ints
are unbounded so nothing is clamped to ``2^64-1``. ``itob`` / ``btoi`` bridge
the two value spaces and are handled inline so the bridge stays in one place.

HAZARD: without a uint64 ceiling a bigint range can grow forever around a cyclic
CFG, so the fixpoint carries an explicit cap and warns rather than spinning.
``b~`` is deliberately absent: complement flips every bit of the byte-string, so
its value depends on the operand's BYTE LENGTH, which this pass does not track."""
from __future__ import annotations

import functools
import logging
from collections import deque
from typing import Optional

from ..ssa import (
    Assignment, Const, IntRange, SSAProgram, SSAVar, TealType, binary_operands,
    const_int, operand_const,
)

logger = logging.getLogger("tealql.tealtools.passes.bytemath")


_BYTES_OP_RULES = ("b+", "b-", "b*", "b/", "b%", "b&", "b|", "b^")

# Termination safety net for unbounded bigint widening; generous on purpose —
# real programs converge in <10 passes.
_PASS_ITER_CAP = 1000


@functools.lru_cache(maxsize=None)
def _bytes_to_int(hex_value: str) -> Optional[int]:
    # Cacheable because it is a pure function of the hex string, and the fixpoint
    # re-derives the same constants on every iteration.
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
    """Best-known bigint range for an operand, lifting a bytes const to a singleton."""
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
    """Output ``(lo, hi)`` of ``A op B`` from bigint ranges — ``ra`` is A, the
    DEEPER operand. ``None`` if the op always halts here, or is unsupported."""
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
        # AND only clears bits — result ≤ each operand.
        return (0, min(ra.hi, rb.hi))
    if op == "b|":
        # OR only sets bits — floor is the larger floor, ceiling is all bits
        # set up to the wider operand's bit-length (bigint, so no uint64 cap).
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (max(ra.lo, rb.lo), hi)
    if op == "b^":
        # ``a ^ a == 0`` so the floor is 0; ceiling as for b|.
        hi = (1 << max(ra.hi.bit_length(), rb.hi.bit_length())) - 1
        return (0, hi)
    return None


def _set_int_value_range(obj, lo: int, hi: int) -> bool:
    """Install / tighten ``int_value_range``, preserving the byte_length fields."""
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
        obj.type = TealType("bytes", int_value_range=IntRange(lo, hi))
    return True


_UINT64 = TealType("uint64")


def _set_uint64_range(obj, lo: int, hi: int) -> bool:
    """Install / TIGHTEN :attr:`SSAVar.range` for the ``btoi`` bridge back into
    uint64-land.

    HAZARD: must INTERSECT, never replace. Assert refinement runs earlier in the
    pipeline, so overwriting re-widens a bound an assert already proved and every
    consumer of ``.range`` silently loses the sharper fact."""
    if lo < 0 or hi > (1 << 64) - 1 or lo > hi:
        return False
    existing = getattr(obj, "range", None)
    if existing is not None:
        lo = max(existing.lo, lo)
        hi = min(existing.hi, hi)
        if lo > hi:
            return False
        if existing.lo == lo and existing.hi == hi:
            return False
    obj.range = IntRange(lo, hi)
    if obj.type is None:
        obj.type = _UINT64
    return True


def propagate_bytemath_ranges(prog: SSAProgram) -> int:
    """Propagate bigint ranges to a fixed point; returns how many were set or tightened."""
    if not getattr(prog, "_consts_propagated", False):
        prog.propagate_constants()
    if not getattr(prog, "_ranges_propagated", False):
        prog.propagate_ranges()

    tagged = 0

    # Worklist rather than re-walking everything each round: a value flows only
    # to the assignments in its `.uses` and the phis taking it as an arg. Sound
    # because `_set_int_value_range` only ever intersects, so the lattice is
    # monotonic and the fixpoint is the same one a full re-walk would reach.
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
                n = const_int(a.inputs[0])
                r = IntRange(n, n) if n is not None else None
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

        # HAZARD: operands are TOP-FIRST, so source order ``A op B`` is
        # ``inputs[1] op inputs[0]``. Use ``binary_operands`` or ``b-`` / ``b/``
        # / ``b%`` are computed reversed.
        if op in _BYTES_OP_RULES:
            if len(a.inputs) != 2:
                return
            lhs, rhs = binary_operands(a)
            ra = _operand_bigint_range(lhs)
            rb = _operand_bigint_range(rhs)
            if ra is None or rb is None:
                return
            result = _bytemath_result(op, ra, rb)
            if result is None:
                return
            if _set_int_value_range(out, *result):
                tagged += 1
                fan_out(out)
            return

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
