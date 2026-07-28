"""Populate ``TealType.byte_length`` (exact) and ``byte_length_range`` (bounded)
on bytes SSAVars / Phis, forward from producing ops and backward from the length
each consuming op's successful execution implies.

HAZARD: operands are TOP-FIRST throughout this module — for the three-input
byte ops the BUFFER is the deepest operand and the indices/counts sit above it.
Every rule below states the index mapping it relies on; getting one backwards
silently reads a length off an index operand.

A phi takes an exact length only when every arg agrees; disagreeing args mean
the runtime length is one of several, so it falls back to the union of the arg
RANGES — a strictly looser bound, never an exact claim."""
from __future__ import annotations

import functools
from collections import deque
from typing import Optional

from ..ssa import (
    Assignment, Const, IntRange, Phi, SSAProgram, SSAVar, TealType,
    const_int, operand_const,
)
from ..avm import (
    FIXED_BYTES_OUTPUT_LEN,
    _GLOBAL_FIELD_BYTELEN,
    _OP_OUTPUT_BYTELEN,
    _PARAMS_OPS,
    _PARAMS_VALUE_BYTELEN,
    _TXN_FIELD_BYTELEN,
    _txn_field_name,
)


_BYTES_STACK_CAP = 4096  # AVM bytes-stack values are capped at 4096 bytes.


@functools.lru_cache(maxsize=None)
def _hex_byte_length(h: str) -> Optional[int]:
    """Byte length of a ``0x...`` hex literal, or ``None`` if unparseable."""
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    if len(h) % 2 != 0:
        return None
    try:
        bytes.fromhex(h)
    except ValueError:
        return None
    return len(h) // 2


def _const_bytes_length(c: Optional[Const]) -> Optional[int]:
    """Length of a ``Const("bytes", "0x...")`` literal, or ``None`` if not one."""
    if c is None or c.kind != "bytes":
        return None
    return _hex_byte_length(c.value)


def _operand_byte_length(operand) -> Optional[int]:
    """Known exact byte_length of an operand, else ``None``."""
    t = getattr(operand, "type", None)
    if t is not None and t.kind == "bytes" and t.byte_length is not None:
        return t.byte_length
    return _const_bytes_length(operand_const(operand))


def _op_byte_length(a: Assignment) -> Optional[int]:
    """Output byte_length implied by ``a``'s op semantics, or ``None`` if not
    statically derivable (yet)."""
    if a.const is not None and a.const.kind == "bytes":
        return _const_bytes_length(a.const)

    op = a.op

    if op == "itob":
        return 8

    if op == "bzero":
        if len(a.inputs) != 1:
            return None
        n = const_int(operand_const(a.inputs[0]))
        if n is None or n < 0:
            return None
        return n

    if op == "extract":
        # ``extract A B``, where ``B == 0`` means "to end of input" and so
        # needs the input's own byte_length.
        if not a.immediates:
            return None
        toks = a.immediates.split()
        if len(toks) != 2:
            return None
        try:
            start, length = int(toks[0]), int(toks[1])
        except ValueError:
            return None
        if length > 0:
            return length
        if length == 0 and a.inputs:
            src_len = _operand_byte_length(a.inputs[0])
            if src_len is None or start > src_len:
                return None
            return src_len - start
        return None

    if op == "substring":
        # ``substring A B`` → bytes[A:B], length B - A.
        if not a.immediates:
            return None
        toks = a.immediates.split()
        if len(toks) != 2:
            return None
        try:
            start, end = int(toks[0]), int(toks[1])
        except ValueError:
            return None
        if end < start:
            return None
        return end - start

    if op == "concat":
        if len(a.inputs) != 2:
            return None
        la = _operand_byte_length(a.inputs[0])
        lb = _operand_byte_length(a.inputs[1])
        if la is None or lb is None:
            return None
        return la + lb

    if op == "extract3":
        # ``extract3 X A B`` → bytes[A : A + B]; output length is the COUNT B.
        # TOP-FIRST: B=inputs[0] (top), A=inputs[1], X=inputs[2] (deepest).
        if len(a.inputs) != 3:
            return None
        n = const_int(operand_const(a.inputs[0]))
        if n is None or n < 0:
            return None
        return n

    if op == "substring3":
        # ``substring3 X A B`` → bytes[A : B]; length is B - A. TOP-FIRST:
        # B(end)=inputs[0], A(start)=inputs[1], X=inputs[2].
        if len(a.inputs) != 3:
            return None
        end = const_int(operand_const(a.inputs[0]))
        start = const_int(operand_const(a.inputs[1]))
        if start is None or end is None or end < start:
            return None
        return end - start

    # Length-preserving ops inherit the BUFFER's byte_length. The buffer X is
    # pushed first, so TOP-FIRST it is the DEEPEST operand ``inputs[-1]``, not
    # ``inputs[0]``.
    if op in ("setbyte", "replace2", "replace3"):
        if not a.inputs:
            return None
        return _operand_byte_length(a.inputs[-1])

    # Fixed-width hash / digest outputs, from the AVM metadata table.
    n = FIXED_BYTES_OUTPUT_LEN.get(op)
    if n is not None:
        return n

    # Fixed-width bytes fields (32-byte addresses / keys, 64-byte StateProofPK).
    if a.immediates:
        toks = a.immediates.split()
        field = _txn_field_name(op, toks)
        if field is not None:
            n = _TXN_FIELD_BYTELEN.get(field)
            if n is not None:
                return n
        if op == "global" and toks:
            n = _GLOBAL_FIELD_BYTELEN.get(toks[0])
            if n is not None:
                return n

    return None


def _operand_byte_length_range(operand) -> Optional[IntRange]:
    """Best-known length range for an operand, an exact length becoming ``[N, N]``."""
    n = _operand_byte_length(operand)
    if n is not None:
        return IntRange(n, n)
    t = getattr(operand, "type", None)
    if t is not None and t.kind == "bytes" and t.byte_length_range is not None:
        return t.byte_length_range
    return None


def _set_byte_length(obj, n: int) -> bool:
    """Pin ``obj`` to an exact byte length; returns True if it changed."""
    existing = getattr(obj, "type", None)
    if existing is not None and existing.kind == "bytes" \
            and existing.byte_length is not None:
        return False
    obj.type = TealType(
        "bytes",
        byte_length=n,
        byte_length_range=IntRange(n, n),
        # Carry the bigint value-range forward — the three fields coexist on one
        # TealType, and dropping it erases bytemath's facts depending on pass order.
        int_value_range=getattr(existing, "int_value_range", None),
    )
    return True


def _set_byte_length_range(obj, lo: int, hi: int) -> bool:
    """Install or INTERSECT a length range on ``obj``; True if it tightened.

    HAZARD: never widens, and never touches a var already pinned to an exact
    ``byte_length`` — the exact fact is strictly stronger than any range."""
    # Clamp to the AVM bytes-stack cap.
    if lo < 0:
        lo = 0
    if hi > _BYTES_STACK_CAP:
        hi = _BYTES_STACK_CAP
    if lo > hi:
        return False
    existing = getattr(obj, "type", None)
    if existing is not None and existing.kind == "bytes" \
            and existing.byte_length is not None:
        return False
    if existing is not None and existing.byte_length_range is not None:
        old = existing.byte_length_range
        new_lo = max(old.lo, lo)
        new_hi = min(old.hi, hi)
        if new_lo > new_hi:
            return False  # would yield an infeasible (empty) range
        if new_lo == old.lo and new_hi == old.hi:
            return False
        lo, hi = new_lo, new_hi
    obj.type = TealType(
        "bytes",
        byte_length=None,
        byte_length_range=IntRange(lo, hi),
        int_value_range=getattr(existing, "int_value_range", None),
    )
    return True


def _input_min_length(a: Assignment) -> Optional[tuple[int, int, Optional[int]]]:
    """``(input_index, min_len, max_len)`` for an op whose success constrains an
    input's byte_length; ``max_len`` ``None`` means lower bound only."""
    op = a.op

    # btoi(X) succeeds ⇒ len(X) ∈ [0, 8]. It fails ONLY for len > 8, and
    # btoi("") legally yields 0, so the lower bound must include 0.
    if op == "btoi":
        if not a.inputs:
            return None
        return (0, 0, 8)

    # getbyte(X, i) — needs len(X) ≥ i + 1 when i is a const. TOP-FIRST:
    # i=inputs[0], X=inputs[1], so the constraint lands on index 1.
    if op == "getbyte":
        if len(a.inputs) != 2:
            return None
        idx = const_int(operand_const(a.inputs[0]))
        if idx is None or idx < 0:
            return None
        return (1, idx + 1, None)

    # extract_uint{16,32,64}(X, i) — needs len(X) ≥ i + 2/4/8. TOP-FIRST:
    # i=inputs[0], X=inputs[1], so the constraint lands on index 1.
    if op in ("extract_uint16", "extract_uint32", "extract_uint64"):
        if len(a.inputs) != 2:
            return None
        idx = const_int(operand_const(a.inputs[0]))
        if idx is None or idx < 0:
            return None
        width = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}[op]
        return (1, idx + width, None)

    # extract A B X (immediate) — needs len(X) ≥ A + B (≥ A when B == 0).
    if op == "extract":
        if not a.inputs or not a.immediates:
            return None
        toks = a.immediates.split()
        if len(toks) != 2:
            return None
        try:
            start, length = int(toks[0]), int(toks[1])
        except ValueError:
            return None
        if length < 0 or start < 0:
            return None
        return (0, start + length, None)

    # substring A B X (immediate) — needs len(X) ≥ B.
    if op == "substring":
        if not a.inputs or not a.immediates:
            return None
        toks = a.immediates.split()
        if len(toks) != 2:
            return None
        try:
            end = int(toks[1])
        except ValueError:
            return None
        if end < 0:
            return None
        return (0, end, None)

    # extract3 X A B — needs len(X) ≥ A + B when both are const. TOP-FIRST:
    # B(count)=inputs[0], A(start)=inputs[1], X=inputs[2] — constraint on index 2.
    if op == "extract3":
        if len(a.inputs) != 3:
            return None
        length = const_int(operand_const(a.inputs[0]))
        start = const_int(operand_const(a.inputs[1]))
        if start is None or length is None or start < 0 or length < 0:
            return None
        return (2, start + length, None)

    # substring3 X A B — needs len(X) ≥ B when B is a const. TOP-FIRST:
    # B(end)=inputs[0], A=inputs[1], X=inputs[2] — constraint on index 2.
    if op == "substring3":
        if len(a.inputs) != 3:
            return None
        end = const_int(operand_const(a.inputs[0]))
        if end is None or end < 0:
            return None
        return (2, end, None)

    # setbyte X i b — needs len(X) ≥ i + 1 when i is a const. TOP-FIRST:
    # b=inputs[0], i=inputs[1], X=inputs[2] — constraint on index 2.
    if op == "setbyte":
        if len(a.inputs) != 3:
            return None
        idx = const_int(operand_const(a.inputs[1]))
        if idx is None or idx < 0:
            return None
        return (2, idx + 1, None)

    return None


def propagate_byte_lengths(prog: SSAProgram) -> int:
    """Propagate lengths to a fixed point; returns how many facts were installed."""
    if not getattr(prog, "_consts_propagated", False):
        prog.propagate_constants()

    tagged = 0

    # Worklist rather than re-walking everything each round: a value flows only
    # to the assignments in its `.uses` and the phis taking it as an arg. Sound
    # because the lattice is monotonic (byte_length set once, ranges only
    # intersect), so this reaches the same least fixed point.
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

    # Forward exact-length rules for one bytes-producing op.
    def do_assignment(a) -> None:
        nonlocal tagged
        # Multi-output fixed-width bytes ops (ecdsa pubkey words, vrf_verify)
        # bind by output INDEX, top-first.
        out_lens = _OP_OUTPUT_BYTELEN.get(a.op)
        if out_lens is not None:
            for idx, n in out_lens:
                if idx < len(a.outputs):
                    out = a.outputs[idx]
                    if isinstance(out, SSAVar) and _set_byte_length(out, n):
                        tagged += 1
                        fan_out(out)
            return

        # *_params_get: outputs[1] is the VALUE, fixed-width for some fields.
        if a.op in _PARAMS_OPS:
            if a.immediates and len(a.outputs) > 1:
                n = _PARAMS_VALUE_BYTELEN.get(a.immediates.split()[0])
                out = a.outputs[1]
                if n is not None and isinstance(out, SSAVar) \
                        and _set_byte_length(out, n):
                    tagged += 1
                    fan_out(out)
            return

        if len(a.outputs) != 1:
            return
        out = a.outputs[0]
        if not isinstance(out, SSAVar):
            return
        existing = out.type
        if existing is not None and existing.kind == "bytes" \
                and existing.byte_length is not None:
            return
        n = _op_byte_length(a)
        if n is None or n < 0:
            return
        if _set_byte_length(out, n):
            tagged += 1
            fan_out(out)

    # Phi propagation: exact-length agreement first, range union as fallback.
    def do_phi(ph) -> None:
        nonlocal tagged
        existing = ph.type
        if existing is not None and existing.kind == "bytes" \
                and existing.byte_length is not None:
            return
        if not ph.args:
            return
        lengths: list[Optional[int]] = [_operand_byte_length(a) for a in ph.args]
        if all(n is not None for n in lengths) and lengths \
                and all(n == lengths[0] for n in lengths):
            if _set_byte_length(ph, lengths[0]):  # type: ignore[arg-type]
                tagged += 1
                fan_out(ph)
                return
        ranges = [_operand_byte_length_range(a) for a in ph.args]
        if any(r is None for r in ranges):
            return
        lo = min(r.lo for r in ranges)  # type: ignore[union-attr]
        hi = max(r.hi for r in ranges)  # type: ignore[union-attr]
        if _set_byte_length_range(ph, lo, hi):
            tagged += 1
            fan_out(ph)

    # Inverse length constraints depend only on op / immediates / const operands,
    # so they are a one-shot seed rather than part of the fixpoint.
    #
    # HAZARD: FLOW-GATED, on the same model as passes.range_assert. "This op
    # executed successfully" holds only on paths through the op, but the range
    # lands on the SSAVar and is read at EVERY use — one branch's btoi(X) would
    # otherwise cap X at 8 bytes in the other branch. So install it only when
    # every other use is dominated by the op, and never on a phi-fed value,
    # whose incoming edge the dominance check cannot see.
    from ..cfg.dominance import AssertDominance
    dom = AssertDominance(prog)
    phi_fed = {id(arg) for ph in prog.phis.values() for arg in ph.args}
    for a in prog.assignments:
        constraint = _input_min_length(a)
        if constraint is None:
            continue
        idx, lo, hi = constraint
        if idx >= len(a.inputs):
            continue
        target = a.inputs[idx]
        if not isinstance(target, (SSAVar, Phi)):
            continue
        if id(target) in phi_fed:
            continue
        block_a = a.basic_block
        if block_a is None:
            continue
        if not all(
            dom.dominates(block_a, u.basic_block,
                          a.location.line, u.location.line)
            for u in target.uses if u is not a
        ):
            continue
        hi_eff = _BYTES_STACK_CAP if hi is None else hi
        if _set_byte_length_range(target, lo, hi_eff):
            tagged += 1
            fan_out(target)

    for a in prog.assignments:
        enqueue(a)
    for ph in phis:
        enqueue(ph)
    while work:
        item = work.popleft()
        queued.discard(id(item))
        if isinstance(item, Assignment):
            do_assignment(item)
        else:
            do_phi(item)

    return tagged
