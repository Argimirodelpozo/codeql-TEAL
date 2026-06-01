"""Constant folding for SSA Assignments.

Pure functions over :class:`tealtools.ssa.Const` values that compute
the result of foldable opcodes when every input is statically known.
Used by :meth:`tealtools.ssa.SSAProgram.propagate_constants` to
extend its phi-unification + identity-step fixpoint with op-level
folding — ``concat`` of two bytes literals, ``itob`` of an int,
``extract A B`` of a known bytes value, ``+`` of two ints, etc.

Kept as a separate module so the ssa.py substrate stays focused on
type definitions and the SSA construction itself; everything in here
is TEAL-semantics layered on top of those types.

Each ``_fold_*`` helper returns either a :class:`Const` (the
computed value) or ``None`` (folding unavailable: wrong input kind,
overflow, divide-by-zero, out-of-range slice, etc.). The top-level
entry point :func:`try_fold_assignment` dispatches on
``Assignment.op``.
"""
from __future__ import annotations

from typing import Optional

from ..ssa import Assignment, Const


# ---------------------------------------------------------------------------
# Const ↔ runtime-value helpers
# ---------------------------------------------------------------------------


def _bytes_from_const(c: Optional[Const]) -> Optional[bytes]:
    if c is None or c.kind != "bytes":
        return None
    h = c.value
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    try:
        return bytes.fromhex(h)
    except ValueError:
        return None


def _int_from_const(c: Optional[Const]) -> Optional[int]:
    if c is None or c.kind != "int":
        return None
    try:
        return int(c.value)
    except (TypeError, ValueError):
        return None


def _bytes_const(b: bytes) -> Const:
    return Const("bytes", "0x" + b.hex())


def _int_const(n: int) -> Const:
    return Const("int", str(n))


_UINT64_MAX = (1 << 64) - 1


# ---------------------------------------------------------------------------
# Per-op folders
# ---------------------------------------------------------------------------


def _fold_concat(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 2:
        return None
    a, b = _bytes_from_const(inputs[0]), _bytes_from_const(inputs[1])
    if a is None or b is None:
        return None
    return _bytes_const(a + b)


def _fold_extract_imm(
    inputs: list[Const], immediates: str,
) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    src = _bytes_from_const(inputs[0])
    if src is None:
        return None
    parts = immediates.split()
    if len(parts) != 2:
        return None
    try:
        start, length = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    end = start + length if length != 0 else len(src)
    if start < 0 or end > len(src):
        return None
    return _bytes_const(src[start:end])


def _fold_extract3(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 3:
        return None
    src = _bytes_from_const(inputs[0])
    start = _int_from_const(inputs[1])
    length = _int_from_const(inputs[2])
    if src is None or start is None or length is None:
        return None
    if start < 0 or start + length > len(src):
        return None
    return _bytes_const(src[start:start + length])


def _fold_substring_imm(
    inputs: list[Const], immediates: str,
) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    src = _bytes_from_const(inputs[0])
    if src is None:
        return None
    parts = immediates.split()
    if len(parts) != 2:
        return None
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        return None
    if start < 0 or end > len(src) or start > end:
        return None
    return _bytes_const(src[start:end])


def _fold_substring3(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 3:
        return None
    src = _bytes_from_const(inputs[0])
    start = _int_from_const(inputs[1])
    end = _int_from_const(inputs[2])
    if src is None or start is None or end is None:
        return None
    if start < 0 or end > len(src) or start > end:
        return None
    return _bytes_const(src[start:end])


def _fold_extract_uint(
    inputs: list[Const], n_bytes: int,
) -> Optional[Const]:
    if len(inputs) != 2:
        return None
    src = _bytes_from_const(inputs[0])
    offset = _int_from_const(inputs[1])
    if src is None or offset is None:
        return None
    if offset < 0 or offset + n_bytes > len(src):
        return None
    return _int_const(int.from_bytes(src[offset:offset + n_bytes], "big"))


def _fold_itob(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    n = _int_from_const(inputs[0])
    if n is None or n < 0 or n >= 2 ** 64:
        return None
    return _bytes_const(n.to_bytes(8, "big"))


def _fold_btoi(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    src = _bytes_from_const(inputs[0])
    if src is None or len(src) > 8:
        return None
    return _int_const(int.from_bytes(src, "big") if src else 0)


def _fold_len(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    src = _bytes_from_const(inputs[0])
    if src is None:
        return None
    return _int_const(len(src))


def _fold_bzero(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 1:
        return None
    n = _int_from_const(inputs[0])
    if n is None or n < 0 or n > 4096:
        return None
    return _bytes_const(b"\x00" * n)


def _fold_getbyte(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 2:
        return None
    src = _bytes_from_const(inputs[0])
    idx = _int_from_const(inputs[1])
    if src is None or idx is None or idx < 0 or idx >= len(src):
        return None
    return _int_const(src[idx])


def _fold_setbyte(inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 3:
        return None
    src = _bytes_from_const(inputs[0])
    idx = _int_from_const(inputs[1])
    val = _int_from_const(inputs[2])
    if src is None or idx is None or val is None:
        return None
    if idx < 0 or idx >= len(src) or val < 0 or val > 255:
        return None
    buf = bytearray(src)
    buf[idx] = val
    return _bytes_const(bytes(buf))


def _fold_int_arith(
    op: str, inputs: list[Const],
) -> Optional[Const]:
    if len(inputs) != 2:
        return None
    a, b = _int_from_const(inputs[0]), _int_from_const(inputs[1])
    if a is None or b is None:
        return None
    if op == "+":
        r = a + b
    elif op == "-":
        r = a - b
        if r < 0:
            return None  # AVM is uint64; underflow would err at runtime
    elif op == "*":
        r = a * b
    elif op == "/":
        if b == 0:
            return None
        r = a // b
    elif op == "%":
        if b == 0:
            return None
        r = a % b
    else:
        return None
    if r >= 2 ** 64:
        return None
    return _int_const(r)


def _fold_bitwise(op: str, inputs: list[Const]) -> Optional[Const]:
    """Fold the uint64 bitwise / shift binary ops. Operand order
    matches the arithmetic folders and :mod:`tealtools.passes.range_arith`:
    ``inputs[0]`` is the deeper stack value ``A``, ``inputs[1]`` the
    top ``B``. AVM semantics: ``<<`` is ``A * 2^B mod 2^64`` (wraps,
    never halts); ``>>`` is ``A // 2^B``; ``&`` / ``|`` / ``^`` are the
    usual uint64 bit ops."""
    if len(inputs) != 2:
        return None
    a, b = _int_from_const(inputs[0]), _int_from_const(inputs[1])
    if a is None or b is None:
        return None
    if a < 0 or a > _UINT64_MAX or b < 0 or b > _UINT64_MAX:
        return None
    if op == "&":
        r = a & b
    elif op == "|":
        r = a | b
    elif op == "^":
        r = a ^ b
    elif op == "<<":
        # B ≥ 64 zeroes the result. Guard the shift so we never
        # materialise a multi-exabit Python int before masking.
        r = 0 if b >= 64 else (a << b) & _UINT64_MAX
    elif op == ">>":
        r = 0 if b >= 64 else a >> b
    else:
        return None
    return _int_const(r)


def _fold_bitwise_not(inputs: list[Const]) -> Optional[Const]:
    """uint64 bitwise NOT: ``~a == (2^64-1) - a``."""
    if len(inputs) != 1:
        return None
    a = _int_from_const(inputs[0])
    if a is None or a < 0 or a > _UINT64_MAX:
        return None
    return _int_const(_UINT64_MAX - a)


def _fold_cmp(op: str, inputs: list[Const]) -> Optional[Const]:
    if len(inputs) != 2:
        return None
    a, b = inputs[0], inputs[1]
    if a is None or b is None:
        return None
    if a.kind == "int" and b.kind == "int":
        x, y = int(a.value), int(b.value)
    elif a.kind == "bytes" and b.kind == "bytes":
        bx = _bytes_from_const(a)
        by = _bytes_from_const(b)
        if bx is None or by is None:
            return None
        # b-prefixed comparisons treat bytes as big-endian unsigned ints.
        if op.startswith("b"):
            x = int.from_bytes(bx, "big")
            y = int.from_bytes(by, "big")
        else:
            x, y = bx, by
    else:
        return None
    bare = op.lstrip("b")
    if bare == "==":
        return _int_const(1 if x == y else 0)
    if bare == "!=":
        return _int_const(1 if x != y else 0)
    if bare == "<":
        return _int_const(1 if x < y else 0)
    if bare == "<=":
        return _int_const(1 if x <= y else 0)
    if bare == ">":
        return _int_const(1 if x > y else 0)
    if bare == ">=":
        return _int_const(1 if x >= y else 0)
    return None


def _fold_global_field(immediates: str) -> Optional[Const]:
    """Resolve a ``global FIELD`` opcode to its known compile-time
    literal where the AVM spec fixes the value. Currently:

    - ``ZeroAddress`` → 32 bytes of zero (the canonical zero address).

    The other ``Global FIELD``s are either runtime (``LatestTimestamp``,
    ``Round``, ``GroupSize``, ``GroupID``, ``CallerApplicationID``,
    ``OpcodeBudget``, …) or protocol-config-dependent (``MinTxnFee``,
    ``MinBalance``, ``MaxTxnLife``, ``LogicSigVersion``) which the QL
    libs don't fold to a literal either."""
    field = immediates.strip()
    if field == "ZeroAddress":
        # 32 zero bytes — AVM's canonical zero address. Matches
        # ``BytesPropagation.qll::zeroAddressHex()``.
        return Const("bytes", "0x" + "00" * 32)
    return None


def fold_spec_fixed(a: Assignment) -> Optional[Const]:
    """Resolve opcodes whose value is fixed by the AVM spec (no
    arithmetic / no inputs required). Currently only ``global
    ZeroAddress``, but the dispatch is intentionally separate from
    :func:`try_fold_assignment` because this set of folds is safe to
    run during SSA construction (no dependency on prior
    const-resolution of inputs) — whereas ``try_fold_assignment``
    expects all inputs to be const-resolved already."""
    if a.op == "global":
        return _fold_global_field(a.immediates)
    return None


def _fold_logical(op: str, inputs: list[Const]) -> Optional[Const]:
    vals = [_int_from_const(c) for c in inputs]
    if any(v is None for v in vals):
        return None
    if op == "!":
        if len(vals) != 1:
            return None
        return _int_const(0 if vals[0] else 1)
    if op == "&&":
        if len(vals) != 2:
            return None
        return _int_const(1 if all(vals) else 0)
    if op == "||":
        if len(vals) != 2:
            return None
        return _int_const(1 if any(vals) else 0)
    return None


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def try_fold_assignment(a: Assignment) -> Optional[Const]:
    """Return the computed :class:`Const` for the (single) output of a
    foldable opcode when every input is statically known, else ``None``.

    Two-output ops (``addw``, ``mulw``, etc.) aren't folded yet — their
    output split would need a tuple return; the helpers above only
    cover single-output ops.
    """
    op = a.op
    if not a.outputs or len(a.outputs) != 1:
        return None
    # ``global FIELD`` and ``txn FIELD`` have no stack inputs; resolve
    # them from the immediate alone. Mirrors what
    # ``BytesPropagation.qll`` / ``ConstantPropagation.qll`` do via
    # ``tryAsBytesDef`` / ``tryAsIntDef``. Without this, dropping
    # ``mustValues.ql`` from the load path loses field-constant
    # resolution and breaks downstream rendering (e.g.
    # ``Global ZeroAddress`` comparisons).
    if op == "global":
        return _fold_global_field(a.immediates)
    inputs: list[Const] = []
    for x in a.inputs:
        if isinstance(x, Const):
            inputs.append(x)
            continue
        cv = getattr(x, "const_value", None)
        if cv is None:
            return None
        inputs.append(cv)
    # ``Assignment.inputs`` are top-first (inputs[0] = topmost popped), but
    # every folder below is written deepest-first (``inputs[0]`` = the deeper
    # stack value ``A`` of ``A op B``). Reverse once so the folders see the
    # operand order they assume — without this, non-commutative ops (``-``,
    # ``/``, ``%``, shifts, ``concat``, ``extract*``, ``getbyte``, the
    # inequality comparisons, …) fold with their operands swapped.
    inputs.reverse()
    if op == "concat":
        return _fold_concat(inputs)
    if op == "extract":
        return _fold_extract_imm(inputs, a.immediates)
    if op == "extract3":
        return _fold_extract3(inputs)
    if op == "substring":
        return _fold_substring_imm(inputs, a.immediates)
    if op == "substring3":
        return _fold_substring3(inputs)
    if op == "extract_uint16":
        return _fold_extract_uint(inputs, 2)
    if op == "extract_uint32":
        return _fold_extract_uint(inputs, 4)
    if op == "extract_uint64":
        return _fold_extract_uint(inputs, 8)
    if op == "itob":
        return _fold_itob(inputs)
    if op == "btoi":
        return _fold_btoi(inputs)
    if op == "len":
        return _fold_len(inputs)
    if op == "bzero":
        return _fold_bzero(inputs)
    if op == "getbyte":
        return _fold_getbyte(inputs)
    if op == "setbyte":
        return _fold_setbyte(inputs)
    if op in ("+", "-", "*", "/", "%"):
        return _fold_int_arith(op, inputs)
    if op in ("&", "|", "^", "<<", ">>"):
        return _fold_bitwise(op, inputs)
    if op == "~":
        return _fold_bitwise_not(inputs)
    if op in (
        "==", "!=", "<", "<=", ">", ">=",
        "b==", "b!=", "b<", "b<=", "b>", "b>=",
    ):
        return _fold_cmp(op, inputs)
    if op in ("!", "&&", "||"):
        return _fold_logical(op, inputs)
    return None
