"""Constant folding for SSA Assignments — the op-level half of
:meth:`SSAProgram.propagate_constants`.

HAZARD: every ``_fold_*`` helper below takes ``operands`` in SOURCE order
(``operands[0]`` = the deeper value ``A`` of ``A op B``), the reverse of raw SSA
top-first ``Assignment.inputs``; :func:`try_fold_assignment` does that reversal
once, so a new caller must too. The parameter is deliberately NOT called
``inputs``: it used to be, and an expression as ordinary as ``inputs[0]`` then
meant the topmost value everywhere else in the tree and the deepest one here,
which is the single most re-found defect in this codebase.

``None`` always means "no constant" — including on paths the AVM would halt on
(underflow, over-shift, bad slice), never a made-up value.
"""
from __future__ import annotations

from typing import Optional

from .models import Assignment, Const
from ..avm import CMP_OPS


# --- Const ↔ runtime-value helpers -----------------------------------------


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


# --- Per-op folders (operands DEEPEST-FIRST; see module header) --------------


def _fold_concat(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 2:
        return None
    a, b = _bytes_from_const(operands[0]), _bytes_from_const(operands[1])
    if a is None or b is None:
        return None
    return _bytes_const(a + b)


def _fold_extract_imm(
    operands: list[Const], immediates: str,
) -> Optional[Const]:
    if len(operands) != 1:
        return None
    src = _bytes_from_const(operands[0])
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
    if start < 0 or start > len(src) or end > len(src):
        return None
    return _bytes_const(src[start:end])


def _fold_extract3(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 3:
        return None
    src = _bytes_from_const(operands[0])
    start = _int_from_const(operands[1])
    length = _int_from_const(operands[2])
    if src is None or start is None or length is None:
        return None
    if start < 0 or start + length > len(src):
        return None
    return _bytes_const(src[start:start + length])


def _fold_substring_imm(
    operands: list[Const], immediates: str,
) -> Optional[Const]:
    if len(operands) != 1:
        return None
    src = _bytes_from_const(operands[0])
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


def _fold_substring3(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 3:
        return None
    src = _bytes_from_const(operands[0])
    start = _int_from_const(operands[1])
    end = _int_from_const(operands[2])
    if src is None or start is None or end is None:
        return None
    if start < 0 or end > len(src) or start > end:
        return None
    return _bytes_const(src[start:end])


def _fold_extract_uint(
    operands: list[Const], n_bytes: int,
) -> Optional[Const]:
    if len(operands) != 2:
        return None
    src = _bytes_from_const(operands[0])
    offset = _int_from_const(operands[1])
    if src is None or offset is None:
        return None
    if offset < 0 or offset + n_bytes > len(src):
        return None
    return _int_const(int.from_bytes(src[offset:offset + n_bytes], "big"))


def _fold_itob(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 1:
        return None
    n = _int_from_const(operands[0])
    if n is None or n < 0 or n >= 2 ** 64:
        return None
    return _bytes_const(n.to_bytes(8, "big"))


def _fold_btoi(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 1:
        return None
    src = _bytes_from_const(operands[0])
    if src is None or len(src) > 8:
        return None
    return _int_const(int.from_bytes(src, "big") if src else 0)


def _fold_len(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 1:
        return None
    src = _bytes_from_const(operands[0])
    if src is None:
        return None
    return _int_const(len(src))


def _fold_bzero(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 1:
        return None
    n = _int_from_const(operands[0])
    if n is None or n < 0 or n > 4096:
        return None
    return _bytes_const(b"\x00" * n)


def _fold_getbyte(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 2:
        return None
    src = _bytes_from_const(operands[0])
    idx = _int_from_const(operands[1])
    if src is None or idx is None or idx < 0 or idx >= len(src):
        return None
    return _int_const(src[idx])


def _fold_setbyte(operands: list[Const]) -> Optional[Const]:
    if len(operands) != 3:
        return None
    src = _bytes_from_const(operands[0])
    idx = _int_from_const(operands[1])
    val = _int_from_const(operands[2])
    if src is None or idx is None or val is None:
        return None
    if idx < 0 or idx >= len(src) or val < 0 or val > 255:
        return None
    buf = bytearray(src)
    buf[idx] = val
    return _bytes_const(bytes(buf))


def _fold_int_arith(
    op: str, operands: list[Const],
) -> Optional[Const]:
    if len(operands) != 2:
        return None
    a, b = _int_from_const(operands[0]), _int_from_const(operands[1])
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


def _fold_bitwise(op: str, operands: list[Const]) -> Optional[Const]:
    """Fold the uint64 bitwise / shift binary ops.

    HAZARD: ``operands[0]`` is the deeper stack value ``A``, ``operands[1]`` the top
    ``B`` (matching :mod:`..analysis._range_arithmetic`): ``shl`` is
    ``A * 2^B mod 2^64``, ``shr`` is ``A // 2^B``. A shift ``B > 63`` HALTS the AVM
    ("arg too big"), so it folds to ``None`` — like the ``-`` underflow case."""
    if len(operands) != 2:
        return None
    a, b = _int_from_const(operands[0]), _int_from_const(operands[1])
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
    elif op == "shl":
        if b >= 64:
            return None
        r = (a << b) & _UINT64_MAX
    elif op == "shr":
        if b >= 64:
            return None
        r = a >> b
    else:
        return None
    return _int_const(r)


def _fold_bitwise_not(operands: list[Const]) -> Optional[Const]:
    """uint64 bitwise NOT: ``~a == (2^64-1) - a``."""
    if len(operands) != 1:
        return None
    a = _int_from_const(operands[0])
    if a is None or a < 0 or a > _UINT64_MAX:
        return None
    return _int_const(_UINT64_MAX - a)


def _fold_cmp(op: str, operands: list[Const]) -> Optional[Const]:
    if len(operands) != 2:
        return None
    a, b = operands[0], operands[1]
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
            # The BARE ordered comparisons (`<` `<=` `>` `>=`) are uint64-only:
            # two bytes operands is a runtime type error, so there is no value to
            # fold (Python would answer LEXICOGRAPHICALLY). `==`/`!=` are legal.
            if op not in ("==", "!="):
                return None
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
    """The literal of a ``global FIELD`` whose value the AVM spec fixes — only
    ``ZeroAddress``; the rest are runtime or protocol-config dependent."""
    field = immediates.strip()
    if field == "ZeroAddress":
        return Const("bytes", "0x" + "00" * 32)
    return None


def fold_spec_fixed(a: Assignment) -> Optional[Const]:
    """Resolve opcodes whose value the AVM spec fixes outright, operands or not.

    HAZARD: kept separate from :func:`try_fold_assignment` because these folds
    depend on no prior const-resolution and so are safe DURING SSA construction;
    ``try_fold_assignment`` requires every input already resolved."""
    if a.op == "global":
        return _fold_global_field(a.immediates)
    return None


def _fold_logical(op: str, operands: list[Const]) -> Optional[Const]:
    vals = [_int_from_const(c) for c in operands]
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


# --- Dispatch --------------------------------------------------------------


def try_fold_assignment(a: Assignment) -> Optional[Const]:
    """The :class:`Const` computed for a foldable single-output opcode whose every
    input is statically known, else ``None``."""
    op = a.op
    if not a.outputs or len(a.outputs) != 1:
        return None
    # ``global FIELD`` has no stack operands — resolve from the immediate alone.
    if op == "global":
        return _fold_global_field(a.immediates)
    resolved: list[Const] = []
    for x in a.inputs:                       # TOP-first, per Assignment.inputs
        if isinstance(x, Const):
            resolved.append(x)
            continue
        cv = getattr(x, "const_value", None)
        if cv is None:
            return None
        resolved.append(cv)
    # The ONE reversal in this module, and the reason the folders' parameter is
    # named ``operands`` rather than ``inputs``: they read SOURCE order, where
    # [0] is the deeper value A of `A op B`, and Assignment.inputs is top-first.
    # Get it backwards and every non-commutative op (`-` `/` `%`, shifts,
    # `concat`, `extract*`, `getbyte`, the inequalities) folds with its operands
    # swapped — which is exactly the bug this codebase keeps re-finding.
    operands = resolved[::-1]
    if op == "concat":
        return _fold_concat(operands)
    if op == "extract":
        return _fold_extract_imm(operands, a.immediates)
    if op == "extract3":
        return _fold_extract3(operands)
    if op == "substring":
        return _fold_substring_imm(operands, a.immediates)
    if op == "substring3":
        return _fold_substring3(operands)
    if op == "extract_uint16":
        return _fold_extract_uint(operands, 2)
    if op == "extract_uint32":
        return _fold_extract_uint(operands, 4)
    if op == "extract_uint64":
        return _fold_extract_uint(operands, 8)
    if op == "itob":
        return _fold_itob(operands)
    if op == "btoi":
        return _fold_btoi(operands)
    if op == "len":
        return _fold_len(operands)
    if op == "bzero":
        return _fold_bzero(operands)
    if op == "getbyte":
        return _fold_getbyte(operands)
    if op == "setbyte":
        return _fold_setbyte(operands)
    if op in ("+", "-", "*", "/", "%"):
        return _fold_int_arith(op, operands)
    if op in ("&", "|", "^", "shl", "shr"):
        return _fold_bitwise(op, operands)
    if op == "~":
        return _fold_bitwise_not(operands)
    if op in CMP_OPS:
        return _fold_cmp(op, operands)
    if op in ("!", "&&", "||"):
        return _fold_logical(op, operands)
    return None
