"""Operand → compile-time-constant resolution — one source of truth.

HAZARD: for an SSAVar / Phi these read ``const_value``, which is set by
:meth:`SSAProgram.propagate_constants` (a Phi gets one when every arg agrees).
Query them before that pass has run and every non-literal looks non-constant.

Also home to :func:`imm0`, the immediate-token sibling (assignment → first
immediate as int) — it was re-rolled per-module before landing here.
"""
from __future__ import annotations

from typing import Optional

from .models import Const


def imm0(a) -> Optional[int]:
    """First immediate of an assignment as an int (scratch slot / frame index /
    ``proto`` count), or ``None`` when absent or non-numeric."""
    toks = (a.immediates or "").split()
    if not toks:
        return None
    try:
        return int(toks[0])
    except ValueError:
        return None


def operand_const(op) -> Optional[Const]:
    """The :class:`Const` ``op`` resolves to, or ``None`` when not statically known."""
    if isinstance(op, Const):
        return op
    cv = getattr(op, "const_value", None)
    return cv if isinstance(cv, Const) else None


def const_int(op) -> Optional[int]:
    """The uint64 value ``op`` resolves to, or ``None`` when it isn't a known int."""
    c = operand_const(op)
    if c is None or c.kind != "int":
        return None
    try:
        return int(c.value)
    except (TypeError, ValueError):
        return None


def const_bytes(op) -> Optional[str]:
    """The bytes value ``op`` resolves to, as the SSA-normalised ``0x``-hex form
    every literal (``addr`` / ``byte "s"`` / ``byte b64 ..``) is folded to — or
    ``None`` when it isn't a statically-known bytes literal."""
    c = operand_const(op)
    if c is None or c.kind != "bytes":
        return None
    return c.value


def const_byte_length(op) -> Optional[int]:
    """The length in bytes of the constant ``op`` resolves to, or ``None``."""
    v = const_bytes(op)
    if v is None or not v.startswith("0x"):
        return None
    return (len(v) - 2) // 2


def is_const(op) -> bool:
    """``True`` when ``op`` resolves to any compile-time constant."""
    return operand_const(op) is not None


def binary_operands(a) -> "Optional[tuple]":
    """The ``(lhs, rhs)`` of a 2-input opcode in SOURCE order (``a b <`` ⇒ ``a < b``),
    or ``None`` unless it has exactly two inputs.

    HAZARD: SSA ``Assignment.inputs`` are TOP-FIRST — ``inputs[0]`` is the topmost
    popped value, i.e. the SECOND source operand — so ``lhs = inputs[1]`` and
    ``rhs = inputs[0]``. Hand-rolling that swap the wrong way round is an invisible
    correctness bug in every comparison / non-commutative decoder; use this."""
    if len(a.inputs) != 2:
        return None
    return a.inputs[1], a.inputs[0]


def source_operands(a) -> tuple:
    """Every operand of ``a`` in SOURCE order — the n-ary :func:`binary_operands`.

    ``extract3`` is pushed ``buf start len``, so this returns
    ``(buf, start, len)`` where ``a.inputs`` holds ``(len, start, buf)``.

    Use this, and NAME the result something other than ``inputs``. The recurring
    defect in this codebase is not the top-first convention itself — it is that
    a reversed copy kept the name ``inputs``, so the identical expression
    ``inputs[0]`` meant the topmost value in one module and the deepest in
    another, distinguishable only by reading a docstring in a third."""
    return tuple(reversed(a.inputs))
