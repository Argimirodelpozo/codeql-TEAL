"""Operand → producing-assignment helpers — one source of truth for
"is this SSAVar produced by op X (with immediate Y)?".
"""
from __future__ import annotations

from typing import Optional

from .models import Assignment, SSAVar


def producing_op(op) -> Optional[Assignment]:
    """The :class:`Assignment` defining ``op``, or ``None`` for a :class:`Const`, a
    :class:`Phi` (it *is* a definition, not a producer) or an undefined SSAVar."""
    if isinstance(op, SSAVar):
        return op.defined_by
    return None


def is_field_var(op, op_name: str, field: Optional[str] = None) -> bool:
    """``True`` when ``op`` is the SSAVar produced by opcode ``op_name`` whose
    stripped immediates equal ``field`` (``field=None`` matches any immediate)."""
    a = producing_op(op)
    if a is None or a.op != op_name:
        return False
    return field is None or a.immediates.strip() == field
