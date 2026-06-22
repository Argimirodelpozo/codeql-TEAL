"""Operand → producing-assignment helpers — one source of truth for the
"is this SSAVar produced by op X (with immediate Y)?" question.

The shape ``isinstance(op, SSAVar) and op.defined_by is not None and
op.defined_by.op == NAME and op.defined_by.immediates.strip() == FIELD`` was
hand-rolled across detectors and passes (``_is_txn_sender``,
``_is_caller_app_id``, ``detections.common._is_txn_field_var`` /
``_is_global_field_var`` …). These two helpers replace them — the producer-side
analogue of the operand→constant helpers in :mod:`tealtools.ssa.operands`.
"""
from __future__ import annotations

from typing import Optional

from .models import Assignment, SSAVar


def producing_op(op) -> Optional[Assignment]:
    """The :class:`Assignment` that defines ``op``, or ``None`` when ``op`` has
    no producer — a :class:`Const`, a :class:`Phi` (it *is* a definition, not a
    producer), or an SSAVar with no ``defined_by``."""
    if isinstance(op, SSAVar):
        return op.defined_by
    return None


def is_field_var(op, op_name: str, field: Optional[str] = None) -> bool:
    """``True`` when ``op`` is the SSAVar produced by opcode ``op_name`` — and,
    when ``field`` is given, whose (stripped) immediates equal ``field``.

    Covers the field-read guard shapes: ``txn Sender``, ``global
    CallerApplicationID``, ``global CreatorAddress``, etc. ``field=None`` matches
    any immediate (e.g. just "is this a ``balance`` op result?")."""
    a = producing_op(op)
    if a is None or a.op != op_name:
        return False
    return field is None or a.immediates.strip() == field
