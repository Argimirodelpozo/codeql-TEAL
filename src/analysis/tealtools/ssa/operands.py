"""Operand → compile-time-constant resolution — one source of truth.

A TEAL SSA operand is a :class:`Const` literal, an :class:`SSAVar`, or a
:class:`Phi`. Nearly every annotation pass and detector asks the same
question of one: *does it resolve to a known constant, and if so what
value?* That logic used to be copy-pasted — with subtly different names
and signatures (``_const_int`` / ``_const_int_value`` / ``_operand_const``
/ ``_is_const_like`` / ``_operand_is_constant``) — across ``range_arith``,
``byte_length_prop``, ``bytemath``, ``detections.common``,
``path_predicates``, ``xcontract`` and ``dataflow.engine``. These three
helpers replace all of them.

``const_value`` is set on SSAVars / Phis by
:meth:`SSAProgram.propagate_constants` (a Phi gets one when every arg
agrees on a literal), so resolution flows transitively through it. Each
helper accepts a bare ``Const`` too, so a caller that has already resolved
one operand can pass it straight back in.
"""
from __future__ import annotations

from typing import Optional

from .models import Const


def operand_const(op) -> Optional[Const]:
    """The :class:`Const` ``op`` resolves to — itself when it is a Const,
    else the ``const_value`` set on an SSAVar / Phi by
    :meth:`SSAProgram.propagate_constants` — or ``None`` when not
    statically known."""
    if isinstance(op, Const):
        return op
    cv = getattr(op, "const_value", None)
    return cv if isinstance(cv, Const) else None


def const_int(op) -> Optional[int]:
    """The uint64 value ``op`` resolves to, or ``None`` when it isn't a
    statically-known int-kind literal."""
    c = operand_const(op)
    if c is None or c.kind != "int":
        return None
    try:
        return int(c.value)
    except (TypeError, ValueError):
        return None


def const_bytes(op) -> Optional[str]:
    """The bytes value ``op`` resolves to (the TEAL literal form, e.g. an
    ``0x``-hex or ``base64(..)`` string), or ``None`` when it isn't a
    statically-known bytes-kind literal. The bytes analogue of
    :func:`const_int`."""
    c = operand_const(op)
    if c is None or c.kind != "bytes":
        return None
    return c.value


def is_const(op) -> bool:
    """``True`` when ``op`` resolves to any compile-time constant."""
    return operand_const(op) is not None
