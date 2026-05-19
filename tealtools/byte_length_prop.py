"""Byte-length propagation — populate ``TealType.byte_length`` on
output SSAVars / Phis whose length is statically derivable from the
producing op's semantics.

Independent, idempotent, opt-in (not part of
:func:`tealtools.experimental_2.passes.run_all_passes`). Best run
after :meth:`tealtools.ssa.SSAProgram.propagate_constants` so any
``Const("bytes", ...)`` literals already on producers' ``const_value``
can seed the analysis directly; the entry point lazy-trips
``propagate_constants`` if it hasn't run.

Op semantics covered (forward, single-output bytes producers):

  - ``itob X``                  → 8 bytes (TEAL spec: itob outputs a
                                  big-endian 8-byte encoding of the
                                  popped uint64).
  - ``bzero N``                 → N bytes when the popped count is a
                                  resolved constant int.
  - ``extract A B``             → B bytes when B != 0; otherwise
                                  ``len(input) - A`` if the input has
                                  a known byte_length.
  - ``substring A B``           → ``B - A`` bytes.
  - ``concat X Y``              → ``len(X) + len(Y)`` when both inputs
                                  have a known byte_length.
  - ``extract3 X A B``          → B bytes when B is a const int on the
                                  stack.
  - ``substring3 X A B``        → ``B - A`` bytes when A and B are
                                  both const ints on the stack.
  - ``setbyte X i b``           → preserves ``len(X)``.
  - ``replace2 A X V``          → preserves ``len(X)`` (X is input[0]).
  - ``replace3 X A V``          → preserves ``len(X)`` (X is input[0]).
  - ``sha256`` / ``sha512_256``
    / ``keccak256`` / ``sha3_256``  → 32 bytes (AVM hash digests have
                                  fixed output width).
  - Any output already resolved to a ``Const("bytes", "0x..")`` via
    :meth:`propagate_constants` has its length lifted directly from
    the hex literal.

A phi gets a byte_length only when every arg has the *same* known
byte_length (intersect, not union — disagreeing args mean the value
can be one of several lengths at runtime, so the static length is
unknown). Iterated to fixed point so multi-hop chains converge.

Mutates the SSA in place: sets :attr:`SSAVar.type` /
:attr:`Phi.type` to ``TealType("bytes", byte_length=N)``. Never
overwrites an existing ``byte_length`` (so multiple calls converge).

Not included here, deferred to follow-up passes:

  - Inverse range constraints (e.g. ``btoi(X)`` succeeding ⇒
    ``len(X) ∈ [1, 8]``).
  - Forward range arithmetic through ``+`` / ``-`` / ``*``.
  - Length-preserving ops (``setbyte``, ``replace2``, ``replace3``)
    and stack-indexed extract / substring variants.
"""
from __future__ import annotations

from typing import Optional

from .ssa import Assignment, Const, Phi, SSAProgram, SSAVar, TealType


def _const_bytes_length(c: Optional[Const]) -> Optional[int]:
    """Length in bytes of a ``Const("bytes", "0x...")`` literal, or
    ``None`` if the operand isn't a parseable bytes constant."""
    if c is None or c.kind != "bytes":
        return None
    h = c.value
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    if len(h) % 2 != 0:
        return None
    try:
        bytes.fromhex(h)
    except ValueError:
        return None
    return len(h) // 2


def _const_int_value(c: Optional[Const]) -> Optional[int]:
    if c is None or c.kind != "int":
        return None
    try:
        return int(c.value)
    except (TypeError, ValueError):
        return None


def _operand_const(operand) -> Optional[Const]:
    """Resolve an Assignment input operand to a :class:`Const`, either
    directly (the literal is on the operand itself) or transitively
    via :attr:`SSAVar.const_value` / :attr:`Phi.const_value` set by
    :meth:`SSAProgram.propagate_constants`."""
    if isinstance(operand, Const):
        return operand
    return getattr(operand, "const_value", None)


def _operand_byte_length(operand) -> Optional[int]:
    """Known byte_length of an input operand, looking at (a) its
    TealType if set by a prior pass / iteration, then (b) its
    ``const_value`` if it's a bytes literal, then (c) the operand
    itself if it's a :class:`Const` bytes literal."""
    t = getattr(operand, "type", None)
    if t is not None and t.kind == "bytes" and t.byte_length is not None:
        return t.byte_length
    return _const_bytes_length(_operand_const(operand))


def _op_byte_length(a: Assignment) -> Optional[int]:
    """Compute the output byte_length implied by ``a``'s op semantics,
    or ``None`` when the length isn't statically derivable yet (an
    input is missing its byte_length, an immediate is malformed, etc.).
    """
    # Output of a const-folded bytes literal: lift the length straight
    # from the hex value.
    if a.const is not None and a.const.kind == "bytes":
        return _const_bytes_length(a.const)

    op = a.op

    if op == "itob":
        return 8

    if op == "bzero":
        if len(a.inputs) != 1:
            return None
        n = _const_int_value(_operand_const(a.inputs[0]))
        if n is None or n < 0:
            return None
        return n

    if op == "extract":
        # Immediate form: ``extract A B``. ``B == 0`` means "to end of
        # input", so we need the input's known byte_length to compute.
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
        # Immediate form: ``substring A B`` → bytes[A:B], length B - A.
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
        # Stack form: (X, A, B) → bytes[A : A + B]. Output length is B
        # when the count is a const int.
        if len(a.inputs) != 3:
            return None
        n = _const_int_value(_operand_const(a.inputs[2]))
        if n is None or n < 0:
            return None
        return n

    if op == "substring3":
        # Stack form: (X, A, B) → bytes[A : B]. Need both endpoints
        # const to know the length.
        if len(a.inputs) != 3:
            return None
        start = _const_int_value(_operand_const(a.inputs[1]))
        end = _const_int_value(_operand_const(a.inputs[2]))
        if start is None or end is None or end < start:
            return None
        return end - start

    # Length-preserving ops: result inherits input[0]'s byte_length.
    if op in ("setbyte", "replace2", "replace3"):
        if not a.inputs:
            return None
        return _operand_byte_length(a.inputs[0])

    # Fixed-width hash digests.
    if op in ("sha256", "sha512_256", "keccak256", "sha3_256"):
        return 32

    return None


def _set_byte_length(obj, n: int) -> bool:
    """Set ``obj.type`` to ``TealType("bytes", byte_length=n)`` if it's
    not already set with that length. Returns True when a change was
    made (to drive the fixed-point loop)."""
    existing = getattr(obj, "type", None)
    if existing is not None and existing.kind == "bytes" \
            and existing.byte_length is not None:
        return False
    obj.type = TealType("bytes", byte_length=n)
    return True


def propagate_byte_lengths(prog: SSAProgram) -> int:
    """Walk ``prog`` to a fixed point, seeding ``TealType.byte_length``
    on outputs of bytes-producing ops whose length is statically
    derivable. Returns the number of SSAVars / Phis tagged."""
    if not getattr(prog, "_consts_propagated", False):
        prog.propagate_constants()

    tagged = 0
    changed = True
    while changed:
        changed = False

        for a in prog.assignments:
            if len(a.outputs) != 1:
                continue
            out = a.outputs[0]
            if not isinstance(out, SSAVar):
                continue
            existing = out.type
            if existing is not None and existing.kind == "bytes" \
                    and existing.byte_length is not None:
                continue
            n = _op_byte_length(a)
            if n is None or n < 0:
                continue
            if _set_byte_length(out, n):
                tagged += 1
                changed = True

        for ph in prog.phis.values():
            existing = ph.type
            if existing is not None and existing.kind == "bytes" \
                    and existing.byte_length is not None:
                continue
            if not ph.args:
                continue
            lengths = []
            ok = True
            for arg in ph.args:
                la = _operand_byte_length(arg)
                if la is None:
                    ok = False
                    break
                lengths.append(la)
            if not ok or not lengths:
                continue
            if not all(l == lengths[0] for l in lengths):
                continue
            if _set_byte_length(ph, lengths[0]):
                tagged += 1
                changed = True

    return tagged
