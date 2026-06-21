"""Byte-length propagation — populate ``TealType.byte_length`` on
output SSAVars / Phis whose length is statically derivable from the
producing op's semantics.

Independent, idempotent, opt-in (not part of
:func:`tealtools.passes.run_all_passes`). Best run
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
  - Any ``txn`` / ``gtxn*`` / ``itxn*`` / ``gitxn*`` form (via
    :func:`_txn_field_name`) reading a fixed-width bytes field — 32-byte
    addresses incl. the ``Accounts`` array element + ``Lease`` / ``VotePK``
    / ``SelectionPK``, 64-byte ``StateProofPK`` — from
    ``_TXN_FIELD_BYTELEN``; ``global`` address fields from
    ``_GLOBAL_FIELD_BYTELEN``.
  - ``*_params_get`` value output (``outputs[1]``) for address / hash
    fields (``AppAddress``, ``AssetManager``, ``AcctAuthAddr``, …) from
    the field-keyed ``_PARAMS_VALUE_BYTELEN``.
  - ``ecdsa_pk_decompress`` / ``ecdsa_pk_recover`` (both outputs 32) and
    ``vrf_verify`` (64-byte output) — *multi*-output ops, seeded
    positionally from ``_OP_OUTPUT_BYTELEN``.
  - Any output already resolved to a ``Const("bytes", "0x..")`` via
    :meth:`propagate_constants` has its length lifted directly from
    the hex literal.

A phi gets an exact byte_length only when every arg has the *same*
known byte_length (intersect, not union — disagreeing args mean the
value can be one of several lengths at runtime, so the exact static
length is unknown). When the exact lengths disagree but the args all
have known length *ranges*, the phi adopts the union — a strictly
looser bound, but still useful for downstream consumers that just
want "at most this many bytes". Iterated to fixed point so multi-hop
chains converge.

Inverse range constraints (item 3): a single forward op whose
successful execution constrains the byte_length of one of its inputs
also installs a ``byte_length_range`` on that input:

  - ``btoi(X)``                 → ``len(X) ∈ [1, 8]``.
  - ``getbyte(X, i)`` (i const) → ``len(X) ≥ i + 1``.
  - ``extract_uint16/32/64(X, i)`` (i const) → ``len(X) ≥ i + 2/4/8``.
  - ``extract A B X``            → ``len(X) ≥ A + B``.
  - ``substring A B X``          → ``len(X) ≥ B``.
  - ``extract3 X A B`` (A, B const) → ``len(X) ≥ A + B``.
  - ``substring3 X A B`` (B const)  → ``len(X) ≥ B``.
  - ``setbyte X i b`` (i const) → ``len(X) ≥ i + 1``.

The constraints intersect with anything already on the input's
``byte_length_range`` (so multiple ops on the same SSAVar tighten
the bound). Constraints are deliberately *not* applied when the
input already has an exact ``byte_length`` — the exact value is
strictly stronger.

Mutates the SSA in place: sets :attr:`SSAVar.type` /
:attr:`Phi.type` to ``TealType("bytes", byte_length=N,
byte_length_range=IntRange(N, N))`` for the exact case, or
``TealType("bytes", byte_length_range=IntRange(lo, hi))`` for the
ranged case.
"""
from __future__ import annotations

import functools
from collections import deque
from typing import Optional

from ..ssa import Assignment, Const, IntRange, Phi, SSAProgram, SSAVar, TealType
from ..ssa.models import (
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
    """Byte length of a ``0x...`` hex literal, or ``None`` if unparseable.
    Cached: a constant's length is immutable, but the naive byte-length fixpoint
    re-derives it for every operand on every iteration -- tens of millions of
    times on large contracts (40M ``fromhex`` re-parses on folks-v3)."""
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
    """Length in bytes of a ``Const("bytes", "0x...")`` literal, or
    ``None`` if the operand isn't a parseable bytes constant."""
    if c is None or c.kind != "bytes":
        return None
    return _hex_byte_length(c.value)


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

    # Fixed-width bytes fields (32-byte addresses / keys, 64-byte
    # StateProofPK) read off the txn-family or global field tables.
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
    """Best-known length range for an operand. An exact byte_length
    (from :func:`_operand_byte_length`) is returned as ``[N, N]``;
    otherwise the operand's ``type.byte_length_range`` if set."""
    n = _operand_byte_length(operand)
    if n is not None:
        return IntRange(n, n)
    t = getattr(operand, "type", None)
    if t is not None and t.kind == "bytes" and t.byte_length_range is not None:
        return t.byte_length_range
    return None


def _set_byte_length(obj, n: int) -> bool:
    """Set ``obj.type`` to ``TealType("bytes", byte_length=n,
    byte_length_range=IntRange(n, n))`` if it's not already set with
    that length. Returns True when a change was made (to drive the
    fixed-point loop)."""
    existing = getattr(obj, "type", None)
    if existing is not None and existing.kind == "bytes" \
            and existing.byte_length is not None:
        return False
    obj.type = TealType(
        "bytes",
        byte_length=n,
        byte_length_range=IntRange(n, n),
    )
    return True


def _set_byte_length_range(obj, lo: int, hi: int) -> bool:
    """Install or *intersect* a byte_length range on ``obj``. Honours
    an existing exact ``byte_length`` (would either confirm it or
    indicate an infeasible path — we leave it alone in either case).
    Returns True when the stored range was actually tightened so the
    fixed-point loop knows to re-iterate."""
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
        # Already pinned to an exact length; nothing to refine.
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
    )
    return True


def _input_min_length(a: Assignment) -> Optional[tuple[int, int, Optional[int]]]:
    """Return ``(input_index, min_len, max_len)`` for any op whose
    successful execution constrains the byte_length of one of its
    inputs. ``max_len`` is ``None`` when only a lower bound is known
    (it gets clamped to the bytes-stack cap by the caller). Returns
    ``None`` when the op doesn't carry a static input-length
    constraint (or its key immediates / stack operands aren't
    resolved to constants).
    """
    op = a.op

    # btoi(X) succeeds ⇒ len(X) ∈ [1, 8]. (TEAL spec: btoi panics on
    # an empty input or on length > 8.)
    if op == "btoi":
        if not a.inputs:
            return None
        return (0, 1, 8)

    # getbyte(X, i) — needs len(X) ≥ i + 1 when i is a const.
    if op == "getbyte":
        if len(a.inputs) != 2:
            return None
        idx = _const_int_value(_operand_const(a.inputs[1]))
        if idx is None or idx < 0:
            return None
        return (0, idx + 1, None)

    # extract_uint{16,32,64}(X, i) — needs len(X) ≥ i + 2/4/8.
    if op in ("extract_uint16", "extract_uint32", "extract_uint64"):
        if len(a.inputs) != 2:
            return None
        idx = _const_int_value(_operand_const(a.inputs[1]))
        if idx is None or idx < 0:
            return None
        width = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}[op]
        return (0, idx + width, None)

    # extract A B X  (immediate) — needs len(X) ≥ A + B when B != 0,
    # ≥ A when B == 0 ("to end of input").
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
            _start, end = int(toks[0]), int(toks[1])
        except ValueError:
            return None
        if end < 0:
            return None
        return (0, end, None)

    # extract3 X A B — needs len(X) ≥ A + B when both A and B are const.
    if op == "extract3":
        if len(a.inputs) != 3:
            return None
        start = _const_int_value(_operand_const(a.inputs[1]))
        length = _const_int_value(_operand_const(a.inputs[2]))
        if start is None or length is None or start < 0 or length < 0:
            return None
        return (0, start + length, None)

    # substring3 X A B — needs len(X) ≥ B when B is a const.
    if op == "substring3":
        if len(a.inputs) != 3:
            return None
        end = _const_int_value(_operand_const(a.inputs[2]))
        if end is None or end < 0:
            return None
        return (0, end, None)

    # setbyte X i b — needs len(X) ≥ i + 1 when i is a const.
    if op == "setbyte":
        if len(a.inputs) != 3:
            return None
        idx = _const_int_value(_operand_const(a.inputs[1]))
        if idx is None or idx < 0:
            return None
        return (0, idx + 1, None)

    return None


def propagate_byte_lengths(prog: SSAProgram) -> int:
    """Walk ``prog`` to a fixed point. In each iteration:

      1. Forward-propagate exact ``byte_length`` from ops whose
         output length is statically derivable.
      2. Install inverse ``byte_length_range`` constraints on inputs
         of ops whose successful execution implies a minimum length
         (``btoi``, ``getbyte``, ``extract_*``, ``setbyte``, …).
      3. Union arg lengths through phis — exact when every arg
         agrees, else the looser ``byte_length_range`` union.

    Returns the cumulative number of (byte_length, byte_length_range)
    assignments made across the fixed-point walk."""
    if not getattr(prog, "_consts_propagated", False):
        prog.propagate_constants()

    tagged = 0

    # Worklist instead of a fixpoint that re-walks all ~4M assignments + phis
    # every round: a value flows only to the assignments that use it (.uses) and
    # the phis that take it as an arg (phi_consumers), so when an operand's
    # byte_length / range changes only its consumers are re-evaluated. The
    # lattice is monotonic (byte_length set once, ranges only intersect), so the
    # least fixed point -- and the final type state -- is identical.
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

    # (1) Forward exact-length rule for one bytes-producing op.
    def do_assignment(a) -> None:
        nonlocal tagged
        # Multi-output ops with fixed-width bytes outputs (ecdsa pubkey
        # words, vrf_verify's output) — positional, top-first.
        out_lens = _OP_OUTPUT_BYTELEN.get(a.op)
        if out_lens is not None:
            for idx, n in out_lens:
                if idx < len(a.outputs):
                    out = a.outputs[idx]
                    if isinstance(out, SSAVar) and _set_byte_length(out, n):
                        tagged += 1
                        fan_out(out)
            return

        # *_params_get: the value output (outputs[1]) is a fixed-width
        # bytes value (address / metadata hash) for some fields.
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

    # (3) Phi propagation: exact-length agreement first, range union fallback.
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

    # (2) Inverse length constraints are op-only (op / immediates / const
    # operands), stable across the walk -- a one-shot seed, not in the fixpoint.
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
        hi_eff = _BYTES_STACK_CAP if hi is None else hi
        if _set_byte_length_range(target, lo, hi_eff):
            tagged += 1
            fan_out(target)

    # Seed every assignment + phi once, then propagate only to consumers.
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
