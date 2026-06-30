"""Byte-interval ("partial") taint — a standalone prototype.

The live taint engine (:mod:`tealtools.dataflow.engine`) is boolean: a
bytes value is tainted or it isn't. But TEAL contracts routinely pack
several logical fields into one byte array (ABI args, length-prefixed
blobs, embedded 32-byte addresses), so whole-value taint is too coarse —
"bytes 0..7 of this arg are a validated selector, bytes 8.. are
attacker-controlled" can't be expressed.

This module tracks taint at **byte-offset granularity**: each bytes value
carries a set of tainted half-open intervals over ``[0, len)`` (an
:class:`Intervals`). The TEAL byte ops map cleanly onto interval algebra,
and the offsets/lengths the rules need come from
:meth:`SSAProgram.propagate_byte_lengths` (already in the substrate):

  - ``extract A B X`` / ``substring A B X`` → ``(taint(X) ∩ window) − A``
  - ``concat A B``                         → ``taint(A) ∪ (taint(B) + len(A))``
  - ``setbyte`` / ``replace2`` / ``replace3`` → splice
  - ``getbyte`` / ``extract_uint16/32/64``   → the byte-range → **scalar**
    bridge: the uint64 result is tainted iff any byte it reads is tainted
  - ``btoi`` / ``itob``                     → scalar ↔ first-8-bytes bridge
  - hashes (``sha256`` …)                   → a 32-byte digest, tainted iff
    the input carries any taint (attacker can steer it)

Soundness over precision: when an offset or length isn't statically known
(``extract3`` with a runtime count, an unknown-length ``concat`` prefix),
the rule falls back to whole-value taint — never a false negative, just a
lost partition. Any op without a precise rule is handled conservatively
(output tainted if any input is). This is the **forward** half; a
``range_assert``-style flow-sensitive pass that *clears* a validated
sub-range is the planned second layer.

Entry point: :func:`byte_taint`. Standalone — it does not touch the live
engine.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..ssa import Const, SSAProgram, SSAVar, const_int, operand_const
from ..ssa.models import _shuffle_mapping, _txn_field_name

INF = float("inf")  # open right end: "to the end of a (possibly unknown) value"


def _normalize(parts) -> tuple:
    """Sort, drop empties, and merge overlapping / adjacent intervals."""
    out: list = []
    for lo, hi in sorted((lo, hi) for lo, hi in parts if hi > lo):
        if out and lo <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return tuple(out)


class Intervals:
    """An immutable set of half-open ``[lo, hi)`` byte intervals (``hi`` may
    be :data:`INF`), kept normalized: sorted, disjoint, non-adjacent."""

    __slots__ = ("parts",)

    def __init__(self, parts=()):
        self.parts = _normalize(parts)

    @classmethod
    def empty(cls) -> "Intervals":
        return cls()

    @classmethod
    def whole(cls, length: Optional[float] = None) -> "Intervals":
        """``[0, length)`` — or ``[0, INF)`` when the length is unknown."""
        return cls([(0, INF if length is None else length)])

    def __bool__(self) -> bool:
        return bool(self.parts)

    def __eq__(self, other) -> bool:
        return isinstance(other, Intervals) and self.parts == other.parts

    def __hash__(self) -> int:
        return hash(self.parts)

    def union(self, other: "Intervals") -> "Intervals":
        return Intervals(self.parts + other.parts)

    def intersect(self, other: "Intervals") -> "Intervals":
        out = []
        for a0, a1 in self.parts:
            for b0, b1 in other.parts:
                lo, hi = max(a0, b0), min(a1, b1)
                if lo < hi:
                    out.append((lo, hi))
        return Intervals(out)

    def clip(self, lo: float, hi: float) -> "Intervals":
        """Restrict to the window ``[lo, hi)``."""
        return Intervals((max(p0, lo), min(p1, hi)) for p0, p1 in self.parts)

    def subtract(self, lo: float, hi: float) -> "Intervals":
        """Remove the window ``[lo, hi)`` (used by splice ops)."""
        out = []
        for p0, p1 in self.parts:
            if p0 < lo:
                out.append((p0, min(p1, lo)))
            if p1 > hi:
                out.append((max(p0, hi), p1))
        return Intervals(out)

    def shift(self, d: float) -> "Intervals":
        """Translate every interval by ``d`` (``INF`` stays ``INF``)."""
        return Intervals((lo + d, hi + d) for lo, hi in self.parts)

    def minus(self, other: "Intervals") -> "Intervals":
        """Set difference: ``self`` with every interval of ``other`` removed
        (used by the validation pass to clear checked sub-ranges)."""
        result = self
        for lo, hi in other.parts:
            result = result.subtract(lo, hi)
        return result

    def overlaps(self, lo: float, hi: float) -> bool:
        """Does any interval intersect ``[lo, hi)``?"""
        return any(p0 < hi and lo < p1 for p0, p1 in self.parts)

    def __repr__(self) -> str:
        if not self.parts:
            return "∅"
        return ",".join(
            f"[{lo}:{'∞' if hi == INF else hi})" for lo, hi in self.parts
        )


def _byte_length(op) -> Optional[int]:
    """Exact byte length of an operand — from the ``byte_length`` that
    :func:`propagate_byte_lengths` pinned, else from a bytes ``const_value``
    (a literal ``byte 0x..`` carries its length even when the length pass
    didn't tag the SSAVar). ``None`` when unknown → caller falls back
    conservatively."""
    t = getattr(op, "type", None)
    if t is not None and getattr(t, "byte_length", None) is not None:
        return t.byte_length
    cv = op if isinstance(op, Const) else getattr(op, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "bytes":
        from ..passes.byte_length_prop import _const_bytes_length
        return _const_bytes_length(cv)
    return None


def _default_sources(a) -> Optional[Intervals]:
    """Default attacker-input seed: every ``ApplicationArgs`` read is fully
    tainted (its length is usually dynamic, so ``[0, INF)``)."""
    if not a.immediates:
        return None
    if _txn_field_name(a.op, a.immediates.split()) == "ApplicationArgs":
        out = a.outputs[0] if a.outputs else None
        return Intervals.whole(_byte_length(out) if out is not None else None)
    return None


_HASH_OPS = frozenset({"sha256", "sha512_256", "keccak256", "sha3_256"})
_EXTRACT_UINT = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}
# Bytes-PRODUCING ops with no precise byte-interval rule: the conservative
# fallback must record byte taint, not scalar (json_ref is excluded -- it is
# polymorphic on its immediate, e.g. JSONUint64 -> uint64).
_BYTES_OUT_FALLBACK = frozenset({
    "b+", "b-", "b*", "b/", "b%", "bsqrt",      # bigint arithmetic
    "b|", "b&", "b^", "b~", "bzero",            # bytewise
    "base64_decode",
})


def _slice_of(v) -> Optional[tuple]:
    """If SSAVar ``v`` is a *static* byte-slice read of some value ``X`` —
    ``extract`` / ``substring`` (immediate or stack-const), ``getbyte``,
    ``extract_uint16/32/64`` — return ``(X, lo, hi)``: the byte window of X
    it reads. ``None`` when the offsets aren't statically known."""
    d = getattr(v, "defined_by", None)
    if d is None:
        return None
    op = d.op
    if op == "extract" and d.immediates and d.inputs:
        toks = d.immediates.split()
        if len(toks) == 2:
            A, B = int(toks[0]), int(toks[1])
            X = d.inputs[0]
            return (X, A, (_byte_length(X) or INF) if B == 0 else A + B)
    if op == "substring" and d.immediates and d.inputs:
        toks = d.immediates.split()
        if len(toks) == 2:
            return (d.inputs[0], int(toks[0]), int(toks[1]))
    if op in ("extract3", "substring3") and len(d.inputs) == 3:
        A, B = const_int(d.inputs[1]), const_int(d.inputs[0])
        if A is not None and B is not None:
            return (d.inputs[2], A, A + B if op == "extract3" else B)
    if op == "getbyte" and len(d.inputs) == 2:
        i = const_int(d.inputs[0])
        if i is not None:
            return (d.inputs[1], i, i + 1)
    if op in _EXTRACT_UINT and len(d.inputs) == 2:
        i = const_int(d.inputs[0])
        if i is not None:
            return (d.inputs[1], i, i + _EXTRACT_UINT[op])
    return None


def _validated_intervals(prog: SSAProgram) -> dict:
    """``value -> Intervals`` proven NOT attacker-controlled by
    ``assert(slice(X) == const)`` guards, flow-sensitively.

    A guard pinning a static slice of X to a compile-time constant means
    those bytes can't be attacker-chosen past the assert (the txn fails
    otherwise). We clear them from X's taint **globally** only when every
    *other* use of X is dominated by the assert — the same soundness
    contract as :mod:`tealtools.passes.range_assert` (a use reachable
    without passing the guard would otherwise lose taint unsoundly).
    Dominance is approximated by reachability-without-the-assert-block on
    the raw interprocedural CFG (over-approximates → conservative)."""
    from ..passes.range_assert import _all_blocks, _reachable_avoiding

    entries = [b for b in _all_blocks(prog) if not b.predecessors]
    if not entries:
        return {}
    dom_cache: dict = {}

    def dominates(block_a, use, line: int) -> bool:
        ub = use.basic_block
        if ub is None:
            return False
        if ub is block_a:
            return use.location.line > line
        reach = dom_cache.get(block_a)
        if reach is None:
            reach = dom_cache[block_a] = _reachable_avoiding(entries, block_a)
        return ub not in reach

    out: dict = {}
    for a in prog.assignments:
        if a.op != "assert" or not a.inputs:
            continue
        block_a = a.basic_block
        if block_a is None:
            continue
        d = getattr(a.inputs[0], "defined_by", None)
        if d is None or d.op != "==" or len(d.inputs) != 2:
            continue
        lhs, rhs = d.inputs[1], d.inputs[0]
        slc = win = None
        for s, other in ((lhs, rhs), (rhs, lhs)):
            if operand_const(other) is not None and isinstance(s, SSAVar):
                info = _slice_of(s)
                if info is not None:
                    slc, win = s, info
                    break
        if win is None:
            continue
        x, lo, hi = win
        if not isinstance(x, SSAVar):
            continue
        test = {getattr(slc, "defined_by", None)}
        if all(dominates(block_a, u, a.location.line)
               for u in x.uses if u not in test):
            out.setdefault(x, []).append((lo, hi))
    return {v: Intervals(parts) for v, parts in out.items()}


class ByteTaintResult:
    """The fixpoint result: per-value tainted byte intervals + the set of
    tainted scalar (uint64) values produced by the byte→scalar bridges."""

    def __init__(self, bytes_taint: dict, scalar_taint: set):
        self.bytes_taint = bytes_taint
        self.scalar_taint = scalar_taint

    def tainted_bytes(self, value) -> Intervals:
        return self.bytes_taint.get(value, Intervals.empty())

    def is_scalar_tainted(self, value) -> bool:
        return value in self.scalar_taint

    def report(self) -> str:
        lines = ["byte-interval taint:"]
        for v, iv in sorted(
            self.bytes_taint.items(),
            key=lambda kv: (getattr(kv[0], "location", None).line
                            if getattr(kv[0], "location", None) else 0),
        ):
            if iv:
                lines.append(f"  {v}: {iv}")
        if self.scalar_taint:
            lines.append(f"  tainted scalars: {len(self.scalar_taint)}")
        return "\n".join(lines)


def byte_taint(
    prog: SSAProgram,
    *,
    sources: Optional[Callable] = None,
    validate: bool = False,
) -> ByteTaintResult:
    """Forward byte-interval taint to a fixed point.

    ``sources(assignment) -> Optional[Intervals]`` seeds an output value's
    initial taint (default: ``ApplicationArgs`` reads, fully tainted). Trips
    :meth:`propagate_constants` + :meth:`propagate_byte_lengths` first so the
    slice offsets and concat lengths the rules read are in place.

    ``validate=True`` adds the flow-sensitive **validation-narrowing** layer:
    a sub-range of a value pinned to a constant by an ``assert(slice == const)``
    guard is cleared from its taint (so e.g. a checked ABI selector / magic
    prefix stops a downstream read of those bytes from being flagged). It
    first runs :meth:`propagate_inputs` + :meth:`propagate_stack_shuffles` so
    the validated value and its downstream reads share one canonical SSAVar
    (in a stack machine they otherwise diverge across dups / re-reads). See
    :func:`_validated_intervals` for the soundness contract."""
    prog.propagate_constants()
    if validate:
        prog.propagate_inputs()
        prog.propagate_stack_shuffles()
    prog.propagate_byte_lengths()
    seed = sources or _default_sources
    validated = _validated_intervals(prog) if validate else {}

    bt: dict = {}     # value -> Intervals (tainted byte ranges)
    st: set = set()   # scalar (uint64) values that are tainted

    def bget(op) -> Intervals:
        return Intervals.empty() if isinstance(op, Const) else bt.get(op, Intervals.empty())

    def sget(op) -> bool:
        return (not isinstance(op, Const)) and op in st

    def any_tainted(a) -> bool:
        return any(bool(bget(i)) or sget(i) for i in a.inputs)

    def set_bytes(out, iv: Intervals) -> bool:
        v = validated.get(out)
        if v is not None:
            iv = iv.minus(v)        # clear validated (checked) byte ranges
        if not iv:
            return False
        old = bt.get(out)
        new = old.union(iv) if old is not None else iv
        if old is None or new != old:
            bt[out] = new
            return True
        return False

    def set_scalar(out) -> bool:
        if out not in st:
            st.add(out)
            return True
        return False

    def flow(a) -> bool:
        if not a.outputs:
            return False
        op = a.op

        # Stack shuffles (dup / swap / dig / frame_*): copy each output's
        # taint from its mapped source operand — intervals and scalar alike.
        sm = _shuffle_mapping(a)
        if sm is not None:
            changed = False
            for oi, ii in enumerate(sm):
                if oi < len(a.outputs) and ii < len(a.inputs):
                    src, dst = a.inputs[ii], a.outputs[oi]
                    changed = set_bytes(dst, bget(src)) or changed
                    if sget(src):
                        changed = set_scalar(dst) or changed
            return changed

        out = a.outputs[0]
        s = seed(a)
        if s is not None:
            return set_bytes(out, s)

        # ---- bytes -> bytes (precise slice / concat / splice) ----
        if op == "extract" and a.immediates:                       # extract A B X
            toks = a.immediates.split()
            if len(toks) == 2 and a.inputs:
                A, B = int(toks[0]), int(toks[1])
                hi = INF if B == 0 else A + B
                return set_bytes(out, bget(a.inputs[0]).clip(A, hi).shift(-A))
        if op == "substring" and a.immediates:                     # substring A B X
            toks = a.immediates.split()
            if len(toks) == 2 and a.inputs:
                A, B = int(toks[0]), int(toks[1])
                return set_bytes(out, bget(a.inputs[0]).clip(A, B).shift(-A))
        if op in ("extract3", "substring3") and len(a.inputs) == 3:
            x = a.inputs[2]
            A = const_int(a.inputs[1])
            B = const_int(a.inputs[0])
            if A is not None and B is not None:
                hi = A + B if op == "extract3" else B
                return set_bytes(out, bget(x).clip(A, hi).shift(-A))
            return set_bytes(out, Intervals.whole()) if bget(x) else False
        if op == "concat" and len(a.inputs) == 2:                  # concat A B -> A||B
            pre, suf = a.inputs[1], a.inputs[0]
            lp = _byte_length(pre)
            if lp is None:
                return (set_bytes(out, Intervals.whole())
                        if (bget(pre) or bget(suf)) else False)
            return set_bytes(out, bget(pre).union(bget(suf).shift(lp)))
        if op == "setbyte" and len(a.inputs) == 3:                 # setbyte X i b
            x, i_op, b = a.inputs[2], a.inputs[1], a.inputs[0]
            i = const_int(i_op)
            if i is not None:
                iv = bget(x).subtract(i, i + 1)
                if sget(b):
                    iv = iv.union(Intervals([(i, i + 1)]))
                return set_bytes(out, iv)
            return set_bytes(out, Intervals.whole()) if any_tainted(a) else False
        if op in ("replace2", "replace3"):                         # splice V into X at A
            if op == "replace2" and a.immediates and len(a.inputs) == 2:
                x, v, A = a.inputs[1], a.inputs[0], int(a.immediates.split()[0])
            elif op == "replace3" and len(a.inputs) == 3:
                x, v, A = a.inputs[2], a.inputs[0], const_int(a.inputs[1])
            else:
                x = v = A = None
            lv = _byte_length(v) if v is not None else None
            if A is not None and lv is not None:
                iv = bget(x).subtract(A, A + lv).union(bget(v).shift(A))
                return set_bytes(out, iv)
            return set_bytes(out, Intervals.whole()) if any_tainted(a) else False
        if op in _HASH_OPS and a.inputs:                           # digest of tainted -> tainted
            return set_bytes(out, Intervals.whole(32)) if bget(a.inputs[0]) else False

        # ---- bytes -> scalar (the byte-range -> scalar bridge) ----
        if op == "getbyte" and len(a.inputs) == 2:
            i = const_int(a.inputs[0])
            x = a.inputs[1]
            hit = bget(x).overlaps(i, i + 1) if i is not None else bool(bget(x))
            return set_scalar(out) if hit else False
        if op in _EXTRACT_UINT and len(a.inputs) == 2:
            n = _EXTRACT_UINT[op]
            i = const_int(a.inputs[0])
            x = a.inputs[1]
            hit = bget(x).overlaps(i, i + n) if i is not None else bool(bget(x))
            return set_scalar(out) if hit else False
        if op == "btoi" and a.inputs:
            return set_scalar(out) if bget(a.inputs[0]).overlaps(0, 8) else False

        # ---- scalar -> bytes ----
        if op == "itob" and a.inputs:
            return set_bytes(out, Intervals.whole(8)) if sget(a.inputs[0]) else False

        # ---- conservative fallback: any-input-tainted -> output tainted ----
        if any_tainted(a):
            # len / bitlen derive metadata, not content — don't propagate.
            if op in ("len", "bitlen"):
                return False
            # Bytes-PRODUCING ops with no precise interval rule must record
            # BYTE taint (not scalar): a tainted byte result later read by
            # extract / getbyte / extract_uintN would otherwise find an empty
            # byte map and propagate nothing -- a false negative, which violates
            # the module's "never a false negative" soundness contract.
            if op in _BYTES_OUT_FALLBACK:
                return set_bytes(out, Intervals.whole(_byte_length(out)))
            return set_scalar(out)
        return False

    def flow_phi(ph) -> bool:
        iv = Intervals.empty()
        sc = False
        for arg in ph.args:
            iv = iv.union(bget(arg))
            sc = sc or sget(arg)
        changed = set_bytes(ph, iv)
        if sc:
            changed = set_scalar(ph) or changed
        return changed

    changed = True
    while changed:
        changed = False
        for a in prog.assignments:
            changed = flow(a) or changed
        for ph in prog.phis.values():
            changed = flow_phi(ph) or changed

    return ByteTaintResult(bt, st)
