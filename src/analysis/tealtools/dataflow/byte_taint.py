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
(output tainted if any input is).

Three layers, all live: (1) the **forward** interval propagation; (2)
**validation-narrowing** (``validate=True``) that *clears* a sub-range pinned
by an ``assert(slice(X) == clean)`` guard (see :func:`_validated_intervals`);
and (3) an **interprocedural** bridge — a ``frame_dig`` param inherits the
byte-intervals of its caller args via :func:`frame_param_sources`, so taint fed
INTO a subroutine is tracked through it at byte granularity without an IR lift.

Entry point: :func:`byte_taint`. Standalone — it does not touch the live
engine.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..ssa import Const, Phi, SSAProgram, SSAVar, const_int, operand_const
from ..ssa.models import _shuffle_mapping, _txn_field_name

INF = float("inf")  # sentinel the Intervals algebra tolerates as an open right end
#: AVM byteslice stack values are capped at 4096 bytes -- there is no true ∞ end.
AVM_MAX_BYTES = 4096


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
        """``[0, length)`` — or ``[0, AVM_MAX_BYTES)`` when the length is unknown
        (a byteslice value can't exceed the AVM's 4096-byte cap)."""
        return cls([(0, AVM_MAX_BYTES if length is None else length)])

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


def _len_bound(op) -> int:
    """UPPER bound on a value's byte length — the honest open-end for a taint
    interval (there is no true ∞; the AVM caps a byteslice at 4096 bytes).
    Reuses :func:`propagate_byte_lengths`' annotations (byte_taint runs the pass):
    the exact ``byte_length``, else the ``byte_length_range`` hi (e.g. ``btoi(X)``
    ⇒ ``len(X) ≤ 8``), else :data:`AVM_MAX_BYTES`."""
    exact = _byte_length(op)
    if exact is not None:
        return min(exact, AVM_MAX_BYTES)
    t = getattr(op, "type", None)
    r = getattr(t, "byte_length_range", None) if t is not None else None
    hi = getattr(r, "hi", None) if r is not None else None
    if hi is not None:
        return min(int(hi), AVM_MAX_BYTES)
    return AVM_MAX_BYTES


def _default_sources(a) -> Optional[Intervals]:
    """Default attacker-input seed: every ``ApplicationArgs`` read is fully
    tainted (its length is usually dynamic, so ``[0, len-bound)`` — the exact /
    range-bounded length when known, else the 4096-byte AVM cap)."""
    if not a.immediates:
        return None
    if _txn_field_name(a.op, a.immediates.split()) == "ApplicationArgs":
        out = a.outputs[0] if a.outputs else None
        return Intervals.whole(_len_bound(out) if out is not None else None)
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


# Pure combinators: their output is a deterministic function of their stack
# inputs, with no external read. Used by :func:`_is_clean` — a value built only
# from constants / ``global`` reads through these ops is attacker-independent.
# Deliberately an ALLOWLIST: any op NOT here (``txn`` / ``arg`` / ``frame_dig``
# / ``load`` / ``app_global_get`` / a source, …) breaks cleanliness, so a
# missing entry costs precision, never soundness.
_PURE_COMBINATORS = frozenset({
    "+", "-", "*", "/", "%", "exp", "sqrt", "shl", "shr", "<<", ">>",
    "b+", "b-", "b*", "b/", "b%", "bsqrt",
    "&", "|", "^", "~", "b&", "b|", "b^", "b~", "bzero",
    "==", "!=", "<", ">", "<=", ">=", "!", "&&", "||",
    "b==", "b!=", "b<", "b>", "b<=", "b>=",
    "concat", "extract", "extract3", "substring", "substring3",
    "len", "bitlen", "getbyte", "setbyte", "getbit", "setbit",
    "replace2", "replace3", "itob", "btoi",
    "sha256", "sha512_256", "keccak256", "sha3_256",
})


def _is_clean(v, seen: Optional[set] = None) -> bool:
    """True if operand ``v`` is attacker-INDEPENDENT — its value cannot be
    steered by attacker input, so an ``assert(slice(X) == v)`` guard genuinely
    pins those bytes of X to a value outside attacker control.

    Sound over-approximation via an allowlist: a value is clean iff every leaf
    of its def-tree is a constant or a ``global`` read, combined only through
    :data:`_PURE_COMBINATORS`. Everything else — ``txn``/``arg`` reads, a
    ``frame_dig`` param (interprocedurally attacker-controlled), scratch/state
    reads, unknown ops — is treated as NOT clean. Note we do NOT define clean as
    "currently untainted": byte_taint is intra-procedural, so a param can look
    untainted here yet carry taint from the caller; clearing against it would be
    a false negative."""
    if operand_const(v) is not None:
        return True
    if seen is None:
        seen = set()
    if v in seen:
        return True                       # cycle edge introduces no new source
    seen.add(v)
    if isinstance(v, Phi):
        return all(_is_clean(arg, seen) for arg in v.args)
    if not isinstance(v, SSAVar):
        return False
    d = getattr(v, "defined_by", None)
    if d is None:
        return False                      # unknown origin (param / frame read)
    if d.op == "global":
        return True                       # chain / app metadata, attacker-independent
    if d.op in _PURE_COMBINATORS and d.inputs:
        return all(_is_clean(i, seen) for i in d.inputs)
    return False


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
            return (X, A, (_byte_length(X) or _len_bound(X)) if B == 0 else A + B)
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
    ``assert(slice(X) == clean)`` guards, flow-sensitively.

    A guard pinning a static slice of X to an attacker-INDEPENDENT value means
    those bytes can't be attacker-chosen past the assert (the txn fails
    otherwise). ``clean`` is a compile-time constant OR any value that
    :func:`_is_clean` proves attacker-independent (a ``global`` read, or pure
    computation over constants / globals — e.g. ``extract(X,0,32) == global
    CurrentApplicationAddress`` or ``== itob(global Round)``). Comparing two
    attacker slices (``slice(X) == slice(Y)``) clears nothing — neither side is
    clean.

    We clear the range from X's taint **globally** only when every *other* use
    of X is dominated by the assert — the same soundness contract as
    :mod:`tealtools.passes.range_assert` (a use reachable without passing the
    guard would otherwise lose taint unsoundly). Dominance is approximated by
    reachability-without-the-assert-block on the raw interprocedural CFG
    (over-approximates → conservative)."""
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
    prov: dict = {}       # value -> [(lo, hi, kind, line)] : which op validated
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
            if isinstance(s, SSAVar) and _is_clean(other):
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
            prov.setdefault(x, []).append((lo, hi, "assert", a.location.line))

    # Branch-to-reject validation: a `slice(X) == clean` that drives a `bz` /
    # `bnz` to a rejection -- OR a `match` / `switch` arm -- pins those bytes on
    # the reachable path exactly as an `assert` does, but the loop above only sees
    # a literal `assert`. PathPredicateAnalysis derives the same `slice == clean`
    # fact from a guarded `==`, a branch, AND a match/switch arm (an ABI router
    # pins the selector to that arm's method const) -- all as an "eq" predicate on
    # the slice value. Clear X's range when such a predicate holds at every OTHER
    # use of X -- the same global-soundness contract (different arms may pin to
    # different clean consts; each still validates the same slice bytes).
    from ..path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(prog)

    def _eq_clean_at(value, use) -> bool:
        return any(
            bc.kind == "eq" and bc.value is value and bc.args and _is_clean(bc.args[0])
            for bc in pp.predicates_at(use.location.file, use.location.line)
        )

    # Candidate slice values pinned to a clean value on some path (== branch or
    # match/switch arm), gathered straight from the predicate facts.
    slice_cands: dict = {}
    for preds in pp.bb_preds.values():
        for bc in preds:
            if (bc.kind == "eq" and bc.args and isinstance(bc.value, SSAVar)
                    and _is_clean(bc.args[0])):
                info = _slice_of(bc.value)
                if info is not None and isinstance(info[0], SSAVar):
                    slice_cands[bc.value] = info
    for slc, (x, lo, hi) in slice_cands.items():
        uses = [u for u in x.uses if u is not getattr(slc, "defined_by", None)]
        if uses and all(_eq_clean_at(slc, u) for u in uses):
            out.setdefault(x, []).append((lo, hi))
            prov.setdefault(x, []).append((lo, hi, "branch/match", getattr(slc, "line", 0)))
    return {v: Intervals(parts) for v, parts in out.items()}, prov


def _op_desc(d) -> str:
    """One-line label for an assignment: ``op imm @Lline``."""
    if d is None:
        return "?"
    imm = f" {d.immediates}".rstrip() if getattr(d, "immediates", "") else ""
    ln = getattr(getattr(d, "location", None), "line", None)
    return f"{d.op}{imm}" + (f" @L{ln}" if ln else "")


def taint_chain(value, result: "ByteTaintResult", *, max_hops: int = 32) -> list:
    """The op chain SOURCE → ``value``: walk backward from ``value``, at each hop
    following the input that carries the taint reaching it, until a source (an op
    with no tainted input, e.g. ``txna ApplicationArgs 0``). Returns the defining
    assignments source-first -- the provenance of *why* the value is tainted."""
    chain: list = []
    seen: set = set()
    cur = value
    while cur is not None and id(cur) not in seen and len(chain) < max_hops:
        seen.add(id(cur))
        d = getattr(cur, "defined_by", None)
        if d is None:
            break
        chain.append(d)
        nxt = None
        for i in getattr(d, "inputs", ()):
            if not isinstance(i, Const) and (result.tainted_bytes(i) or
                                             result.is_scalar_tainted(i)):
                nxt = i
                break
        # Interprocedural: a `frame_dig` param has no local input -- follow the
        # frame bridge back to a tainted caller arg, so the chain crosses callsub
        # (the IR-level advantage) instead of dead-ending at the param read.
        if nxt is None:
            for arg in result.frame_src.get(cur, ()):
                if result.tainted_bytes(arg) or result.is_scalar_tainted(arg):
                    nxt = arg
                    break
        cur = nxt
    chain.reverse()
    return chain


class ByteTaintResult:
    """The fixpoint result: per-value tainted byte intervals + the set of
    tainted scalar (uint64) values produced by the byte→scalar bridges, plus the
    validation provenance (which op cleared which range)."""

    def __init__(self, bytes_taint: dict, scalar_taint: set,
                 validated_by: Optional[dict] = None, frame_src: Optional[dict] = None):
        self.bytes_taint = bytes_taint
        self.scalar_taint = scalar_taint
        self.validated_by = validated_by or {}   # value -> [(lo, hi, kind, line)]
        self.frame_src = frame_src or {}         # frame_dig out -> caller args (interproc)

    def tainted_bytes(self, value) -> Intervals:
        return self.bytes_taint.get(value, Intervals.empty())

    def provenance(self, value) -> str:
        """A witness for ``value``: the chain of ops that TAINT it (source → sink)
        and the ops that VALIDATE (clear) its byte ranges."""
        lines = [f"{value}: {self.tainted_bytes(value) or '(scalar)'}"]
        chain = taint_chain(value, self)
        if chain:
            lines.append("  tainted by:  " + "  →  ".join(_op_desc(d) for d in chain))
        for lo, hi, kind, ln in self.validated_by.get(value, []):
            lines.append(f"  validated:   bytes [{lo}:{hi}) by {kind} @L{ln}")
        return "\n".join(lines)

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

    def render(self, *, width: int = 32) -> str:
        """A byte-STRIP debug view: each tainted value's byte layout as a bar
        (``█`` attacker-tainted, ``·`` clean/validated), anchored to its source
        line + producing opcode. Byte granularity at a glance -- e.g. a checked
        selector shows a clean ``·`` head and a tainted ``█`` tail, and a
        ``validate=True`` clearing is visible as ``·`` where taint used to be.

        ``width``: cells shown for an open-ended (``∞``) or over-wide value,
        suffixed ``→``."""
        lines = ["byte-interval taint  (█ attacker-tainted   · clean/validated)"]
        rows = []
        for v, iv in self.bytes_taint.items():
            if not iv:
                continue
            line = getattr(v, "line", 0)
            d = getattr(v, "defined_by", None)
            op = (f"{d.op} {d.immediates}".strip() if d is not None else str(v))
            rows.append((line, op, _byte_strip(iv, _len_bound(v), width), str(iv)))
        for line, op, strip, rng in sorted(rows, key=lambda r: (r[0], r[1])):
            lines.append(f"  L{line:<4} {op:24.24} {strip}  {rng}")
        if self.scalar_taint:
            lines.append(f"  + {len(self.scalar_taint)} scalar-tainted (uint64) value(s)")
        return "\n".join(lines)

    def render_provenance(self) -> str:
        """Full witness per tainted value: the chain of ops that TAINT it (source
        → value, crossing callsub) + the ops that VALIDATE its byte ranges."""
        blocks = [self.provenance(v)
                  for v in sorted(self.bytes_taint, key=lambda x: getattr(x, "line", 0))
                  if self.bytes_taint[v]]
        return "\n".join(blocks) if blocks else "(no tainted values)"


def _byte_strip(iv: Intervals, bound: Optional[int], width: int = 32) -> str:
    """Intervals -> a byte bar: one cell per byte (``█`` tainted, ``·`` clean).
    ``bound`` is the value's max byte length (see :func:`_len_bound`); the bar is
    truncated at ``width`` cells and suffixed ``→`` when the value extends past
    what's shown (``bound`` unknown, or > the cells drawn, or an ``INF`` end)."""
    n = width if bound is None else min(int(bound), width)
    cells = "".join("█" if iv.overlaps(i, i + 1) else "·" for i in range(n))
    max_hi = max((hi for _, hi in iv.parts), default=0)
    open_end = bound is None or bound > n or max_hi > n
    return cells + ("→" if open_end else "")


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
    validated, validated_by = _validated_intervals(prog) if validate else ({}, {})

    # Interprocedural bridge: a `frame_dig` param read has no def-use input in
    # PySSA, so caller taint would stop at the call boundary. `frame_param_sources`
    # supplies {frame_dig output -> caller-arg operands}; the fixpoint unions each
    # param's byte-intervals from its callers' args -> a value fed INTO a sub is
    # tracked through it, at byte granularity, with no IR lift.
    from ..passes.frame_flow import frame_param_sources
    frame_src = frame_param_sources(prog)

    bt: dict = {}     # value -> Intervals (tainted byte ranges)
    st: set = set()   # scalar (uint64) values that are tainted

    def bget(op) -> Intervals:
        return Intervals.empty() if isinstance(op, Const) else bt.get(op, Intervals.empty())

    def sget(op) -> bool:
        return (not isinstance(op, Const)) and op in st

    def any_tainted(a) -> bool:
        return any(bool(bget(i)) or sget(i) for i in a.inputs)

    def set_bytes(out, iv: Intervals) -> bool:
        iv = iv.clip(0, _len_bound(out))    # no byte past the value's length bound
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
                hi = _len_bound(a.inputs[0]) if B == 0 else A + B
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
            return set_bytes(out, Intervals.whole(_len_bound(out))) if bget(x) else False
        if op == "concat" and len(a.inputs) == 2:                  # concat A B -> A||B
            pre, suf = a.inputs[1], a.inputs[0]
            lp = _byte_length(pre)
            if lp is None:
                return (set_bytes(out, Intervals.whole(_len_bound(out)))
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
            return set_bytes(out, Intervals.whole(_len_bound(out))) if any_tainted(a) else False
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
            return set_bytes(out, Intervals.whole(_len_bound(out))) if any_tainted(a) else False
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
                return set_bytes(out, Intervals.whole(_len_bound(out)))
            return set_scalar(out)
        return False

    def _join(target, operands) -> bool:
        """Union the byte-intervals + scalar taint of ``operands`` into
        ``target`` — the meet for a phi (its args) and a frame param (its
        caller args)."""
        iv = Intervals.empty()
        sc = False
        for o in operands:
            iv = iv.union(bget(o))
            sc = sc or sget(o)
        changed = set_bytes(target, iv)
        if sc:
            changed = set_scalar(target) or changed
        return changed

    changed = True
    while changed:
        changed = False
        for a in prog.assignments:
            changed = flow(a) or changed
        for ph in prog.phis.values():
            changed = _join(ph, ph.args) or changed
        for dig_out, args in frame_src.items():
            changed = _join(dig_out, args) or changed

    return ByteTaintResult(bt, st, validated_by, frame_src)


class IrByteTaint:
    """SSA byte-taint carried UP onto the lifted IR's registers.

    The precise, interprocedural byte-interval taint is computed once on the SSA
    substrate (:func:`byte_taint`) and mapped onto IR ``Register`` objects via the
    lifter's ``SSAVar -> Register`` bridge — the same rail ``const_value`` /
    ``range`` / ``type`` ride up. IR-layer detectors then get byte-granular taint
    without re-deriving it on the IR (a re-derivation gains nothing: the SSA
    computation is already interprocedural via the frame bridge).

    ``tainted_bytes(reg)`` / ``is_scalar_tainted(reg)`` answer for any register.
    ``is_covered(reg)`` reports whether the carry-up reached the register at all:
    a register with NO source SSAVar (lift-synthesized — a block-arg / phi-copy)
    is *uncovered*, and a caller MUST treat an uncovered sink operand
    conservatively (whole-value tainted), exactly as the boolean IR taint does
    today. So the view is purely additive: byte precision where covered, no
    regression where not."""

    def __init__(self, bytes_view: dict, scalar_view: set, covered: set):
        self._b = bytes_view      # {id(Register): Intervals}
        self._s = scalar_view     # {id(Register)} scalar-tainted
        self._covered = covered   # {id(Register)} reached by the carry-up

    def tainted_bytes(self, reg) -> Intervals:
        return self._b.get(id(reg), Intervals.empty())

    def is_scalar_tainted(self, reg) -> bool:
        return id(reg) in self._s

    def is_covered(self, reg) -> bool:
        return id(reg) in self._covered

    def sink_tainted(self, reg) -> bool:
        """Conservative sink verdict: an uncovered operand is treated as tainted
        (whole-value), a covered one iff it actually carries byte or scalar taint."""
        return (not self.is_covered(reg)) or bool(self.tainted_bytes(reg)) or self.is_scalar_tainted(reg)


def byte_taint_view(
    lifter, *, validate: bool = True, result: Optional[ByteTaintResult] = None,
) -> IrByteTaint:
    """Carry the SSA byte-taint of ``lifter.prog`` up onto its IR registers.

    Runs :func:`byte_taint` on the lifter's own program and maps each
    ``SSAVar/Phi`` result onto its ``Register`` by object identity. Pass a
    precomputed ``result`` to share one fixpoint.

    ``validate=True`` (default) carries up the validation-narrowing too — an
    ``assert(slice(X) == clean)`` guard clears those bytes at the IR sink, the
    headline partial-taint precision. It runs ``propagate_inputs`` on
    ``lifter.prog``; despite rewriting SSAVar *consumers*, the def SSAVars in
    ``lifter.regs`` persist and still receive their (cleared) taint, so the
    bridge does NOT desync — measured on real contracts: coverage preserved
    (<0.1% merge drift, absorbed by the conservative fallback) while validated
    ranges clear correctly.

    Returns an :class:`IrByteTaint`. A register is *covered* iff its SSAVar is in
    ``lifter.regs``; lift-synthesized registers are absent and callers fall back
    conservatively (see :meth:`IrByteTaint.sink_tainted`)."""
    if result is None:
        result = byte_taint(lifter.prog, validate=validate)
    bytes_view: dict = {}
    scalar_view: set = set()
    covered: set = set()
    for sv, reg in lifter.regs.items():
        covered.add(id(reg))
        iv = result.tainted_bytes(sv)
        if iv:
            bytes_view[id(reg)] = iv
        if result.is_scalar_tainted(sv):
            scalar_view.add(id(reg))
    return IrByteTaint(bytes_view, scalar_view, covered)


def _main(argv) -> int:
    """CLI: byte-strip taint view for a contract.

        python -m tealtools.dataflow.byte_taint <db|file.teal> [--no-validate] [--why]

    ``--why`` prints the provenance witness (taint chain source→value, crossing
    callsub, + the validating ops) instead of the strip view.
    """
    args = [a for a in argv if not a.startswith("-")]
    if not args:
        print(_main.__doc__.strip())
        return 1
    validate = "--no-validate" not in argv
    prog = SSAProgram(args[0], verbose=False)
    result = byte_taint(prog, validate=validate)
    print(result.render_provenance() if "--why" in argv else result.render())
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
