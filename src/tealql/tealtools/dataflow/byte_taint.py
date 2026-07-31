"""Taint at BYTE-OFFSET granularity — each bytes value carries a set of tainted
half-open intervals, so "bytes 0..7 are a validated selector, bytes 8.. are
attacker-controlled" is expressible where the boolean engine sees one blob.

Three layers: forward interval propagation, validation-narrowing that CLEARS a
sub-range an ``assert(slice(X) == clean)`` guard pins, and an interprocedural
bridge giving a ``frame_dig`` param its caller args' intervals.

HAZARD: soundness beats precision everywhere here — the whole point is that a
range reported CLEAN is trusted downstream. Whenever an offset or length is not
statically known the rule falls back to whole-value taint, and any op without a
precise rule taints its output if any input is tainted. Losing a partition is
acceptable; a false negative is not."""
from __future__ import annotations

import contextlib
from typing import Callable, Optional

from ..ssa import (Const, Phi, SSAProgram, SSAVar, binary_operands, const_int,
                   operand_const)
from ..avm import _txn_field_name, _multi_out_type
from ..ssa.models import _shuffle_mapping

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
    """An immutable, normalized set of half-open ``[lo, hi)`` byte intervals."""

    __slots__ = ("parts",)

    def __init__(self, parts=()):
        self.parts = _normalize(parts)

    @classmethod
    def empty(cls) -> "Intervals":
        return cls()

    @classmethod
    def whole(cls, length: Optional[float] = None) -> "Intervals":
        """``[0, length)``, or the AVM byte cap when the length is unknown."""
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
        """Remove the window ``[lo, hi)``."""
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
        """Set difference — used to clear validated sub-ranges."""
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
    """EXACT byte length of an operand, or ``None`` — on which every caller
    falls back to whole-value taint."""
    t = getattr(op, "type", None)
    if t is not None and getattr(t, "byte_length", None) is not None:
        return t.byte_length
    cv = op if isinstance(op, Const) else getattr(op, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "bytes":
        from ..passes.byte_length_prop import _const_bytes_length
        return _const_bytes_length(cv)
    return None


def _len_bound(op) -> int:
    """UPPER bound on a value's byte length — the honest open end for an
    interval, since the AVM caps a byteslice and there is no true ∞."""
    exact = _byte_length(op)
    if exact is not None:
        return min(exact, AVM_MAX_BYTES)
    t = getattr(op, "type", None)
    r = getattr(t, "byte_length_range", None) if t is not None else None
    hi = getattr(r, "hi", None) if r is not None else None
    if hi is not None:
        return min(int(hi), AVM_MAX_BYTES)
    return AVM_MAX_BYTES


def _uint_hi(op) -> Optional[int]:
    """UPPER bound on a uint64 operand: its constant, else its range hi, else None."""
    c = const_int(op)
    if c is not None:
        return c
    r = getattr(op, "range", None)
    return getattr(r, "hi", None) if r is not None else None


def _index_window(idx_op, width: int) -> tuple:
    """The byte window a ``width``-byte read at ``idx_op`` could touch — exact
    for a const index, else its range, else every byte."""
    c = const_int(idx_op)
    if c is not None:
        return (c, c + width)
    r = getattr(idx_op, "range", None)
    if r is not None:
        return (r.lo, min(r.hi + width, AVM_MAX_BYTES))
    return (0, AVM_MAX_BYTES)


def _default_sources(a) -> Optional[Intervals]:
    """Seed: every ``ApplicationArgs`` read and every LogicSig ``arg`` read is
    fully tainted, both being wholly attacker-supplied.

    HAZARD: the lsig ``arg`` family must stay — without it a LogicSig analysed
    with the default sources shows NO taint at all."""
    from .taint_query import _LSIG_ARG_OPS

    if a.op in _LSIG_ARG_OPS:
        out = a.outputs[0] if a.outputs else None
        return Intervals.whole(_len_bound(out) if out is not None else None)
    if not a.immediates:
        return None
    if _txn_field_name(a.op, a.immediates.split()) == "ApplicationArgs":
        out = a.outputs[0] if a.outputs else None
        return Intervals.whole(_len_bound(out) if out is not None else None)
    return None


_HASH_OPS = frozenset({"sha256", "sha512_256", "keccak256", "sha3_256"})
_EXTRACT_UINT = {"extract_uint16": 2, "extract_uint32": 4, "extract_uint64": 8}
# Bytes-PRODUCING ops with no precise rule: the fallback must record BYTE
# taint for these, not scalar (json_ref is polymorphic, handled separately).
_BYTES_OUT_FALLBACK = frozenset({
    "b+", "b-", "b*", "b/", "b%", "bsqrt",      # bigint arithmetic
    "b|", "b&", "b^", "b~", "bzero",            # bytewise
    "base64_decode",
})


# Ops whose output is a deterministic function of their stack inputs with no
# external read. Deliberately an ALLOWLIST: any op not here breaks cleanliness,
# so a missing entry costs precision, never soundness.
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

# HAZARD: the ONLY globals safe to treat as an attacker-independent pin —
# fixed by the chain or the deployment. EXCLUDES ``GroupSize`` / ``GroupID``
# (the attacker assembles the group) and ``Round`` / ``LatestTimestamp`` /
# ``OpcodeBudget`` (attacker- or miner-influenceable). ``CallerApplication*``
# stay because an inner-txn caller cannot forge which app called it. Unknown
# fields fall through to NOT-clean: a lost proof, never a wrongly cleared taint.
_CLEAN_GLOBALS = frozenset({
    "ZeroAddress", "MinTxnFee", "MinBalance", "MaxTxnLife",
    "LogicSigVersion", "GenesisHash",
    "CurrentApplicationID", "CurrentApplicationAddress", "CreatorAddress",
    "CallerApplicationID", "CallerApplicationAddress",
    "AssetCreateMinBalance", "AssetOptInMinBalance",
})


def _is_clean(v, seen: Optional[set] = None) -> bool:
    """True if ``v`` is attacker-INDEPENDENT, so an ``assert(slice(X) == v)``
    genuinely pins those bytes outside attacker control.

    Clean iff every leaf of the def-tree is a constant or an allowlisted
    ``global``, combined only through :data:`_PURE_COMBINATORS`.

    HAZARD: clean is NOT "currently untainted". This analysis is
    intra-procedural, so a subroutine param can look untainted here while
    carrying taint from its caller; clearing against it is a false negative."""
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
        field = (d.immediates or "").split()[:1]
        return bool(field) and field[0] in _CLEAN_GLOBALS
    if d.op in _PURE_COMBINATORS and d.inputs:
        return all(_is_clean(i, seen) for i in d.inputs)
    return False


def _slice_of(v) -> Optional[tuple]:
    """``(X, lo, hi)`` if ``v`` is a STATIC byte-slice read of ``X``, else ``None``."""
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


def _validated_intervals(prog: SSAProgram) -> tuple[dict, dict]:
    """``(value -> Intervals, value -> provenance)`` for the byte ranges an
    ``assert(slice(X) == clean)`` guard proves are NOT attacker-controlled.

    Comparing two attacker slices clears nothing — neither side is clean.

    HAZARD: the clearing is GLOBAL on X, so it is only applied when every other
    use of X is dominated by the guard; a use reachable without passing it would
    otherwise lose taint unsoundly. Same contract as
    :mod:`tealql.tealtools.passes.range_assert`, with dominance approximated by
    reachability, which over-approximates and so errs toward not clearing."""
    from ..cfg.dominance import AssertDominance

    dom = AssertDominance(prog)

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
        lhs, rhs = binary_operands(d)
        x = lo = hi = test = None
        for s, other in ((lhs, rhs), (rhs, lhs)):
            if not (isinstance(s, SSAVar) and _is_clean(other)):
                continue
            info = _slice_of(s)
            if info is not None and isinstance(info[0], SSAVar):
                x, lo, hi = info                 # a static slice of X is pinned
                test = getattr(s, "defined_by", None)   # the slice read forms the guard
            else:
                # Whole-value equality: `s` itself is pinned to a clean value,
                # so its ENTIRE taint clears past the assert.
                x, lo, hi = s, 0, (_byte_length(s) or _len_bound(s))
                test = d                          # the `==` read forms the guard
            break
        if not isinstance(x, SSAVar):
            continue
        if dom.narrowing_is_sound(x, block_a, a.location.line, exclude=test):
            out.setdefault(x, []).append((lo, hi))
            prov.setdefault(x, []).append((lo, hi, "assert", a.location.line))

    # A `slice(X) == clean` driving a branch to rejection — or a match/switch
    # arm, as an ABI router pins the selector to that arm's const — pins those
    # bytes exactly as an assert does, but the loop above only sees literal
    # asserts. Same global-soundness contract: clear only when the predicate
    # holds at every OTHER use of X.
    from ..path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(prog)

    def _eq_clean_at(value, use) -> bool:
        return any(
            bc.kind == "eq" and bc.value is value and bc.args and _is_clean(bc.args[0])
            for bc in pp.predicates_at(use.location.file, use.location.line)
        )

    slice_cands: dict = {}                    # slice values pinned on some path
    for preds in pp.bb_preds.values():
        for bc in preds:
            if (bc.kind == "eq" and bc.args and isinstance(bc.value, SSAVar)
                    and _is_clean(bc.args[0])):
                info = _slice_of(bc.value)
                if info is not None and isinstance(info[0], SSAVar):
                    slice_cands[bc.value] = info
    for slc, (x, lo, hi) in slice_cands.items():
        if id(x) in dom.phi_fed:
            continue                          # edge-specific: never clear
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
    """The op chain SOURCE → ``value``, source-first: why the value is tainted."""
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
        # A `frame_dig` param has no local input, so follow the frame bridge to
        # a tainted caller arg rather than dead-ending at the param read.
        if nxt is None:
            for arg in result.frame_src.get(cur, ()):
                if result.tainted_bytes(arg) or result.is_scalar_tainted(arg):
                    nxt = arg
                    break
        cur = nxt
    chain.reverse()
    return chain


class ByteTaintResult:
    """The fixpoint: per-value tainted byte intervals, tainted scalars, and the
    provenance of which op cleared which range."""

    def __init__(self, bytes_taint: dict, scalar_taint: set,
                 validated_by: Optional[dict] = None, frame_src: Optional[dict] = None):
        self.bytes_taint = bytes_taint
        self.scalar_taint = scalar_taint
        self.validated_by = validated_by or {}   # value -> [(lo, hi, kind, line)]
        self.frame_src = frame_src or {}         # frame_dig out -> caller args (interproc)

    def tainted_bytes(self, value) -> Intervals:
        return self.bytes_taint.get(value, Intervals.empty())

    def provenance(self, value) -> str:
        """A witness: the ops that TAINT ``value`` and the ops that VALIDATE it."""
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
        """A byte-STRIP debug view: each tainted value's layout as a bar of
        ``█`` (tainted) and ``·`` (clean), anchored to its line and opcode."""
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
        """The full witness for every tainted value."""
        blocks = [self.provenance(v)
                  for v in sorted(self.bytes_taint, key=lambda x: getattr(x, "line", 0))
                  if self.bytes_taint[v]]
        return "\n".join(blocks) if blocks else "(no tainted values)"


def _byte_strip(iv: Intervals, bound: Optional[int], width: int = 32) -> str:
    """Intervals to a byte bar, truncated at ``width`` and suffixed ``→`` when
    the value extends past what is drawn."""
    n = width if bound is None else min(int(bound), width)
    cells = "".join("█" if iv.overlaps(i, i + 1) else "·" for i in range(n))
    max_hi = max((hi for _, hi in iv.parts), default=0)
    open_end = bound is None or bound > n or max_hi > n
    return cells + ("→" if open_end else "")


@contextlib.contextmanager
def _unification_confined(prog: SSAProgram, active: bool):
    """Keep the ``validate=True`` unification from OUTLIVING this analysis.

    ``propagate_inputs`` / ``propagate_stack_shuffles`` REWIRE consumers, and the
    program they run on is one the caller shares with the SSA-layer detectors
    (``ir_lifter`` lifts it in place rather than re-parsing a copy). Annotations
    may cross that boundary — they only ever refine — but a rewiring must not:
    it replaces a ``frame_dig``/shuffle read with a coarse slot-merge phi, which
    a MAY-semantics consumer then walks into unrelated producers (a 30-arg phi
    mixing bytes and uint64 producers is a stack-slot artefact, not a value).

    So snapshot the consumer wiring and put it back. A program that ALREADY
    carried the unification is left alone — that state is its own, not ours."""
    if not active or (getattr(prog, "_inputs_propagated", False)
                      and getattr(prog, "_shuffles_propagated", False)):
        yield
        return
    saved_inputs = [(a, list(a.inputs), a.shuffled) for a in prog.assignments]
    saved_args = [(p, list(p.args)) for p in prog.phis.values()]
    had = (getattr(prog, "_inputs_propagated", False),
           getattr(prog, "_shuffles_propagated", False))
    try:
        yield
    finally:
        for a, ins, shuf in saved_inputs:
            a.inputs[:] = ins
            a.shuffled = shuf
        for p, args in saved_args:
            p.args[:] = args
        prog._inputs_propagated, prog._shuffles_propagated = had


def byte_taint(
    prog: SSAProgram,
    *,
    sources: Optional[Callable] = None,
    validate: bool = False,
) -> ByteTaintResult:
    """Forward byte-interval taint to a fixed point.

    ``validate=True`` adds the validation-narrowing layer, which CLEARS the
    bytes a guard pins. It first unifies inputs and shuffles so the validated
    value and its downstream reads share one canonical SSAVar — on a stack
    machine they otherwise diverge across dups and re-reads, and the clearing
    lands on a value nothing reads. That unification is CONFINED to this call
    (:func:`_unification_confined`); the result keys on def SSAVars, which the
    rewiring never touches, so nothing downstream needs it to persist."""
    with _unification_confined(prog, validate):
        return _byte_taint_impl(prog, sources=sources, validate=validate)


def _byte_taint_impl(
    prog: SSAProgram,
    *,
    sources: Optional[Callable] = None,
    validate: bool = False,
) -> ByteTaintResult:
    prog.propagate_constants()
    if validate:
        prog.propagate_inputs()
        prog.propagate_stack_shuffles()
    prog.propagate_byte_lengths()
    # Integer ranges let a const-offset slice with a RUNTIME count bound its
    # length by the count's range: `assert(L <= 32); extract3 X 4 L` taints
    # [4, 36) rather than [4, 4096). Ranges only ever narrow, so this can only
    # tighten taint, never clear a byte that should stay tainted.
    prog.propagate_assert_ranges()
    seed = sources or _default_sources
    validated, validated_by = _validated_intervals(prog) if validate else ({}, {})

    # Both bridges close a def-use gap in PySSA: a `frame_dig` param and a
    # `load N` have no input, so without them taint dies at the call boundary
    # and at every `store N; …; load N` roundtrip. Shared with the boolean
    # engine so the two cannot disagree on what reaches a load.
    from ..passes.frame_flow import frame_param_sources, scratch_load_sources
    frame_src = frame_param_sources(prog)
    scratch_src = scratch_load_sources(prog)

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

        # Stack shuffles copy each output's taint from its mapped source.
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
            if A is not None:
                # Const OFFSET, runtime count: the byte mapping is still EXACT
                # (out[j] = X[A+j]), only the length is uncertain — so X's taint
                # BEFORE offset A genuinely never reaches the output.
                bh = _uint_hi(a.inputs[0])
                if op == "extract3":
                    hi = (A + bh) if bh is not None else _len_bound(x)
                else:                                  # substring3: inputs[0]=end
                    hi = bh if bh is not None else _len_bound(x)
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
                iv = bget(x).subtract(i, i + 1)                 # that byte is overwritten
                if sget(b):
                    iv = iv.union(Intervals([(i, i + 1)]))
                return set_bytes(out, iv)
            # HAZARD: runtime index — the overwritten position is unknown, so
            # subtracting anything would be a false NEGATIVE. Keep ALL of X's
            # taint and add the written byte over the index's possible window.
            iv = bget(x)
            if sget(b):
                lo, hi = _index_window(i_op, 1)
                iv = iv.union(Intervals([(lo, hi)]))
            return set_bytes(out, iv)
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
            if A is not None and x is not None:
                # HAZARD: const offset but UNKNOWN value length — the overwritten
                # region is unbounded, so subtracting it would be a false
                # NEGATIVE. Keep ALL of X's taint and add V's at A.
                iv = bget(x).union(bget(v).shift(A)) if v is not None else bget(x)
                return set_bytes(out, iv)
            return set_bytes(out, Intervals.whole(_len_bound(out))) if any_tainted(a) else False
        if op in _HASH_OPS and a.inputs:                           # digest of tainted -> tainted
            return set_bytes(out, Intervals.whole(32)) if bget(a.inputs[0]) else False

        # ---- bytes -> scalar bridge ----
        # A non-const index uses its range window rather than "any taint", so a
        # read whose possible bytes miss X's tainted region stays clean.
        if op == "getbyte" and len(a.inputs) == 2:
            lo, hi = _index_window(a.inputs[0], 1)
            return set_scalar(out) if bget(a.inputs[1]).overlaps(lo, hi) else False
        if op in _EXTRACT_UINT and len(a.inputs) == 2:
            lo, hi = _index_window(a.inputs[0], _EXTRACT_UINT[op])
            return set_scalar(out) if bget(a.inputs[1]).overlaps(lo, hi) else False
        if op == "btoi" and a.inputs:
            return set_scalar(out) if bget(a.inputs[0]).overlaps(0, 8) else False

        # ---- scalar -> bytes ----
        if op == "itob" and a.inputs:
            return set_bytes(out, Intervals.whole(8)) if sget(a.inputs[0]) else False

        # ---- select A B C -> A if C==0 else B. TOP-FIRST, so the two VALUE
        # inputs are inputs[2]=A and inputs[1]=B. Treated as a phi of them,
        # carrying byte intervals AND scalar taint so a tainted bytes value
        # survives a downstream extract.
        if op == "select" and len(a.inputs) == 3:
            iv = bget(a.inputs[1]).union(bget(a.inputs[2]))
            changed = set_bytes(out, iv)
            if sget(a.inputs[1]) or sget(a.inputs[2]):
                changed = set_scalar(out) or changed
            return changed

        # ---- conservative fallback: any-input-tainted -> output tainted ----
        if any_tainted(a):
            # len / bitlen derive metadata, not content — don't propagate.
            if op in ("len", "bitlen"):
                return False
            # HAZARD: a bytes-PRODUCING op must record BYTE taint, not scalar.
            # A later extract / getbyte / extract_uintN of a scalar-tagged
            # result finds an empty byte map and propagates nothing.
            if op in _BYTES_OUT_FALLBACK:
                return set_bytes(out, Intervals.whole(_len_bound(out)))
            if op == "json_ref":
                # Polymorphic on its immediate: JSONUint64 is a scalar but
                # JSONString / JSONObject are BYTES, and must be tagged so.
                kind = (a.immediates or "").strip().split()
                if kind and kind[0] in ("JSONString", "JSONObject"):
                    return set_bytes(out, Intervals.whole(_len_bound(out)))
                return set_scalar(out)
            if len(a.outputs) == 1:
                return set_scalar(out)
            # HAZARD: a multi-result op must taint EVERY output by its slot
            # type. The interesting value is often NOT output 0 — a `box_get` /
            # `*_get_ex` value sits BELOW its exists flag, and divmodw and the
            # word pairs carry attacker influence in both halves.
            changed = False
            for oi, o in enumerate(a.outputs):
                t = _multi_out_type(op, a.immediates, oi)
                if t in ("bytes", "account"):
                    changed = set_bytes(o, Intervals.whole(_len_bound(o))) or changed
                elif t in ("uint64", "bool"):
                    changed = set_scalar(o) or changed
                else:                      # unknown slot type -> sound both ways
                    c = set_scalar(o)
                    changed = set_bytes(o, Intervals.whole(_len_bound(o))) or c or changed
            return changed
        return False

    def _join(target, operands) -> bool:
        """Union the operands' taint into ``target`` — the join for a phi, a
        frame param and a scratch load alike."""
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
        for load_var, stores in scratch_src.items():
            changed = _join(load_var, stores) or changed

    return ByteTaintResult(bt, st, validated_by, frame_src)


class IrByteTaint:
    """SSA byte-taint carried UP onto the lifted IR's registers.

    HAZARD: the carry-up does not reach every register — a lift-synthesized one
    (block-arg, phi-copy) has no source SSAVar and is UNCOVERED, meaning "no
    information", not "clean". A caller must treat an uncovered sink operand as
    whole-value tainted, or the view silently loses flows instead of refining
    them; :meth:`sink_tainted` does exactly that."""

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
        """Sink verdict — an UNCOVERED operand counts as tainted."""
        return (not self.is_covered(reg)) or bool(self.tainted_bytes(reg)) or self.is_scalar_tainted(reg)


def _cached_byte_taint(lifter, validate: bool) -> ByteTaintResult:
    """``byte_taint(lifter.prog)`` memoised per lifter + ``validate``. Keys on the
    lifter, not the program: the result is consumed through ``lifter.regs``, and a
    lifter is already the per-program unit both entry points cache."""
    key = f"_sec_byte_taint_{'v' if validate else 'nv'}"
    res = getattr(lifter, key, None)
    if res is None:
        res = byte_taint(lifter.prog, validate=validate)
        try:
            setattr(lifter, key, res)
        except AttributeError:          # only if _Lifter ever gains __slots__
            pass
    return res


def byte_taint_view(
    lifter, *, validate: bool = True, result: Optional[ByteTaintResult] = None,
) -> IrByteTaint:
    """Carry the SSA byte-taint of ``lifter.prog`` up onto its IR registers.

    ``validate=True`` unifies inputs on ``lifter.prog`` for the duration of the
    fixpoint (:func:`_unification_confined`); that rewrites SSAVar CONSUMERS only
    — the def SSAVars in ``lifter.regs`` persist and still receive their cleared
    taint, so the register bridge does not desync.

    The fixpoint is MEMOISED on the lifter: the ir-* detectors call this several
    times per program (three sites in ``ir-partial-tainted-fund-flow`` alone) and
    each call used to redo the whole analysis."""
    if result is None:
        result = _cached_byte_taint(lifter, validate)
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

        python -m tealql.tealtools.dataflow.byte_taint <contract.teal> [--no-validate] [--why]

    ``--why`` prints the provenance witness (taint chain source→value, crossing
    callsub, + the validating ops) instead of the strip view.
    """
    args = [a for a in argv if not a.startswith("-")]
    if not args:
        print(_main.__doc__.strip())
        return 1
    validate = "--no-validate" not in argv
    prog = SSAProgram(args[0])
    result = byte_taint(prog, validate=validate)
    print(result.render_provenance() if "--why" in argv else result.render())
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv[1:]))
