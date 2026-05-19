"""Per-BB path predicates derived from branch and assert outcomes.

For each :class:`tealtools.ssa.BasicBlock`, computes the set of
value-outcome pairs that hold on **every** path from program entry to
that BB. A pair ``(V, "nonzero")`` reads as "the SSA value ``V`` was
non-zero on every path that reaches this BB" — typically because
some ``bnz`` / ``bz`` / ``assert`` dominated the BB.

This is the substrate for "must dominate sink" detectors. Example
(an upcoming auth-checker would do something like this):

    pp = PathPredicateAnalysis(prog)
    for sink in suspicious_assignments(prog):
        bb = prog.block_containing(sink.location.file, sink.location.line)
        if not any(p.is_admin_check() for p in pp.bb_preds[bb]):
            flag(sink)

Algorithm
---------

Forward dataflow with intersection at BB joins:

    bb_preds[entry]   = ∅
    bb_preds[bb]      = ⋂_{p ∈ preds(bb)}  ( bb_preds[p]  ∪  edge_pred(p, bb) )

Edge predicates per branch op:

- ``bnz l_target``: target edge ⇒ ``(value, "nonzero")``;
                    fall-through ⇒ ``(value, "zero")``.
- ``bz l_target``:  target edge ⇒ ``(value, "zero")``;
                    fall-through ⇒ ``(value, "nonzero")``.
- ``assert``:       only successor (success path) ⇒
                    ``(value, "nonzero")``.

Self-loops are handled correctly by the standard "TOP starts
unknown" fixpoint convention — a back-edge predicate that's only
true on the back-edge intersects to ∅ at the merge with the
non-back-edge contribution and drops out.

``switch`` / ``match`` aren't modelled yet; their edge predicates
are richer (per-target equality with an immediate value) and don't
fit the binary nonzero/zero shape. A successor BB reached from a
``switch`` will simply not pick up a predicate from that edge —
sound but imprecise.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from .ssa import (
    BasicBlock,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
)


Operand = Union[SSAVar, Phi, Const]


@dataclass(frozen=True)
class BranchCondition:
    """A predicate on an SSA value, derived from a dominated branch.

    ``kind``:
        - ``"nonzero"``: value != 0 (bnz-taken, bz-not-taken, asserted).
        - ``"zero"``: value == 0 (bnz-not-taken, bz-taken).
        - ``"eq"``: value == ``args[0]``. Emitted both for switch /
          match (where ``args[0]`` is the target's literal) and for
          a guarded ``==`` whose result feeds into a branch (where
          ``args[0]`` is the other operand the value was compared with).
        - ``"neq"``: value != ``args[0]``. Complement of ``eq``;
          emitted on the negative side of a guarded ``==``, or directly
          when ``!=`` drives the branch.
        - ``"lt"`` / ``"le"`` / ``"gt"`` / ``"ge"``: value vs.
          ``args[0]`` with the named relation. Emitted when an ordered
          comparison (``<``/``<=``/``>``/``>=`` and the ``b``-prefixed
          byte-arithmetic variants) drives the branch.
        - ``"not_in_range"``: value ∉ ``[args[0]..args[1] - 1]``
          (switch fall-through: index out of [0..N-1]).
        - ``"neq_all"``: value not equal to any of the operands in
          ``args`` (match fall-through: key didn't match any
          candidate).

    Identity is ``(value, kind, args)`` so the analysis can put these
    in sets and intersect across joins. ``args`` must be a tuple of
    hashables (Const / SSAVar / Phi / int / str).
    """

    value: Operand
    kind: str
    args: tuple = ()

    def __repr__(self) -> str:
        v = _disp(self.value)
        if self.kind == "nonzero":
            return f"({v} != 0)"
        if self.kind == "zero":
            return f"({v} == 0)"
        if self.kind == "eq":
            return f"({v} == {_disp(self.args[0])})"
        if self.kind == "neq":
            return f"({v} != {_disp(self.args[0])})"
        if self.kind == "lt":
            return f"({v} < {_disp(self.args[0])})"
        if self.kind == "le":
            return f"({v} <= {_disp(self.args[0])})"
        if self.kind == "gt":
            return f"({v} > {_disp(self.args[0])})"
        if self.kind == "ge":
            return f"({v} >= {_disp(self.args[0])})"
        if self.kind == "not_in_range":
            lo, hi = self.args
            return f"({v} not in [{lo}..{hi - 1}])"
        if self.kind == "neq_all":
            return f"({v} not in {{{', '.join(_disp(a) for a in self.args)}}})"
        return f"({v} ?? {self.kind}{self.args})"


# Branch-taken → kind map for each binary op. The "not-taken" side
# uses the *negated* kind from the same table (eq ↔ neq, lt ↔ ge,
# le ↔ gt, gt ↔ le, ge ↔ lt). Byte-arithmetic variants are treated
# as the same predicate kinds for downstream reasoning; consumers
# that care about width can inspect the operand types.
_CMP_OP_TO_KIND_TAKEN: dict[str, str] = {
    "==": "eq", "b==": "eq",
    "!=": "neq", "b!=": "neq",
    "<": "lt", "b<": "lt",
    "<=": "le", "b<=": "le",
    ">": "gt", "b>": "gt",
    ">=": "ge", "b>=": "ge",
}

_KIND_NEGATION: dict[str, str] = {
    "eq": "neq", "neq": "eq",
    "lt": "ge", "ge": "lt",
    "le": "gt", "gt": "le",
    "nonzero": "zero", "zero": "nonzero",
}


# Swapping operands of an ordered comparison flips the relation
# (``a < b`` ↔ ``b > a``). Equality and inequality are symmetric.
_KIND_FLIP: dict[str, str] = {
    "eq": "eq", "neq": "neq",
    "lt": "gt", "gt": "lt",
    "le": "ge", "ge": "le",
}


def _is_const_like(op: Operand) -> bool:
    """``True`` when ``op`` resolves to a known constant — either a
    bare :class:`Const`, or an SSAVar / Phi whose ``const_value`` was
    set by :meth:`SSAProgram.propagate_constants`."""
    if isinstance(op, Const):
        return True
    return getattr(op, "const_value", None) is not None


def _canonical_binary_pred(
    left: Operand, kind: str, right: Operand,
) -> BranchCondition:
    """Construct a binary :class:`BranchCondition` with the *variable*
    side on the left when the other operand is a known constant. For
    ordered relations, the operator is flipped to preserve semantics
    after the swap (``5 < V`` ↦ ``V > 5``). Keeps downstream filtering
    simple — consumers only have to check ``isinstance(p.value, SSAVar)``
    once instead of also handling the reversed form. Const-resolved
    SSAVars (e.g. an ``intc_0`` output that ``propagate_constants``
    pinned to 0) count as "constant" for this swap."""
    if _is_const_like(left) and not _is_const_like(right):
        return BranchCondition(value=right, kind=_KIND_FLIP[kind], args=(left,))
    return BranchCondition(value=left, kind=kind, args=(right,))


def _disp(op) -> str:
    """Compact rendering for an :class:`Operand`. Resolves
    ``const_value`` to a literal so a candidate SSAVar reads as
    ``100`` instead of ``V#1@L7`` once
    :meth:`SSAProgram.propagate_constants` has run."""
    if isinstance(op, Const):
        return op.value
    cv = getattr(op, "const_value", None)
    if cv is not None:
        return cv.value
    return repr(op)


# ---------------------------------------------------------------------------
# Static-incompatibility check for exclusive-pair detection
# ---------------------------------------------------------------------------


def _operand_int_const(operand) -> Optional[int]:
    """Get the integer value if ``operand`` resolves to an int literal,
    else ``None``. Accepts a bare :class:`Const` or an SSAVar/Phi with
    ``const_value`` set."""
    if isinstance(operand, Const):
        cv = operand
    else:
        cv = getattr(operand, "const_value", None)
    if cv is None or cv.kind != "int":
        return None
    try:
        return int(cv.value)
    except (TypeError, ValueError):
        return None


def _operand_bytes_const(operand) -> Optional[str]:
    """Get the canonical hex string if ``operand`` resolves to a bytes
    literal, else ``None``. The hex form is stable and hashable so we
    can compare it for equality across operands."""
    if isinstance(operand, Const):
        cv = operand
    else:
        cv = getattr(operand, "const_value", None)
    if cv is None or cv.kind != "bytes":
        return None
    return cv.value.lower()


def _normalize_pred_kind(p: "BranchCondition") -> tuple[str, Optional[object]]:
    """Project a :class:`BranchCondition` onto the (kind, comparand) axis
    used by the incompatibility checker. ``zero``/``nonzero`` are
    rewritten as ``eq 0`` / ``neq 0`` so the same case-table covers
    everything. Returns ``(None, None)`` for predicates the checker
    doesn't reason about (``not_in_range``, ``neq_all``)."""
    if p.kind == "zero":
        return ("eq", Const("int", "0"))
    if p.kind == "nonzero":
        return ("neq", Const("int", "0"))
    if p.kind in ("eq", "neq", "lt", "le", "gt", "ge"):
        if not p.args:
            return (None, None)
        return (p.kind, p.args[0])
    return (None, None)


def _kind_to_int_interval(
    kind: str, k: int,
) -> tuple[Optional[int], Optional[int]]:
    """Closed-interval representation of ``value ⟨kind⟩ k`` over ints.
    Returns ``(lo, hi)`` with ``None`` meaning unbounded on that side.
    ``neq`` is *not* representable as a single interval; callers must
    handle it specially."""
    if kind == "eq":
        return (k, k)
    if kind == "lt":
        return (None, k - 1)
    if kind == "le":
        return (None, k)
    if kind == "gt":
        return (k + 1, None)
    if kind == "ge":
        return (k, None)
    return (None, None)


def _intervals_disjoint(
    a: tuple[Optional[int], Optional[int]],
    b: tuple[Optional[int], Optional[int]],
) -> bool:
    """``True`` iff the closed integer intervals ``a`` and ``b`` have
    empty intersection. ``None`` on a side means unbounded."""
    a_lo, a_hi = a
    b_lo, b_hi = b
    if a_lo is not None and b_hi is not None and a_lo > b_hi:
        return True
    if b_lo is not None and a_hi is not None and b_lo > a_hi:
        return True
    return False


def _are_predicates_incompatible(
    p: "BranchCondition", q: "BranchCondition",
) -> bool:
    """``True`` iff ``p`` and ``q`` constrain the same operand in ways
    that are statically unsatisfiable — they cannot both hold for any
    integer value. Used to flag XOR / mutual-exclusion relationships
    (e.g., ``selector == 0xAAA`` vs ``selector == 0xBBB`` on a dispatch
    chain). Sound but incomplete: only catches same-operand
    incompatibilities; cross-operand exclusions (e.g., ``a >= b`` vs.
    ``sender == admin``) need path-level reasoning, not just
    constraint inspection."""
    if p.value != q.value:
        return False
    pk, pa = _normalize_pred_kind(p)
    qk, qa = _normalize_pred_kind(q)
    if pk is None or qk is None:
        return False

    # Bytes-equality: ``eq B1`` and ``eq B2`` with B1 != B2 ⇒ incompatible.
    p_bytes = _operand_bytes_const(pa)
    q_bytes = _operand_bytes_const(qa)
    if p_bytes is not None and q_bytes is not None:
        if pk == "eq" and qk == "eq":
            return p_bytes != q_bytes
        if {pk, qk} == {"eq", "neq"}:
            return p_bytes == q_bytes
        return False

    # Int-typed comparisons: drop into the interval / neq case-table.
    p_int = _operand_int_const(pa)
    q_int = _operand_int_const(qa)
    if p_int is None or q_int is None:
        return False
    if pk == "neq" and qk == "neq":
        return False  # both excluded points; satisfiable elsewhere
    if pk == "neq":
        # Only ``q`` constrains a closed interval. ``p`` excludes ``p_int``.
        # Incompatible iff ``q``'s interval is exactly ``{p_int}``.
        return qk == "eq" and q_int == p_int
    if qk == "neq":
        return pk == "eq" and p_int == q_int
    return _intervals_disjoint(
        _kind_to_int_interval(pk, p_int),
        _kind_to_int_interval(qk, q_int),
    )


def find_exclusive_pairs(
    preds: frozenset["BranchCondition"],
) -> list[tuple["BranchCondition", "BranchCondition"]]:
    """All ``(p, q)`` pairs in ``preds`` that are statically
    incompatible — at most one of them holds for any reaching path.
    Each pair is returned once in deterministic order (sorted by repr)."""
    items = sorted(preds, key=repr)
    out: list[tuple[BranchCondition, BranchCondition]] = []
    for i, p in enumerate(items):
        for q in items[i + 1:]:
            if _are_predicates_incompatible(p, q):
                out.append((p, q))
    return out


@dataclass(frozen=True)
class PredicateQuery:
    """Per-line snapshot of path-aware predicates.

    ``must_hold`` are predicates that hold on *every* path from
    program entry to this location (the existing dataflow intersection).
    ``may_hold`` are predicates that hold on at least one path
    (forward union, includes ``must_hold``). ``exclusive_pairs`` are
    statically-incompatible pairs in ``may_hold`` — at most one of
    each pair can be true on any reaching path. See
    :func:`_are_predicates_incompatible` for the constraint vocabulary
    the checker covers (same-operand eq/neq/range, bytes equality)."""

    must_hold: frozenset["BranchCondition"]
    may_hold: frozenset["BranchCondition"]
    exclusive_pairs: tuple[tuple["BranchCondition", "BranchCondition"], ...]

    def __repr__(self) -> str:
        parts: list[str] = []
        if self.must_hold:
            parts.append(
                "must: " + ", ".join(
                    repr(p) for p in sorted(self.must_hold, key=repr)
                )
            )
        only_may = self.may_hold - self.must_hold
        if only_may:
            parts.append(
                "may: " + ", ".join(repr(p) for p in sorted(only_may, key=repr))
            )
        if self.exclusive_pairs:
            parts.append(
                "exclusive: " + ", ".join(
                    f"{p!r} XOR {q!r}" for p, q in self.exclusive_pairs
                )
            )
        return "PredicateQuery(" + "; ".join(parts) + ")"


# Sentinel for the dataflow's "not yet computed" lattice top.
class _Top:
    __slots__ = ()

    def __repr__(self) -> str:
        return "TOP"


_TOP = _Top()


# Branch / assert opcodes that contribute predicates.
_BNZ = "bnz"
_BZ = "bz"
_ASSERT = "assert"
_SWITCH = "switch"
_MATCH = "match"


class PathPredicateAnalysis:
    """Forward dataflow over basic blocks accumulating branch / assert
    predicates that must hold on every path to each BB.

    Construction is cheap — one fixpoint pass over BBs.
    """

    def __init__(
        self,
        prog: SSAProgram,
        *,
        entry_seeds: frozenset[BranchCondition] = frozenset(),
        bb_seeds: Optional[dict[BasicBlock, frozenset[BranchCondition]]] = None,
    ):
        """``entry_seeds``: predicates known to hold at every program
        entry BB before any branch — used by cross-contract analyses
        to propagate caller-side facts (e.g. ``ApplicationArgs[0] ==
        "do_thing"``) into the callee. They flow forward like any
        other predicate.

        ``bb_seeds``: predicates known to hold at the start of specific
        BBs, regardless of join inputs — used when an external event
        (e.g. a successful ``itxn_submit`` returning a callee's
        approving-exit summary) injects facts into a non-entry BB.
        Unioned in *after* the predecessor-intersection step on each
        recomputation of that BB.
        """
        self.prog = prog
        self.entry_seeds = entry_seeds
        self.bb_seeds: dict[BasicBlock, frozenset[BranchCondition]] = (
            bb_seeds or {}
        )
        # (file, label_name) → label's source line, used to resolve
        # branch immediates (``bnz l_target`` ↦ which successor BB).
        self._label_lines: dict[tuple[str, str], int] = self._index_labels()
        self.bb_preds: dict[BasicBlock, frozenset[BranchCondition]] = {}
        # May-hold (forward union) — predicates true on *some* path here
        # rather than every path. ``must_hold ⊆ may_hold`` always. Used
        # for the exclusive-pair query, which inspects pairs in the may
        # set and checks static incompatibility.
        self.bb_may_preds: dict[BasicBlock, frozenset[BranchCondition]] = {}
        self._compute()
        self._compute_may()

    # -- public ---------------------------------------------------------

    def predicates_at(
        self, file: str, line: int
    ) -> frozenset[BranchCondition]:
        """Predicates that hold on every path from program entry to
        ``(file, line)``. Returns an empty set if ``(file, line)``
        isn't inside any computed BB."""
        bb = self.prog.block_containing(file, line)
        if bb is None:
            return frozenset()
        return self.bb_preds.get(bb, frozenset())

    def may_predicates_at(
        self, file: str, line: int,
    ) -> frozenset[BranchCondition]:
        """Predicates that hold on at least one path from program entry
        to ``(file, line)``. ``must_hold ⊆ may_hold`` — every must-hold
        is in here too."""
        bb = self.prog.block_containing(file, line)
        if bb is None:
            return frozenset()
        return self.bb_may_preds.get(bb, frozenset())

    def query(self, file: str, line: int) -> PredicateQuery:
        """Combined snapshot at ``(file, line)``: must-hold predicates,
        may-hold predicates, and statically-incompatible pairs among
        the may set. The third is "at most one of these holds on any
        reaching path" — a sound underapproximation of full
        path-level XOR (cross-operand exclusions require path-level
        reasoning we're not doing yet)."""
        bb = self.prog.block_containing(file, line)
        if bb is None:
            return PredicateQuery(
                must_hold=frozenset(),
                may_hold=frozenset(),
                exclusive_pairs=(),
            )
        must = self.bb_preds.get(bb, frozenset())
        may = self.bb_may_preds.get(bb, frozenset())
        excl = tuple(find_exclusive_pairs(may))
        return PredicateQuery(must_hold=must, may_hold=may, exclusive_pairs=excl)

    def ranges_at(
        self, file: str, line: int,
    ) -> dict[SSAVar, tuple[Optional[int], Optional[int]]]:
        """Per-SSAVar integer interval at ``(file, line)``, aggregated
        from the predicates known to hold there.

        Returns ``{ssavar: (lo, hi)}`` with ``None`` on either side
        meaning unbounded. ``(lo, lo)`` means the value is the constant
        ``lo`` on every path here.

        Currently only literal-int comparands are folded in — predicates
        whose other operand is a non-const SSAVar are ignored. Gap
        constraints from ``neq`` / ``not_in_range`` / ``neq_all`` aren't
        modelled (they'd require a multi-interval representation).
        """
        return self._ranges_from(self.predicates_at(file, line))

    def ranges_at_bb(
        self, bb: BasicBlock,
    ) -> dict[SSAVar, tuple[Optional[int], Optional[int]]]:
        """Same as :meth:`ranges_at` but keyed by :class:`BasicBlock`
        directly. Convenient when iterating over the program."""
        return self._ranges_from(self.bb_preds.get(bb, frozenset()))

    @staticmethod
    def _const_int(operand: Operand) -> Optional[int]:
        """Resolve ``operand`` to a Python int when it's a known
        integer constant, else ``None``."""
        if isinstance(operand, Const):
            cv = operand
        else:
            cv = getattr(operand, "const_value", None)
        if cv is None or cv.kind != "int":
            return None
        try:
            return int(cv.value)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _ranges_from(
        cls, preds: frozenset[BranchCondition],
    ) -> dict[SSAVar, tuple[Optional[int], Optional[int]]]:
        ranges: dict[SSAVar, tuple[Optional[int], Optional[int]]] = {}
        for p in preds:
            if not isinstance(p.value, SSAVar):
                continue
            # Resolve the comparand to an int. ``zero``/``nonzero``
            # carry an implicit 0; other kinds use ``args[0]``.
            if p.kind in ("zero", "nonzero"):
                arg = 0
            else:
                if not p.args:
                    continue
                arg = cls._const_int(p.args[0])
                if arg is None:
                    continue
            lo, hi = ranges.get(p.value, (None, None))
            if p.kind in ("eq", "zero"):
                lo = arg if lo is None else max(lo, arg)
                hi = arg if hi is None else min(hi, arg)
            elif p.kind == "lt":
                hi = arg - 1 if hi is None else min(hi, arg - 1)
            elif p.kind == "le":
                hi = arg if hi is None else min(hi, arg)
            elif p.kind == "gt":
                lo = arg + 1 if lo is None else max(lo, arg + 1)
            elif p.kind == "ge":
                lo = arg if lo is None else max(lo, arg)
            # ``neq`` / ``nonzero``: would require gap-tracking; skip.
            else:
                continue
            ranges[p.value] = (lo, hi)
        return ranges

    def approving_exits(self) -> list[BasicBlock]:
        """BBs whose last opcode is ``return`` — approving exits in TEAL.

        Only ``return`` and ``err`` legitimately terminate execution
        (running past end-of-program is itself an error). ``err`` BBs
        are excluded as rejecting; ``return`` BBs are included
        regardless of the popped value's const-ness — refining by
        nonzero-only is a possible v2 once a return-value classifier
        is needed.
        """
        out: list[BasicBlock] = []
        for bb in self.prog.blocks.values():
            if not bb.assignments:
                continue
            if bb.assignments[-1].op == "return":
                out.append(bb)
        return out

    def approving_exit_summary(self) -> frozenset[BranchCondition]:
        """Intersection of predicates over every approving exit BB.

        These are facts that hold *on every path that leads to an
        approval* — i.e. what a caller can assume after a successful
        ``itxn_submit`` of this program. Returns the empty set if
        there are no approving exits."""
        exits = self.approving_exits()
        if not exits:
            return frozenset()
        summary: Optional[frozenset[BranchCondition]] = None
        for bb in exits:
            preds = self.bb_preds.get(bb, frozenset())
            summary = preds if summary is None else (summary & preds)
        return summary or frozenset()

    def render(self, *, file: Optional[str] = None) -> str:
        """Per-BB dump of accumulated predicates, sorted by source
        order. Useful for spot-checking the analysis on a fixture."""
        out: list[str] = []
        for bb in sorted(
            self.prog.blocks.values(),
            key=lambda b: (b.file, b.first_line),
        ):
            if file is not None and bb.file != file:
                continue
            preds = self.bb_preds.get(bb, frozenset())
            body = ", ".join(repr(p) for p in sorted(
                preds, key=lambda c: (c.kind, repr(c.value)))
            ) if preds else "(none)"
            out.append(f"BB L{bb.first_line:>3}-L{bb.last_line:<3}  {body}")
        return "\n".join(out)

    def render_annotated(self, *, file: Optional[str] = None) -> str:
        """Per-BB annotated dump: each basic block prints with a
        header banner of its path-aware predicate snapshot
        (must-hold / may-only / XOR pairs), followed by the BB's
        assignments in functional form. The output is meant for
        visual inspection — scan the program from top to bottom and
        see exactly which predicates dominate each region.

        Format roughly:

            // === BB L8-L11 ===
            //   must: (V != 0)
            //   may : (V == 0)
            //   xor : (V == 0) XOR (V != 0)
              L  8: V#1@L8 = txna ApplicationArgs 0 ()
              L 10: V#1@L10 = == (0x101cea00, V#1@L8)
              L 11: bnz main_l13 (V#1@L10)

        Empty BBs (no assignments) are skipped. ``file=`` restricts
        to one source file in a multi-program DB."""
        out: list[str] = []
        for bb in sorted(
            self.prog.blocks.values(),
            key=lambda b: (b.file, b.first_line),
        ):
            if file is not None and bb.file != file:
                continue
            if not bb.assignments:
                continue
            must = self.bb_preds.get(bb, frozenset())
            may = self.bb_may_preds.get(bb, frozenset())
            only_may = may - must
            xor_pairs = find_exclusive_pairs(may)

            out.append(f"// === BB L{bb.first_line}-L{bb.last_line} ===")
            if must:
                must_str = ", ".join(
                    repr(p) for p in sorted(must, key=repr)
                )
                out.append(f"//   must: {must_str}")
            if only_may:
                may_str = ", ".join(
                    repr(p) for p in sorted(only_may, key=repr)
                )
                out.append(f"//   may : {may_str}")
            if xor_pairs:
                xor_str = ", ".join(
                    f"{p!r} XOR {q!r}" for p, q in xor_pairs
                )
                out.append(f"//   xor : {xor_str}")
            for a in bb.assignments:
                out.append(f"  L{a.location.line:>4}: {a.functional()}")
            out.append("")
        return "\n".join(out).rstrip() + "\n"

    def to_dict(self, *, file: Optional[str] = None) -> dict:
        """Structured per-BB dump for JSON output."""
        blocks = []
        for bb in sorted(
            self.prog.blocks.values(),
            key=lambda b: (b.file, b.first_line),
        ):
            if file is not None and bb.file != file:
                continue
            preds = self.bb_preds.get(bb, frozenset())
            blocks.append({
                "file": bb.file,
                "first_line": bb.first_line,
                "last_line": bb.last_line,
                "predicates": [repr(p) for p in sorted(
                    preds, key=lambda c: (c.kind, repr(c.value)))
                ],
            })
        return {"blocks": blocks}

    # -- internals ------------------------------------------------------

    def _compute_may(self) -> None:
        """Forward dataflow with *union* at joins (dual of the
        intersection in :meth:`_compute`). Each BB ends up with every
        predicate that holds on at least one entry-to-BB path. Cheap
        — single worklist pass over the same edge-predicate generator.
        """
        prog = self.prog
        bb_may: dict[BasicBlock, frozenset[BranchCondition]] = {}
        for bb in prog.blocks.values():
            if not bb.predecessors:
                bb_may[bb] = (
                    self.entry_seeds | self.bb_seeds.get(bb, frozenset())
                )
            else:
                bb_may[bb] = frozenset()
        worklist = list(prog.blocks.values())
        while worklist:
            bb = worklist.pop()
            if not bb.predecessors:
                continue
            new_may: set[BranchCondition] = set()
            for pred in bb.predecessors:
                new_may |= bb_may[pred]
                new_may |= self._edge_predicates(pred, bb)
            extra = self.bb_seeds.get(bb)
            if extra:
                new_may |= extra
            new_frozen = frozenset(new_may)
            if new_frozen != bb_may[bb]:
                bb_may[bb] = new_frozen
                for succ in bb.successors:
                    worklist.append(succ)
        self.bb_may_preds = bb_may

    def _index_labels(self) -> dict[tuple[str, str], int]:
        idx: dict[tuple[str, str], int] = {}
        for f, ln, code in self.prog.labels:
            # Label code is the source line, e.g. "l_target:".
            name = code.rstrip(":").strip()
            idx[(f, name)] = ln
        return idx

    def _compute(self) -> None:
        prog = self.prog
        # Initial: TOP everywhere; ``∅`` for BBs with no predecessors
        # (program entry, plus any unreachable BBs — both default to
        # "no constraints" which is the right zero element).
        bb_preds: dict[BasicBlock, object] = {bb: _TOP for bb in prog.blocks.values()}
        for bb in prog.blocks.values():
            if not bb.predecessors:
                bb_preds[bb] = (
                    self.entry_seeds | self.bb_seeds.get(bb, frozenset())
                )
        worklist = list(prog.blocks.values())
        while worklist:
            bb = worklist.pop()
            new_preds: Optional[set[BranchCondition]] = None
            for pred in bb.predecessors:
                pred_preds = bb_preds[pred]
                if pred_preds is _TOP:
                    continue
                edge = self._edge_predicates(pred, bb)
                contribution = set(pred_preds) | edge  # type: ignore[arg-type]
                if new_preds is None:
                    new_preds = contribution
                else:
                    new_preds &= contribution
            if new_preds is None:
                continue  # all predecessors still TOP — defer.
            extra = self.bb_seeds.get(bb)
            if extra:
                new_preds |= extra
            new_frozen = frozenset(new_preds)
            old = bb_preds[bb]
            if old is _TOP or old != new_frozen:
                bb_preds[bb] = new_frozen
                for succ in bb.successors:
                    worklist.append(succ)
        # Replace any surviving TOP (unreachable) with ∅ for downstream
        # consumers that expect a frozenset.
        for bb in list(bb_preds.keys()):
            if bb_preds[bb] is _TOP:
                bb_preds[bb] = frozenset()
        self.bb_preds = bb_preds  # type: ignore[assignment]

    def _edge_predicates(
        self, pred: BasicBlock, succ: BasicBlock
    ) -> frozenset[BranchCondition]:
        """All predicates added on the CFG edge ``pred → succ``, based
        on ``pred``'s last assignment.

        For ``bnz`` / ``bz`` / ``assert``, returns the boolean predicate
        on the cond input *plus* any decomposed predicates when the
        cond is itself an SSAVar produced by a recognisable op
        (binary comparison, ``&&``, ``||``, ``!``). For ``switch`` /
        ``match``, returns the per-target equality (or fall-through
        not-in-range / neq_all). Empty frozenset when the edge carries
        no predicate information (sequential fall-through,
        callsub/retsub edges, ops we don't model)."""
        if not pred.assignments:
            return frozenset()
        last = pred.assignments[-1]
        if not last.inputs:
            return frozenset()
        cond = last.inputs[0]
        if last.op == _ASSERT:
            # An asserter BB has exactly one successor (the success
            # path); the assertion guarantees the value was non-zero.
            return self._decompose_cond(cond, taken=True)
        if last.op in (_BNZ, _BZ):
            target_name = last.immediates.strip()
            target_line = self._label_lines.get((pred.file, target_name))
            if target_line is None:
                return frozenset()
            took_branch = succ.first_line == target_line
            # The cond is "truthy" when bnz fires (taken) or bz doesn't (fall-through).
            taken_means_truthy = (
                (last.op == _BNZ and took_branch)
                or (last.op == _BZ and not took_branch)
            )
            return self._decompose_cond(cond, taken=taken_means_truthy)
        if last.op in (_SWITCH, _MATCH):
            edge = self._switch_or_match_edge(pred, succ, last)
            return frozenset((edge,)) if edge is not None else frozenset()
        return frozenset()

    def _decompose_cond(
        self, cond: Operand, *, taken: bool,
    ) -> frozenset[BranchCondition]:
        """Given a boolean cond at a branch point and whether the
        "truthy" side is being taken, derive every predicate we can
        prove on this edge.

        Always emits the bare ``(cond, nonzero|zero)`` predicate. If
        ``cond`` is an SSAVar whose producing op is a binary comparison
        or a boolean connective (``&&``, ``||``, ``!``), additional
        predicates on the underlying operands are emitted by
        propagating through the op's semantics. The connective rules
        are asymmetric: ``&&`` is fully decomposable on its truthy
        side (both args must be non-zero) but not its falsy side (one
        of them is zero — a disjunction we don't model); ``||`` is
        the mirror image.
        """
        out: set[BranchCondition] = {
            BranchCondition(value=cond, kind="nonzero" if taken else "zero"),
        }
        if not isinstance(cond, SSAVar):
            return frozenset(out)
        producer = cond.defined_by
        if producer is None:
            return frozenset(out)
        op, ins = producer.op, producer.inputs
        # Binary comparisons.
        kind = _CMP_OP_TO_KIND_TAKEN.get(op)
        if kind is not None and len(ins) == 2:
            actual_kind = kind if taken else _KIND_NEGATION[kind]
            out.add(_canonical_binary_pred(ins[0], actual_kind, ins[1]))
            return frozenset(out)
        # ``!``: invert the truthiness on the single operand.
        if op == "!" and len(ins) == 1:
            out |= self._decompose_cond(ins[0], taken=not taken)
            return frozenset(out)
        # ``&&``: only the truthy side is fully decomposable.
        if op == "&&" and len(ins) == 2 and taken:
            out |= self._decompose_cond(ins[0], taken=True)
            out |= self._decompose_cond(ins[1], taken=True)
            return frozenset(out)
        # ``||``: only the falsy side is fully decomposable.
        if op == "||" and len(ins) == 2 and not taken:
            out |= self._decompose_cond(ins[0], taken=False)
            out |= self._decompose_cond(ins[1], taken=False)
            return frozenset(out)
        return frozenset(out)

    def _switch_or_match_edge(
        self, pred: BasicBlock, succ: BasicBlock, last
    ) -> Optional[BranchCondition]:
        """``switch`` and ``match`` carry one predicate per target plus a
        fall-through predicate. The two ops differ in where the
        comparand lives: ``switch`` compares the popped int against
        the target's positional index (0..N-1); ``match`` compares it
        against the corresponding stack-popped candidate.

        Stack convention reminder (top-first ``inputs``):

        - ``switch t0 t1 t2``: pops ``index``. ``inputs = [index]``.
        - ``match t0 t1 t2``: pops ``key`` then candidates v0..vN-1
          (deepest first on the underlying stack). ``inputs[0] = key``;
          ``inputs[1..N]`` are the candidates with ``inputs[N] = v0``
          (deepest pushed first), ``inputs[1] = vN-1`` (most recent
          push, just below the key).
        """
        target_names = last.immediates.split()
        if not target_names:
            return None
        # (target_index, target_line) — None if a target's label is
        # unresolved, kept positional so a missing label doesn't shift
        # the others' indices.
        target_lines: list[Optional[int]] = [
            self._label_lines.get((pred.file, n)) for n in target_names
        ]
        # Identify which target ``succ`` corresponds to (or fall-through).
        target_index: Optional[int] = None
        for k, ln in enumerate(target_lines):
            if ln is not None and succ.first_line == ln:
                target_index = k
                break
        key = last.inputs[0]
        if target_index is not None:
            if last.op == _SWITCH:
                # ``key == target_index`` literal.
                return BranchCondition(
                    value=key,
                    kind="eq",
                    args=(Const("int", str(target_index)),),
                )
            # ``match``: compare against the candidate at this position.
            n_candidates = len(last.inputs) - 1
            if not (0 <= target_index < n_candidates):
                return None
            # ``inputs`` is top-first: candidates appear with the
            # most-recently-pushed (vN-1) at inputs[1] and the
            # earliest-pushed (v0) at inputs[N]. Target k → candidate vk
            # → inputs[N - k].
            candidate = last.inputs[n_candidates - target_index]
            return BranchCondition(
                value=key, kind="eq", args=(candidate,),
            )
        # Fall-through edge.
        if last.op == _SWITCH:
            return BranchCondition(
                value=key, kind="not_in_range",
                args=(0, len(target_names)),
            )
        # ``match`` fall-through: key didn't match any candidate.
        n_candidates = len(last.inputs) - 1
        if n_candidates <= 0:
            return None
        # Order the candidates ``v0 .. vN-1`` for human readability.
        candidates = tuple(reversed(last.inputs[1:1 + n_candidates]))
        return BranchCondition(
            value=key, kind="neq_all", args=candidates,
        )
