"""Per-BB path predicates derived from branch and assert outcomes.

For each :class:`tealql.tealtools.ssa.BasicBlock`, computes the set of
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
    is_const,
)
from .avm import CMP_OPS, LOGICAL_OPS


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
    if is_const(left) and not is_const(right):
        return BranchCondition(value=right, kind=_KIND_FLIP[kind], args=(left,))
    return BranchCondition(value=left, kind=kind, args=(right,))


# Opcodes that read an IMMUTABLE transaction / global field. A subroutine cannot
# change what `txn OnCompletion` (or `global CreatorAddress`, …) reads — these are
# properties of the transaction / group, re-derived by opcode, not stack or
# scratch values. So a predicate rooted ONLY in these survives a `callsub` return
# even though the callee may clobber the caller's stack or scratch (a `dig` /
# `bury` beyond its frame, a `store`). Predicates touching anything else
# (load / dig / frame_dig / app_global_get / a sub parameter / …) are NOT carried.
_TXN_FIELD_READ_OPS = frozenset({
    "txn", "txna", "txnas", "gtxn", "gtxna", "gtxnas",
    "gtxns", "gtxnsa", "gtxnsas", "global",
})

# Pure boolean / comparison combinators: immutable-in ⇒ immutable-out.
_PURE_COMBINATOR_OPS = CMP_OPS | LOGICAL_OPS


def _rooted_in_immutable_fields(v, seen: Optional[set] = None) -> bool:
    """True if every leaf of ``v`` is an immutable transaction/global field read
    or a constant, combined only through pure comparison/boolean ops. Such a
    value cannot be altered by a ``callsub`` (the callee can touch stack/scratch,
    never the txn fields), so a predicate on it is preserved across the return."""
    if is_const(v):
        return True
    if seen is None:
        seen = set()
    if isinstance(v, (SSAVar, Phi)):
        if v in seen:
            return True
        seen.add(v)
        if isinstance(v, Phi):
            return bool(v.args) and all(
                _rooted_in_immutable_fields(a, seen) for a in v.args)
        d = v.defined_by
        if d is None:
            return False                     # param / frame_dig / unknown
        if d.op in _TXN_FIELD_READ_OPS:
            return True
        if d.op in _PURE_COMBINATOR_OPS:
            return all(_rooted_in_immutable_fields(i, seen) for i in d.inputs)
        return False                         # load / app_global_get / arith / …
    return False


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
        self._compute()

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

    def _index_labels(self) -> dict[tuple[str, str], int]:
        idx: dict[tuple[str, str], int] = {}
        for f, ln, code in self.prog.labels:
            # Label code is the source line, e.g. "l_target:".
            name = code.rstrip(":").strip()
            idx[(f, name)] = ln
        return idx

    def _compute(self) -> None:
        prog = self.prog
        # Interprocedural return precision: PathPredicateAnalysis is context-
        # INSENSITIVE — a subroutine reached from N call sites merges (intersects)
        # all callers' facts at its entry, so a caller-specific predicate (e.g.
        # `OnCompletion == 5` asserted before the call) is lost by the time the
        # callee's `retsub` returns. But each return TARGET is reached only via
        # its own call (the return address), so the caller's IMMUTABLE-field
        # predicates do still hold there. Recover them: at a return target, union
        # in the calling block's predicates restricted to the txn/global-rooted
        # subset (sound — the callee can't change those). ``caller_of`` maps a
        # return-target BB -> its calling (callsub) BB; ``return_target_of`` is
        # the reverse, so a change to a caller re-queues its return target.
        caller_of, return_target_of = self._callsub_return_maps()

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
            # Carry the calling block's immutable-field predicates across the
            # return into this return target (see comment above).
            caller = caller_of.get(bb)
            if caller is not None:
                caller_preds = bb_preds[caller]
                if caller_preds is not _TOP:
                    new_preds |= {
                        c for c in caller_preds  # type: ignore[union-attr]
                        if _rooted_in_immutable_fields(c.value)
                        and all(_rooted_in_immutable_fields(a) for a in c.args
                                if isinstance(a, (SSAVar, Phi)))
                    }
            new_frozen = frozenset(new_preds)
            old = bb_preds[bb]
            if old is _TOP or old != new_frozen:
                bb_preds[bb] = new_frozen
                for succ in bb.successors:
                    worklist.append(succ)
                # a callsub block's predicates feed its return target's injection
                rt = return_target_of.get(bb)
                if rt is not None:
                    worklist.append(rt)
        # Replace any surviving TOP (unreachable) with ∅ for downstream
        # consumers that expect a frozenset.
        for bb in list(bb_preds.keys()):
            if bb_preds[bb] is _TOP:
                bb_preds[bb] = frozenset()
        self.bb_preds = bb_preds  # type: ignore[assignment]

    def _callsub_return_maps(self):
        """``(caller_of, return_target_of)``: for each ``callsub`` block C, the
        block B that execution returns to (the next block in source order, whose
        predecessors are ALL ``retsub`` blocks — i.e. B is reached ONLY via the
        return, making it sound to carry C's caller-specific facts there). B with
        any non-return predecessor is skipped (the facts wouldn't hold on the
        other path)."""
        prog = self.prog
        caller_of: dict[BasicBlock, BasicBlock] = {}
        return_target_of: dict[BasicBlock, BasicBlock] = {}
        for c in prog.blocks.values():
            if not c.assignments or c.assignments[-1].op != "callsub":
                continue
            after = [b for b in prog.blocks.values()
                     if b.file == c.file and b.first_line > c.last_line]
            if not after:
                continue
            b = min(after, key=lambda x: x.first_line)
            if b.predecessors and all(
                p.assignments and p.assignments[-1].op == "retsub"
                for p in b.predecessors
            ):
                caller_of[b] = c
                return_target_of[c] = b
        return caller_of, return_target_of

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
        matches = [k for k, ln in enumerate(target_lines)
                   if ln is not None and succ.first_line == ln]
        # A label that appears at MORE THAN ONE switch/match position is reached
        # under a DISJUNCTION of keys (e.g. ``switch a a b`` -> a on key==0 OR
        # key==1). A single ``key == target_index`` predicate would be over-strong
        # (unsound: it claims only one key reaches the edge), so emit no edge
        # predicate rather than a false guard a detector might trust.
        if len(matches) > 1:
            return None
        target_index: Optional[int] = matches[0] if matches else None
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
