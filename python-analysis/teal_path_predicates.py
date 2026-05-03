"""Per-BB path predicates derived from branch and assert outcomes.

For each :class:`teal_ssa.BasicBlock`, computes the set of
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

from teal_ssa import (
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
        - ``"eq"``: value == ``args[0]`` (switch-target-k carries
          ``args = (Const("int", k),)``; match-target-k carries the
          candidate operand for that target).
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
        if self.kind == "not_in_range":
            lo, hi = self.args
            return f"({v} not in [{lo}..{hi - 1}])"
        if self.kind == "neq_all":
            return f"({v} not in {{{', '.join(_disp(a) for a in self.args)}}})"
        return f"({v} ?? {self.kind}{self.args})"


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
                edge = self._edge_predicate(pred, bb)
                contribution = set(pred_preds)  # type: ignore[arg-type]
                if edge is not None:
                    contribution.add(edge)
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

    def _edge_predicate(
        self, pred: BasicBlock, succ: BasicBlock
    ) -> Optional[BranchCondition]:
        """Predicate added on the CFG edge ``pred → succ``, based on
        ``pred``'s last assignment.

        Returns ``None`` when the edge carries no predicate
        information (sequential fall-through, callsub/retsub edges,
        unmodelled ops like ``switch`` / ``match``).
        """
        if not pred.assignments:
            return None
        last = pred.assignments[-1]
        if not last.inputs:
            return None
        cond = last.inputs[0]
        if last.op == _ASSERT:
            # An asserter BB has exactly one successor (the success
            # path); the assertion guarantees the value was non-zero.
            return BranchCondition(value=cond, kind="nonzero")
        if last.op in (_BNZ, _BZ):
            # Resolve the branch's target line via the label index.
            target_name = last.immediates.strip()
            target_line = self._label_lines.get((pred.file, target_name))
            if target_line is None:
                return None
            took_branch = succ.first_line == target_line
            if last.op == _BNZ:
                kind = "nonzero" if took_branch else "zero"
            else:  # _BZ
                kind = "zero" if took_branch else "nonzero"
            return BranchCondition(value=cond, kind=kind)
        if last.op in (_SWITCH, _MATCH):
            return self._switch_or_match_edge(pred, succ, last)
        return None

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
