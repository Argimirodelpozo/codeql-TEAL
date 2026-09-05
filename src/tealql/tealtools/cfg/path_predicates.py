"""Per-BB path predicates derived from branch and assert outcomes.

For each :class:`.ssa.BasicBlock`, the ``(value, outcome)`` pairs that hold on
**every** path from program entry to that BB — the substrate for "guard must
dominate sink" detectors. Forward dataflow, intersecting at joins::

    bb_preds[bb] = ⋂_{p ∈ preds(bb)} ( bb_preds[p] ∪ edge_pred(p, bb) )

HAZARD: edge polarity is the whole analysis. ``bnz l``: target edge ⇒
``nonzero``, fall-through ⇒ ``zero``. ``bz l``: the mirror image. ``assert``:
its single (success) successor ⇒ ``nonzero``. A reversed polarity turns an
absent guard into a proven one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from .dominance import program_entries
from .exits import is_approval_exit
from .subroutines import call_executed_blocks, is_retsub_block, sound_return_targets
from ..ssa import (
    BasicBlock,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    binary_operands,
    const_int,
    is_const,
)
from ..language.avm import (CMP_OPS, COND_BRANCH_OPS, LOGICAL_OPS,
                            MULTIWAY_BRANCH_OPS, op_arity)
from .build import BOOL_FALSE, BOOL_TRUE
from ..ast.literals import render_byte_constant
from ..analysis import FactDomain


Operand = Union[SSAVar, Phi, Const]


@dataclass(frozen=True)
class BranchCondition:
    """A predicate on an SSA value, derived from a dominated branch.

    Identity is ``(value, kind, args)`` so predicates can be set-intersected at
    joins; ``args`` must be a tuple of hashables (Const / SSAVar / Phi / int / str).

    HAZARD: ``kind`` encodes branch polarity. ``nonzero`` = bnz-taken /
    bz-not-taken / asserted; ``zero`` is its complement. ``eq`` / ``neq`` /
    ``lt`` / ``le`` / ``gt`` / ``ge`` relate ``value`` to ``args[0]`` in SOURCE
    order. ``not_in_range`` = ``value`` ∉ ``[args[0]..args[1] - 1]`` (switch
    fall-through); ``neq_all`` = ``value`` equals no operand in ``args`` (match
    fall-through).
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


# Branch-TAKEN → kind. HAZARD: the not-taken side is the `_KIND_NEGATION` of the
# same entry, never the entry itself. `b`-prefixed byte variants share the kinds;
# consumers that care about width inspect the operand types.
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


# Swapping operands flips an ordered relation (``a < b`` ↔ ``b > a``); equality
# and inequality are symmetric.
_KIND_FLIP: dict[str, str] = {
    "eq": "eq", "neq": "neq",
    "lt": "gt", "gt": "lt",
    "le": "ge", "ge": "le",
}


def _canonical_binary_pred(
    left: Operand, kind: str, right: Operand,
) -> BranchCondition:
    """Put the variable side left when the other operand is constant, so
    consumers only handle one form.

    HAZARD: the swap MUST flip an ordered relation to preserve semantics
    (``5 < V`` ↦ ``V > 5``). Const-resolved SSAVars count as constants here."""
    if is_const(left) and not is_const(right):
        return BranchCondition(value=right, kind=_KIND_FLIP[kind], args=(left,))
    return BranchCondition(value=left, kind=kind, args=(right,))


# Opcodes reading an IMMUTABLE transaction / global field.
#
# HAZARD: a predicate rooted ONLY in these survives a `callsub` return
# unconditionally — the callee cannot change the transaction. Any OTHER leaf
# (load / app_global_get / arith / …) survives only under the block criterion
# of `_rooted_walk(executed=...)`: its definition must lie outside every block
# the call may execute (:func:`.subroutines.call_executed_blocks`), so the SSA
# value the predicate is about is provably not recomputed by the call. Without
# that set (unit callers, an unresolved callee) such leaves are refused — the
# `_rooted_in_immutable_fields` tests pin that fallback.
from ..language.avm import UNSTABLE_GLOBAL_FIELDS

_TXN_FIELD_READ_OPS = frozenset({
    "txn", "txna", "txnas", "gtxn", "gtxna", "gtxnas",
    "gtxns", "gtxnsa", "gtxnsas", "global",
})

# Pure boolean / comparison combinators: immutable-in ⇒ immutable-out.
_PURE_COMBINATOR_OPS = CMP_OPS | LOGICAL_OPS

#: Reads whose SSA value is fixed once computed, so a predicate on one carries
#: across a ``callsub`` when its defining block lies OUTSIDE everything the call
#: executes (:func:`.subroutines.call_executed_blocks`). Deliberately a short
#: list of LEAF reads (their operands still have to be rooted): admitting ANY
#: out-of-call definition was equally sound but let every phi/loop-carried
#: value in a big caller be re-walked on every fixpoint visit (cycle results
#: are never memoised) — one mainnet probe went from 20s to >10min. This bounds
#: the walk shape, not the soundness.
_CALL_STABLE_READ_OPS = frozenset({
    "app_global_get", "app_global_get_ex", "app_local_get", "app_local_get_ex",
    "box_get", "box_extract", "box_len", "load", "loads", "gload", "gloads",
    "gloadss", "app_params_get", "asset_params_get", "asset_holding_get",
    "acct_params_get", "balance", "min_balance",
})


def _rooted_in_immutable_fields(v, seen: Optional[set] = None,
                                memo: Optional[dict] = None,
                                executed: Optional[frozenset] = None) -> bool:
    """True if a predicate on ``v`` survives a ``callsub`` return: every leaf is
    an immutable txn/global field read or a constant (combined only through
    pure comparison/boolean ops), OR — when ``executed`` (the blocks the call
    may run, :func:`.subroutines.call_executed_blocks`) is given — a value whose
    definition lies outside ``executed``, so the call cannot recompute it.

    HAZARD: ``memo`` must stay PER-ANALYSIS and PER-``executed``. ``SSAVar``
    hashes by ``(file, line, index)``, so a module-level cache collides across
    two programs sharing a basename, and the block criterion's answer depends on
    the call site. A result whose walk took the ``seen`` cycle short-circuit is
    likewise never cached — it holds only for that traversal."""
    return _rooted_walk(v, set() if seen is None else seen,
                        {} if memo is None else memo, executed)[0]


def _rooted_walk(v, seen: set, memo: dict,
                 executed: Optional[frozenset] = None) -> "tuple[bool, bool]":
    """``(survives_the_call, took_a_cycle_shortcut)``."""
    if is_const(v):
        return True, False
    if not isinstance(v, (SSAVar, Phi)):
        return False, False
    if v in memo:
        return memo[v], False
    if v in seen:
        return True, True                    # cycle: neutral for the conjunction
    seen.add(v)
    try:
        if isinstance(v, Phi):
            parts, ok = v.args, bool(v.args)
        else:
            d = v.defined_by
            if d is None:
                return _cache(memo, v, False)         # param / frame_dig / unknown
            if d.op in _TXN_FIELD_READ_OPS:
                # HAZARD: `global` is in that set, but not every global field is
                # execution-stable. `OpcodeBudget` DECREASES as the program runs,
                # so a callee consumes it and a predicate on it does NOT survive
                # the return — carrying it claims a budget that has been spent.
                if (d.op == "global"
                        and d.immediates.strip() in UNSTABLE_GLOBAL_FIELDS):
                    return _cache(memo, v, False)
                return _cache(memo, v, True)
            if d.op not in _PURE_COMBINATOR_OPS and not (
                    executed is not None
                    and d.op in _CALL_STABLE_READ_OPS
                    and d.basic_block is not None
                    and d.basic_block not in executed):
                # arith / a read the call may re-run (or with no executed-set
                # to check against) / any non-leaf op: see _CALL_STABLE_READ_OPS.
                return _cache(memo, v, False)
            parts, ok = d.inputs, True
        cut = False
        if ok:
            for part in parts:
                rooted, part_cut = _rooted_walk(part, seen, memo, executed)
                cut = cut or part_cut
                if not rooted:
                    ok = False
                    break
    finally:
        seen.discard(v)
    if not cut:
        memo[v] = ok
    return ok, cut


def _cache(memo: dict, v, result: bool) -> "tuple[bool, bool]":
    memo[v] = result
    return result, False


def _disp(op) -> str:
    """Compact rendering for an :class:`Operand`, resolving ``const_value`` to a literal."""
    if isinstance(op, Const):
        return render_byte_constant(op.value)
    cv = getattr(op, "const_value", None)
    if cv is not None:
        return render_byte_constant(cv.value)
    return repr(op)


# Lattice top for the fixpoint: "not computed yet", distinct from ∅ ("no
# constraints") — a BB at ∅ is a real answer, a BB at TOP must not be read.
class _Top:
    __slots__ = ()

    def __repr__(self) -> str:
        return "TOP"


_TOP = _Top()


def predicates_contradict(conditions, facts=None) -> bool:
    """Whether a conjunction of lightweight branch predicates is infeasible.

    This is deliberately a unary constant/range domain, not a general solver.
    It codifies complement pairs, distinct equalities, ordered constant bounds,
    switch/match exclusions, and unconditional value ranges.  Unsupported
    symbolic relations simply contribute no contradiction proof.
    """
    states: dict[Operand, dict] = {}

    def state(value):
        current = states.get(value)
        if current is not None:
            return current
        lo, hi = 0, (1 << 64) - 1
        exact = None
        if facts is not None:
            constant = facts.constant(value)
            if constant is not None:
                exact = constant
            value_range = facts.int_range(value)
            if value_range is not None:
                lo, hi = value_range.lo, value_range.hi
        if is_const(value):
            exact = value
        current = {
            "lo": lo, "hi": hi, "exact": exact,
            "excluded": set(), "excluded_ranges": [],
        }
        states[value] = current
        return current

    for condition in conditions:
        current = state(condition.value)
        kind, args = condition.kind, condition.args
        rhs = args[0] if args else None
        rhs_int = const_int(rhs) if rhs is not None else None
        if kind == "zero":
            zero = Const("int", "0")
            previous = current["exact"]
            if previous is not None and previous != zero:
                return True
            current["exact"] = zero
        elif kind == "nonzero":
            current["excluded"].add(Const("int", "0"))
        elif kind == "eq" and rhs is not None and is_const(rhs):
            previous = current["exact"]
            if previous is not None and previous != rhs:
                return True
            current["exact"] = rhs
        elif kind == "neq" and rhs is not None and is_const(rhs):
            current["excluded"].add(rhs)
        elif rhs_int is not None:
            if kind == "lt":
                current["hi"] = min(current["hi"], rhs_int - 1)
            elif kind == "le":
                current["hi"] = min(current["hi"], rhs_int)
            elif kind == "gt":
                current["lo"] = max(current["lo"], rhs_int + 1)
            elif kind == "ge":
                current["lo"] = max(current["lo"], rhs_int)
        if kind == "not_in_range" and len(args) >= 2:
            lo, hi = args[:2]
            if isinstance(lo, int) and isinstance(hi, int):
                current["excluded_ranges"].append((lo, hi - 1))
        elif kind == "neq_all":
            current["excluded"].update(arg for arg in args if is_const(arg))

    for current in states.values():
        lo, hi, exact = current["lo"], current["hi"], current["exact"]
        if lo > hi:
            return True
        if exact is not None:
            if exact in current["excluded"]:
                return True
            exact_int = const_int(exact)
            if exact_int is not None:
                if not lo <= exact_int <= hi:
                    return True
                if any(a <= exact_int <= b for a, b in current["excluded_ranges"]):
                    return True
            continue
        # Exhaustion is cheap and useful for finite enum/range facts, while the
        # cap prevents a uint64-wide iteration.
        if hi - lo <= 256:
            excluded_ints = {
                value for item in current["excluded"]
                if (value := const_int(item)) is not None
            }
            if all(
                value in excluded_ints
                or any(a <= value <= b for a, b in current["excluded_ranges"])
                for value in range(lo, hi + 1)
            ):
                return True
    return False


# Branch / assert opcodes that contribute predicates.
_ASSERT = "assert"
#: ``switch`` is named on its own because its arms are POSITIONAL (arm k means
#: `key == k`), which `match` does not share. The branch FAMILIES themselves are
#: never re-listed — they come from the avm spec sets.
_SWITCH = "switch"


class PathPredicateAnalysis:
    """Branch/assert predicates that must hold on every path to each BB."""

    def __init__(
        self,
        prog: SSAProgram,
        *,
        entry_seeds: frozenset[BranchCondition] = frozenset(),
        bb_seeds: Optional[dict[BasicBlock, frozenset[BranchCondition]]] = None,
    ):
        """``entry_seeds`` hold at every program-entry BB before any branch
        (cross-contract caller-side facts); ``bb_seeds`` hold at named BBs
        regardless of join inputs (facts injected by an external event such as a
        successful ``itxn_submit``), unioned in AFTER the predecessor
        intersection on every recomputation."""
        self.prog = prog
        # Resolve stable input/shuffle/scratch identities through an immutable
        # relation.  Rewriting the shared SSA here used to make every later
        # detector depend on whether path predicates happened to run first.
        self._facts = prog.facts(FactDomain.CONSTANTS, FactDomain.RANGES)
        self.entry_seeds = entry_seeds
        self.bb_seeds: dict[BasicBlock, frozenset[BranchCondition]] = (
            bb_seeds or {}
        )
        # Label -> BLOCK, to resolve switch/match immediates (shared resolver:
        # first definition wins like the builder, empty label -> next block).
        from .labels import LabelIndex
        self._labels = LabelIndex(prog)
        self.bb_preds: dict[BasicBlock, frozenset[BranchCondition]] = {}
        self._compute()

    def _operand(self, value):
        if not hasattr(self, "_facts"):  # synthetic unit-level value webs
            return value
        constant = self._facts.constant(value)
        return constant if constant is not None else self._facts.resolve(value)

    def _lexical_fall_through_line(self, file: str, line: int) -> Optional[int]:
        """First line of the block lexically FOLLOWING ``line`` in ``file`` —
        where a switch/match at ``line`` falls through. ``None`` at file end."""
        starts = getattr(self, "_block_starts", None)
        if starts is None:
            starts = {}
            for bb in self.prog.blocks.values():
                starts.setdefault(bb.file, []).append(bb.first_line)
            for lines in starts.values():
                lines.sort()
            self._block_starts = starts
        import bisect
        lines = starts.get(file, ())
        i = bisect.bisect_right(lines, line)
        return lines[i] if i < len(lines) else None

    # -- public ---------------------------------------------------------

    def predicates_at(
        self, file: str, line: int
    ) -> frozenset[BranchCondition]:
        """Predicates holding on every path to ``(file, line)``; empty if it is in no BB."""
        bb = self.prog.block_containing(file, line)
        if bb is None:
            return frozenset()
        return self.bb_preds.get(bb, frozenset())

    def edge_predicates(
        self, pred: BasicBlock, succ: BasicBlock,
    ) -> frozenset[BranchCondition]:
        """Predicates contributed specifically by ``pred -> succ``."""
        return self._edge_predicates(pred, succ)

    def evidence_at(self, file: str, line: int):
        """Must predicates scoped to one use; assertion dependencies are separate.

        The point is where the fact holds, not a claim about the instruction
        that established it. Consumers must match the subject and relation.
        """
        from ..diagnostics.evidence import GuardEvidence
        from ..diagnostics.location import InstructionPoint
        return tuple(GuardEvidence(
            str(p.value), p.kind, ', '.join(map(str, p.args)),
            InstructionPoint(file, line), scope=(file,), extent=(line, line),
            basis='must-predicate',
        ) for p in sorted(self.predicates_at(file, line), key=str))

    def edge_is_feasible(self, pred: BasicBlock, succ: BasicBlock) -> bool:
        """False only when entry plus edge facts prove a contradiction."""
        conditions = (
            self.bb_preds.get(pred, frozenset())
            | self._edge_predicates(pred, succ)
        )
        return not predicates_contradict(conditions, self._facts)

    def approving_exits(self) -> list[BasicBlock]:
        """BBs whose last opcode is an APPROVING ``return``, per
        :func:`.cfg.exits.is_approval_exit`.

        ``err`` BBs and a ``return`` of the constant ``0`` are rejecting and are
        excluded, so reject-path facts never intersect into
        :meth:`approving_exit_summary`; a non-constant return value stays in.

        The shared exit classifier reads ``return``'s explicit approval
        operand. Do not recover it from the preceding instruction: propagation
        may redirect the value and an intervening stack operation is legal.
        """
        return [bb for bb in self.prog.blocks.values() if is_approval_exit(bb)]

    def approving_exit_summary(self) -> frozenset[BranchCondition]:
        """Predicates common to every approving exit — what a caller may assume
        after a successful ``itxn_submit``; empty if nothing approves."""
        exits = self.approving_exits()
        if not exits:
            return frozenset()
        summary: Optional[frozenset[BranchCondition]] = None
        for bb in exits:
            preds = self.bb_preds.get(bb, frozenset())
            summary = preds if summary is None else (summary & preds)
        return summary or frozenset()

    def render(self, *, file: Optional[str] = None) -> str:
        """Per-BB dump of accumulated predicates, in source order."""
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

    def _compute(self) -> None:
        prog = self.prog
        # Context-INSENSITIVE: a subroutine intersects all callers' facts at its
        # entry, so a caller-specific predicate is gone by `retsub`. But a
        # `retsub` EDGE into a return target is taken only when returning from
        # that target's own call site, so the caller's call-stable predicates
        # are unioned into that edge's contribution (per EDGE: a `b` into the
        # same label is a different path and keeps only its own facts).
        # `caller_of`: return-target BB → its callsub BB; `return_target_of` is
        # the reverse, so a change to a caller re-queues its return target.
        caller_of, return_target_of = self._callsub_return_maps()
        # Which facts survive: field-rooted ones always; anything else only when
        # defined outside the blocks the call may execute (`None` = unknown
        # closure, field-only). Memos are per call site — the block criterion's
        # answer is (see _rooted_in_immutable_fields).
        executed_during = call_executed_blocks(prog)
        rooted_memos: dict = {}

        # Initial: TOP everywhere; ∅ for BBs with no predecessors (unreachable
        # BBs and the usual no-pred program entry).
        #
        # HAZARD: a program entry that HAS predecessors (its first block is a
        # branch target — a top-level loop) must also contribute a VIRTUAL
        # fresh-entry path to its own meet below. Execution reaches it from
        # outside carrying only the entry seeds, so anything the back edge
        # carries must be intersected against that path or it gets credited to
        # executions that never looped.
        program_entry_set = set(program_entries(prog.blocks.values()))
        bb_preds: dict[BasicBlock, object] = {bb: _TOP for bb in prog.blocks.values()}
        for bb in prog.blocks.values():
            if not bb.predecessors or bb in program_entry_set:
                bb_preds[bb] = (
                    self.entry_seeds | self.bb_seeds.get(bb, frozenset())
                )
        worklist = list(prog.blocks.values())
        while worklist:
            bb = worklist.pop()
            new_preds: Optional[set[BranchCondition]] = None
            if bb in program_entry_set:
                new_preds = set(self.entry_seeds)
            carried = self._carried_across_return(
                bb, caller_of, bb_preds, executed_during, rooted_memos)
            for pred in bb.predecessors:
                pred_preds = bb_preds[pred]
                if pred_preds is _TOP:
                    continue
                edge = self._edge_predicates(pred, bb)
                contribution = set(pred_preds) | edge  # type: ignore[arg-type]
                if carried and is_retsub_block(pred):
                    contribution |= carried
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
                # a callsub block's predicates feed its return target's injection
                rt = return_target_of.get(bb)
                if rt is not None:
                    worklist.append(rt)
        # Surviving TOP means unreachable; hand downstream a frozenset.
        for bb in list(bb_preds.keys()):
            if bb_preds[bb] is _TOP:
                bb_preds[bb] = frozenset()
        self.bb_preds = bb_preds  # type: ignore[assignment]

    @staticmethod
    def _carried_across_return(bb, caller_of, bb_preds, executed_during,
                               rooted_memos) -> Optional[set]:
        """The call site's predicates that survive the call into return target
        ``bb`` (for its ``retsub`` in-edges); ``None`` when ``bb`` is no return
        target or its call site is still TOP (the caller's change re-queues it)."""
        caller = caller_of.get(bb)
        if caller is None:
            return None
        caller_preds = bb_preds[caller]
        if caller_preds is _TOP:
            return None
        executed = executed_during.get(caller)
        memo = rooted_memos.setdefault(caller, {})
        return {
            c for c in caller_preds
            if _rooted_in_immutable_fields(c.value, memo=memo, executed=executed)
            and all(
                _rooted_in_immutable_fields(a, memo=memo, executed=executed)
                for a in c.args if isinstance(a, (SSAVar, Phi)))
        }

    def _callsub_return_maps(self):
        """``(caller_of, return_target_of)`` under :func:`.subroutines.sound_return_targets`."""
        return sound_return_targets(self.prog)

    def _edge_predicates(
        self, pred: BasicBlock, succ: BasicBlock
    ) -> frozenset[BranchCondition]:
        """Predicates added on the CFG edge ``pred → succ`` by ``pred``'s last
        assignment; empty when the edge carries none (sequential fall-through,
        callsub/retsub edges, unmodelled ops)."""
        if not pred.assignments:
            return frozenset()
        last = pred.assignments[-1]
        if not last.inputs:
            return frozenset()
        cond = self._operand(last.inputs[0])
        if last.op == _ASSERT:
            # The single successor is the success path: the value was non-zero.
            return self._decompose_cond(cond, taken=True)
        if last.op in COND_BRANCH_OPS:
            # Polarity comes from the CFG BUILDER, which already resolved this
            # branch's target — including a duplicate label, where it takes the
            # FIRST definition. Re-deriving it here from a second label map is
            # how the two could disagree, and a disagreement INVERTS the
            # predicate: `true` means the condition was non-zero on this edge.
            #
            # HAZARD: `bnz next` to the immediately-following label collapses
            # both arms onto ONE successor, which shows up as BOTH labels on the
            # pair. The branch does not partition flow there, so neither the
            # taken nor the fall-through predicate holds.
            kinds = self.prog.edge_polarity.get(
                (pred._key(), succ._key()), frozenset())
            if len(kinds) != 1:
                return frozenset()
            (kind,) = kinds
            if kind not in (BOOL_TRUE, BOOL_FALSE):
                return frozenset()
            return self._decompose_cond(cond, taken=(kind == BOOL_TRUE))
        if last.op in MULTIWAY_BRANCH_OPS:
            edge = self._switch_or_match_edge(pred, succ, last)
            if edge is None:
                return frozenset()
            return frozenset({edge, *self._router_predicates(edge)})
        return frozenset()

    def _router_predicates(self, edge):
        """Decode Puya's (!ApplicationID)*6 + OnCompletion switch key.

        The multiplier and both immutable current-transaction fields are
        required. Existing collapsed-edge checks run before this decomposition.
        """
        if edge.kind != "eq" or not edge.args:
            return ()
        index = const_int(edge.args[0])
        definition = getattr(edge.value, "defined_by", None)
        if index is None or not 0 <= index < 12 or definition is None or definition.op != "+":
            return ()
        def field(value, name):
            d = getattr(value, "defined_by", None)
            return d is not None and d.op == "txn" and d.immediates.strip() == name
        operands = [self._operand(v) for v in definition.inputs]
        for completion in operands:
            if not field(completion, "OnCompletion"):
                continue
            scaled = next((v for v in operands if v is not completion), None)
            multiply = getattr(scaled, "defined_by", None)
            if multiply is None or multiply.op != "*" or len(multiply.inputs) != 2:
                continue
            parts = [self._operand(v) for v in multiply.inputs]
            for part, factor in ((parts[0], parts[1]), (parts[1], parts[0])):
                negate = getattr(part, "defined_by", None)
                if const_int(factor) != 6 or negate is None or negate.op != "!" or len(negate.inputs) != 1:
                    continue
                app_id = self._operand(negate.inputs[0])
                if field(app_id, "ApplicationID"):
                    return (BranchCondition(completion, "eq", (Const("int", str(index % 6)),)),
                            BranchCondition(app_id, "zero" if index >= 6 else "nonzero"))
        return ()

    def _decompose_cond(
        self, cond: Operand, *, taken: bool,
    ) -> frozenset[BranchCondition]:
        """Every predicate provable on this edge for ``cond``, given which side
        (``taken`` = truthy) is taken — the bare ``nonzero``/``zero`` plus any
        decomposition through a comparison or ``&&`` / ``||`` / ``!`` producer.

        HAZARD: the connective rules are ASYMMETRIC. ``&&`` decomposes only on
        its TRUTHY side (both args non-zero); its falsy side is a disjunction we
        don't model. ``||`` is the mirror image. Decomposing the other side
        invents a guard that isn't there.
        """
        # Iterative, not recursive: a long `a && b && ...` chain nests thousands
        # deep and a cyclic value web (a phi feeding its own guard) is unbounded
        # — either blows the recursion limit. `seen` makes it cycle-safe.
        out: set[BranchCondition] = set()
        seen: set = set()
        stack: list = [(cond, taken)]
        while stack:
            c, t = stack.pop()
            c = self._operand(c)
            key = (id(c), t)
            if key in seen:
                continue
            seen.add(key)
            out.add(BranchCondition(value=c, kind="nonzero" if t else "zero"))
            if not isinstance(c, SSAVar):
                continue
            producer = c.defined_by
            if producer is None:
                continue
            op, ins = producer.op, producer.inputs
            # HAZARD: operands are TOP-FIRST, so SOURCE-order ``lhs OP rhs`` is
            # ``inputs[1] OP inputs[0]``. Always go through ``binary_operands``
            # or a non-commutative relation (``>=`` / ``<`` …) is silently
            # flipped and the guard's polarity inverts.
            kind = _CMP_OP_TO_KIND_TAKEN.get(op)
            if kind is not None and len(ins) == 2:
                actual_kind = kind if t else _KIND_NEGATION[kind]
                lhs, rhs = (self._operand(value) for value in binary_operands(producer))
                out.add(_canonical_binary_pred(lhs, actual_kind, rhs))
                continue
            # ``!``: invert the truthiness on the single operand.
            if op == "!" and len(ins) == 1:
                stack.append((self._operand(ins[0]), not t))
                continue
            # ``&&``: only the truthy side is fully decomposable.
            if op == "&&" and len(ins) == 2 and t:
                stack.append((self._operand(ins[0]), True))
                stack.append((self._operand(ins[1]), True))
                continue
            # ``||``: only the falsy side is fully decomposable.
            if op == "||" and len(ins) == 2 and not t:
                stack.append((self._operand(ins[0]), False))
                stack.append((self._operand(ins[1]), False))
        return frozenset(out)

    def _switch_or_match_edge(
        self, pred: BasicBlock, succ: BasicBlock, last
    ) -> Optional[BranchCondition]:
        """One predicate per ``switch`` / ``match`` target plus a fall-through
        one: ``switch`` compares the popped int against the target's positional
        index (0..N-1), ``match`` against the correspondingly-popped candidate.

        HAZARD: ``inputs`` is TOP-FIRST. ``switch t0 t1 t2`` → ``inputs = [index]``.
        ``match t0 t1 t2`` → ``inputs[0] = key`` and the candidates fill
        ``inputs[1..N]`` REVERSED: ``inputs[N] = v0`` (pushed first/deepest),
        ``inputs[1] = vN-1`` (pushed last). Target ``k`` is ``inputs[N - k]``.

        HAZARD: that positional read is only meaningful when EVERY operand is
        present. The public ``inputs`` DROP an unresolved cell (an unsafe
        callee's withdrawn residual, a poisoned frame read), which shifts every
        deeper candidate one position up — and a missing KEY makes the top
        candidate pose as the key. Refuse unless the op's arity is met.
        """
        target_names = last.immediates.split()
        if not target_names:
            return None
        n_in, _ = op_arity(last.op, last.immediates)
        if len(last.inputs) != n_in:
            return None
        # The BLOCK each target lands on (None for an unresolved label or one
        # at EOF), kept POSITIONAL so a missing one doesn't shift the other
        # targets' indices. By block, not line: an EMPTY label (alias) owns no
        # block, so its line matches no successor and the arm would read as
        # the fall-through; resolved to the next real block instead, two
        # aliased targets land on ONE block and the disjunction refusal below
        # sees them.
        targets: list = [self._labels.block(pred.file, n) for n in target_names]
        # Which target ``succ`` corresponds to (or fall-through).
        matches = [k for k, t in enumerate(targets)
                   if t is not None and t._key() == succ._key()]
        # HAZARD: a label at MORE THAN ONE position is reached under a
        # DISJUNCTION of keys (``switch a a b`` → a on key==0 OR key==1), so a
        # single ``key == target_index`` would be over-strong. Emit nothing
        # rather than a false guard a detector will trust.
        if len(matches) > 1:
            return None
        # HAZARD: same collapsed-edge trap as bnz/bz — when the instruction
        # after the switch/match IS one of its targets, the target edge and the
        # fall-through edge land on the SAME successor. That block is also
        # reached with the key OUT of range, so ``key == k`` would let any other
        # key bypass the "guard".
        if len({s.first_line for s in pred.successors}) < 2:
            return None
        target_index: Optional[int] = matches[0] if matches else None
        # HAZARD: the collapsed-edge trap is PER-ARM, not just all-arms. With
        # another distinct target present, the arm that is ALSO the lexical
        # fall-through still carries both roles: the AVM reaches it for every
        # out-of-range (switch) / unmatched (match) key, so ``key == k`` on
        # that edge is a proven-guard-that-isn't. Refuse that arm only.
        if (target_index is not None
                and succ.first_line == self._lexical_fall_through_line(
                    pred.file, last.location.line)):
            return None
        key = self._operand(last.inputs[0])
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
            # Top-first: target k → candidate vk → ``inputs[N - k]``.
            candidate = self._operand(last.inputs[n_candidates - target_index])
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
        candidates = tuple(
            self._operand(value)
            for value in reversed(last.inputs[1:1 + n_candidates])
        )
        return BranchCondition(
            value=key, kind="neq_all", args=candidates,
        )
