"""Shared helpers for the sec-guide detectors.

The common helper layer (OnCompletion guards, fee-validation guards, …)
on top of the :class:`SSAProgram` substrate and
:class:`PathPredicateAnalysis`. Each detector module imports the
predicates it needs from here rather than rebuilding them.

Where possible, we lean on :meth:`PathPredicateAnalysis.predicates_at` for
"must hold on every path" reasoning — it's already a sound, cached
abstraction over branch / assert outcomes. Hand-rolled CFG reachability
only shows up in :func:`approval_exit_protected_for_field` (which is
strictly stronger than what path predicates alone can express).

The detector outputs are intentionally over-conservative on several
fixtures (e.g. ``is-deletable`` flags ``fixed-complex-dispatch.teal``
because the OnCompletion==5 reject sits *after* the dispatch). This is a
deliberate choice — the goal is soundness, not strictly tighter
detection. Improvements live in follow-ups.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import (
    Assignment,
    BasicBlock,
    Const,
    Phi,
    SSAProgram,
    SSAVar,
    const_int,
    is_field_var,
)
from tealtools.cfg.dominance import iterative_dominators
from tealtools.opsets import CMP_OPS

logger = logging.getLogger("security.common")


# ---------------------------------------------------------------------------
# OnCompletion constants (AVM spec)
# ---------------------------------------------------------------------------


ONC_NOOP = 0
ONC_OPTIN = 1
ONC_CLOSEOUT = 2
ONC_CLEAR_STATE = 3
ONC_UPDATE_APPLICATION = 4
ONC_DELETE_APPLICATION = 5


# ---------------------------------------------------------------------------
# Approval / rejection exits
# ---------------------------------------------------------------------------


def _is_const_zero(operand) -> bool:
    return const_int(operand) == 0


def _return_likely_zero(bb: BasicBlock) -> bool:
    """Heuristic for ``int 0; return``: the SSA model strips the
    ``return`` opcode's stack input, so we can't read the return
    value off ``last.inputs``. The next-best signal is the BB's
    second-to-last assignment — if it produces a const-int 0 SSAVar
    that nothing else consumes, the program is almost certainly
    returning 0.

    Conservative: when in doubt, return False (so the BB stays
    classified as a potential approval and downstream analyses see it).
    An approval exit includes returns whose value isn't statically
    resolvable."""
    if len(bb.assignments) < 2:
        return False
    if bb.assignments[-1].op != "return":
        return False
    prev = bb.assignments[-2]
    if not prev.outputs:
        return False
    out = prev.outputs[0]
    return _is_const_zero(out)


def is_approval_exit(bb: BasicBlock) -> bool:
    """An approval exit: BB ends in ``return`` and the return value is
    non-zero or its constness is unknown.

    The SSA model in :mod:`tealtools.ssa` represents ``return`` with
    an empty stack-input list (``last.inputs == []``); we recover the
    likely return value via :func:`_return_likely_zero`. A BB whose
    ``int 0; return`` shape we can prove is excluded; everything else
    counts as approval-or-unknown."""
    if not bb.assignments:
        return False
    if bb.assignments[-1].op != "return":
        return False
    return not _return_likely_zero(bb)


def is_rejection_exit(bb: BasicBlock) -> bool:
    """A rejection exit: BB ends in ``err`` or ``return 0``."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "err":
        return True
    if last.op == "return" and _return_likely_zero(bb):
        return True
    return False


# ---------------------------------------------------------------------------
# File-scoped iteration
#
# Most helpers below accept an optional ``file: Optional[str] = None``
# kwarg. When set, the iteration is restricted to ops/blocks whose
# ``location.file == file``. This is what lets a single
# :class:`SSAProgram` built from a multi-program directory (one program per
# dir, several .teal files inside) be analysed program-by-program by
# threading the filename through every iteration.
# ---------------------------------------------------------------------------


def file_match(loc_file: str, want: Optional[str]) -> bool:
    return want is None or loc_file == want


def has_instructions(prog: SSAProgram, *, file: Optional[str] = None) -> bool:
    """True when the program (scoped to ``file`` if given) parsed to at
    least one instruction. ABSENCE-style detectors ("no X validation
    anywhere → finding") must check this first: a degenerate program —
    empty, or fully dropped by parse diagnostics — trivially "lacks"
    every validation, and reporting a contract-shaped finding about it
    would dress up *we could not analyze this* as *this is vulnerable*."""
    return any(
        file_match(a.location.file, file) for a in prog.assignments
    )


def approving_exits(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[BasicBlock]:
    """Every BB that is an approval exit.

    Stricter than :meth:`PathPredicateAnalysis.approving_exits` — that
    method includes every ``return`` regardless of operand constness;
    here we exclude provably-zero returns.

    ``file``: restrict to BBs in this source file (basename); if None,
    every BB across the loaded program."""
    return [
        bb for bb in prog.blocks.values()
        if file_match(bb.file, file) and is_approval_exit(bb)
    ]


def txn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txn FIELD`` assignment in ``prog``. Includes the bare
    ``txn`` op only — ``gtxn``, ``itxn``, etc. are separate
    predicates."""
    return [
        a for a in prog.assignments
        if a.op == "txn" and a.immediates.strip() == field
        and file_match(a.location.file, file)
    ]


def gtxn_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every group-transaction field read of ``field``, across both
    immediate-index and dynamic-index variants:

    - ``gtxn N FIELD`` / ``gtxna N FIELD I`` / ``gtxnas N FIELD``
      — group index in the first immediate, field in the second.
    - ``gtxns FIELD`` / ``gtxnsa FIELD I`` / ``gtxnsas FIELD``
      — group index popped off the stack, field in the first immediate.

    The mapping covers the ``gtxn``/``gtxns`` opcode families."""
    out: list[Assignment] = []
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        toks = a.immediates.split()
        if a.op in ("gtxn", "gtxna", "gtxnas") and len(toks) >= 2 and toks[1] == field:
            out.append(a)
        elif a.op in ("gtxns", "gtxnsa", "gtxnsas") and toks and toks[0] == field:
            out.append(a)
    return out


def global_field_reads(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``global FIELD`` assignment in ``prog``."""
    return [
        a for a in prog.assignments
        if a.op == "global" and a.immediates.strip() == field
        and file_match(a.location.file, file)
    ]


def ssavar_outputs(assignments) -> set:
    """The set of :class:`SSAVar` outputs across a collection of assignments —
    the canonical "seed set" builder for the value-flow bridge."""
    return {o for a in assignments for o in a.outputs if isinstance(o, SSAVar)}


def op_output_seeds(
    prog: SSAProgram, op: str, *, file: Optional[str] = None,
) -> set:
    """SSAVar outputs of every ``op`` assignment (file-matched) — a seed set the
    flow bridge follows through scratch / phi / proto-frame."""
    return ssavar_outputs(
        a for a in prog.assignments
        if a.op == op and file_match(a.location.file, file)
    )


# ---------------------------------------------------------------------------
# Comparison-operand wiring
# ---------------------------------------------------------------------------


def is_comparison(a: Assignment) -> bool:
    """An ``Assignment`` whose op compares two stack values."""
    return a.op in CMP_OPS


def _bb_strict_dominators(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> dict[BasicBlock, set[BasicBlock]]:
    """Iterative dataflow over the BB CFG: ``dom(b)`` = intersection of
    ``dom(p)`` over predecessors, plus ``b`` itself. Entry BBs (no
    predecessors) dominate only themselves at the start. Returns a
    map ``bb -> {bbs that dominate bb}`` (including ``bb`` itself).

    Multiple entry BBs are handled by giving each entry only itself as
    its initial dominator set; non-entry BBs intersect across all
    predecessors. Standard worklist algorithm.

    With ``file`` set, only blocks in that file participate — useful
    when one source carries multiple programs and dominance must stay
    intra-program. (BB CFG edges don't cross files in tealtools'
    model, so the result is structurally the same as building a
    single-program source.)"""
    blocks = [
        bb for bb in prog.blocks.values() if file_match(bb.file, file)
    ]
    # Entries = BBs with no predecessors at all; preds are file-filtered so a
    # block whose only edges are cross-file stays saturated (defensive — BB CFG
    # edges don't cross files in tealtools' model).
    entries = [bb for bb in blocks if not bb.predecessors]
    return iterative_dominators(
        blocks, entries,
        lambda bb: [p for p in bb.predecessors if file_match(p.file, file)],
    )


def field_validated_on_all_paths(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
) -> bool:
    """The field is validated on all paths: there is a single
    comparison whose BB dominates every approval exit, and one operand
    of the comparison reads from ``txn FIELD``.

    Phi-aware on the operand check (cross-BB cmps are common when the
    field read sits in one BB and the comparison in a successor)."""
    field_vars = {
        out
        for a in (txn_field_reads(prog, field, file=file)
                  + gtxn_field_reads(prog, field, file=file))
        for out in a.outputs
        if isinstance(out, SSAVar)
    }
    if not field_vars:
        return False
    exits = approving_exits(prog, file=file)
    if not exits:
        return False
    dom = _bb_strict_dominators(prog, file=file)
    for cmp in prog.assignments:
        if not file_match(cmp.location.file, file):
            continue
        if not is_comparison(cmp) or len(cmp.inputs) != 2:
            continue
        if not any(
            _operand_flows_from_field_var(prog, op, field_vars)
            for op in cmp.inputs
        ):
            continue
        cmp_bb = cmp.basic_block
        if cmp_bb is None:
            continue
        if not all(cmp_bb in dom[exit] for exit in exits):
            continue
        # The comparison must actually be ENFORCED — a `field == X` whose result
        # is dropped (`pop`) or otherwise never reaches an assert / branch-to-reject
        # is not a guard. Without this, `txn AssetCloseTo; global ZeroAddress; ==;
        # pop` (the result discarded) was accepted as validation — a false negative
        # that approves the txn regardless of the field.
        if not cmp.outputs or not isinstance(cmp.outputs[0], SSAVar):
            continue
        if def_forward_reaches_enforcement(prog, cmp.outputs[0]):
            return True
    return False


# ---------------------------------------------------------------------------
# Path-aware "approval exit protected for field"
#
# This path formulation requires that every path from any
# program entry to the exit crosses a BB containing a comparison that
# (a) consumes a txn FIELD read transitively (via a few sub / scratch
# bridges) and (b) whose result reaches an enforcement sink (assert /
# bnz to err / bz to err).
#
# This is materially stronger than dominance: it correctly accepts
# replicated per-branch checks. Used by the `rekey-to` detector.
# ---------------------------------------------------------------------------


_ENFORCEMENT_TERM_OPS = frozenset({"assert", "bnz", "bz"})


def _label_to_bb_first_line(prog: SSAProgram) -> dict[tuple[str, str], int]:
    """``(file, label_name) -> source line of the label`` for branch
    target resolution. Same shape as the index inside
    ``PathPredicateAnalysis``."""
    out: dict[tuple[str, str], int] = {}
    for f, ln, code in prog.labels:
        out[(f, code.rstrip(":").strip())] = ln
    return out


def _bb_at(prog: SSAProgram, file: str, line: int) -> Optional[BasicBlock]:
    for bb in prog.blocks.values():
        if bb.file == file and bb.first_line == line:
            return bb
    return None


def def_forward_reaches_enforcement(
    prog: SSAProgram,
    var: SSAVar,
    *,
    label_lines: Optional[dict[tuple[str, str], int]] = None,
    seen: Optional[set[SSAVar]] = None,
) -> bool:
    """The def-forward reaches an enforcement: the SSA chain rooted at
    ``var`` terminates in some opcode that enforces rejection when the
    original value is false.

    Recognised sinks:
      - ``assert`` consumes the SSA chain.
      - ``bnz target`` consumes it and the fall-through BB is a
        *rejection exit* (``err`` or ``return 0`` — see
        :func:`is_rejection_exit`), so cmp=false ⇒ fall through ⇒ reject.
      - ``bz target`` consumes it and the target BB is a rejection exit,
        so cmp=false ⇒ branch to rejection ⇒ reject.

    Walks through every consuming opcode that produces an SSA def
    (``&&``, ``||``, ``dup``, etc.), so compositions like ``cmp1; cmp2;
    &&; assert`` and ``cmp; dup; bnz target; err`` are all recognised.

    The ``return 0`` form is essential for LogicSigs and ABI-router
    code that branches on failure to a ``pushint 0; return`` block
    rather than an explicit ``err`` — the old ``first-op-is-err`` check
    silently missed every such guard.
    """
    if seen is None:
        seen = set()
    if var in seen:
        return False
    seen.add(var)
    label_lines = label_lines if label_lines is not None else _label_to_bb_first_line(prog)
    for cons in var.uses:
        if cons.op == "assert":
            return True
        if cons.op == "bnz":
            bnz_bb = cons.basic_block
            if bnz_bb is not None:
                fall_through = _fall_through_bb(prog, bnz_bb)
                if fall_through is not None and is_rejection_exit(fall_through):
                    return True
        elif cons.op == "bz":
            target_name = cons.immediates.strip()
            target_line = label_lines.get((cons.location.file, target_name))
            if target_line is not None:
                target_bb = _bb_at(prog, cons.location.file, target_line)
                if target_bb is not None and is_rejection_exit(target_bb):
                    return True
        # Step: consume produces an SSA def whose forward chain we walk.
        for out in cons.outputs:
            if not isinstance(out, SSAVar):
                continue
            if def_forward_reaches_enforcement(
                prog, out, label_lines=label_lines, seen=seen,
            ):
                return True
    return False


def _fall_through_bb(prog: SSAProgram, bb: BasicBlock) -> Optional[BasicBlock]:
    """The CFG successor that represents falling through past ``bb``'s
    terminating branch (rather than taking the branch). Identified as
    the successor whose first line is the smallest source line strictly
    greater than ``bb.last_line`` — branches' targets sit at labelled
    lines often elsewhere; the fall-through is the next sequential BB.
    """
    candidates: list[BasicBlock] = []
    for succ in bb.successors:
        if succ.first_line > bb.last_line:
            candidates.append(succ)
    if not candidates:
        return None
    candidates.sort(key=lambda b: b.first_line)
    return candidates[0]


def enforced_op_exists(prog: SSAProgram, ops, flows, *, file: Optional[str] = None) -> bool:
    """True if some assignment whose op is in ``ops`` (file-matched) and whose
    operands satisfy ``flows(op)`` has its result reach enforcement
    (:func:`def_forward_reaches_enforcement`).

    The shared shape of the "is there a genuine, *enforced* check of form X?"
    recognisers (timelock timestamp comparison, balance==min_balance tie): a
    check whose result is dropped or sits on an unrelated branch enforces
    nothing. Each caller supplies its own ``flows`` predicate (one-sided vs
    two-sided tie), so the differing flow logic stays explicit at the call
    site while the loop + enforcement test are shared."""
    for op in prog.assignments:
        if op.op not in ops or not file_match(op.location.file, file):
            continue
        if not flows(op):
            continue
        if op.outputs and isinstance(op.outputs[0], SSAVar) and \
                def_forward_reaches_enforcement(prog, op.outputs[0]):
            return True
    return False


def cached_path_predicates(prog: SSAProgram) -> PathPredicateAnalysis:
    """One :class:`PathPredicateAnalysis` per program, memoised on ``prog``.

    The OnCompletion / field-guard family (is-deletable, is-updatable,
    unprotected-*, delete-funds-check, timelock-upgrade, rekey-to, …) each need
    path predicates; building them once and sharing avoids re-running the whole
    branch/assert analysis per detector — the bulk of a scan's per-contract cost.
    Detectors that accept a caller-SEEDED ``path_predicates`` (the cross-contract
    runner) still pass their own; only the default is cached. Sound because the
    analysis is a pure read of ``prog``'s CFG, unaffected by additive passes."""
    pp = getattr(prog, "_sec_path_predicates", None)
    if pp is None:
        pp = PathPredicateAnalysis(prog)
        try:
            prog._sec_path_predicates = pp
        except Exception:
            pass
    return pp


def _frame_param_sources_cached(prog: SSAProgram) -> dict:
    """``frame_param_sources(prog)`` (the interprocedural ``frame_dig`` output ->
    caller-arg map), memoised on the program so the per-BB path walk doesn't
    rebuild it. Cheap to compute, but called once per comparison operand."""
    cache = getattr(prog, "_sec_frame_param_sources", None)
    if cache is None:
        from tealtools.passes.frame_flow import frame_param_sources
        cache = frame_param_sources(prog)
        try:
            prog._sec_frame_param_sources = cache
        except Exception:
            pass
    return cache


def _operand_flows_from_field_var(
    prog: SSAProgram,
    operand,
    field_vars: set,
    *,
    seen: Optional[set] = None,
) -> bool:
    """True if ``operand`` provably reads from one of the SSAVars in
    ``field_vars``, allowing for SSA-level bridges:

      - direct: operand is the SSAVar itself.
      - phi join: every arg flows from a field var (MUST semantics).
      - scratch: operand is a ``load N`` output whose every may-influencing
        store wrote a field-flowing SSAVar (MUST semantics, mirrors
        :meth:`SSAProgram.propagate_scratch_constants`).
      - frame (interprocedural): operand is a ``frame_dig`` param read whose
        every caller-bound argument flows from a field var (MUST). This is what
        lets a guard living *inside a proto subroutine* (``frame_dig -1; global
        ZeroAddress; ==; assert``, the field read happening in the caller and
        passed as a proto arg) count as protecting the field — without it the
        whole approval-exit family is blind across the callsub boundary and
        reports a cross-sub guard as absent (a false positive).

    Termination is bounded by ``seen``: each SSAVar / Phi in the finite
    def-use graph is visited at most once, and a repeat visit returns
    False — sound under the MUST ``all(...)`` semantics (an unprovable
    arm just fails the conjunction). There is deliberately no separate
    recursion-depth cap: the old ``depth=4`` limit was redundant with
    ``seen`` for termination and only suppressed *real* field-flows
    sitting behind deep scratch / phi indirection (common in compiled
    Puya / ABI output), which made a present guard look absent — a
    false-positive source.
    """
    if operand is None:
        return False
    if seen is None:
        seen = set()
    if operand in field_vars:
        return True
    if isinstance(operand, SSAVar):
        if operand in seen:
            return False
        seen.add(operand)
        # Scratch bridge: load N reads from a slot. Every may-influencing
        # store must have written a field-flowing SSAVar.
        if operand.defined_by is not None and operand.defined_by.op == "load":
            stores = _scratch_stores_for(prog, operand)
            if not stores:
                return False
            return all(
                _operand_flows_from_field_var(
                    prog, prog.var(*s), field_vars, seen=seen,
                )
                for s in stores
            )
        # Frame bridge: a `frame_dig` param read flows from the field iff every
        # caller argument bound to that param does (MUST). The fat-frame SSA has
        # no def-use edge across the proto boundary; `frame_param_sources` is the
        # precise interprocedural layer that supplies the caller-arg set.
        frame_src = _frame_param_sources_cached(prog)
        args = frame_src.get(operand)
        if args:
            return all(
                _operand_flows_from_field_var(prog, a, field_vars, seen=seen)
                for a in args
            )
        return False
    if isinstance(operand, Phi):
        if operand in seen or not operand.args:
            return False
        seen.add(operand)
        return all(
            _operand_flows_from_field_var(
                prog, arg, field_vars, seen=seen,
            )
            for arg in operand.args
        )
    return False


def _scratch_stores_for(prog: SSAProgram, load_var: SSAVar) -> Optional[list]:
    """``g.nodes[load_node]["scratch_stores"]`` for the ``load`` opcode
    that produced ``load_var``. Returns the raw list of
    ``(file, line, output_idx)`` tuples that
    :func:`tealtools.graph.load_graph` populated, or ``None`` when the
    load isn't covered (dynamic-slot ``loads`` op, or the scratch
    influence query found no stores)."""
    if load_var.defined_by is None or load_var.defined_by.op != "load":
        return None
    prog._ensure_scratch_influence()
    for n in prog._graph.nodes:
        loc = getattr(n, "location", None)
        if loc is None:
            continue
        if loc.file == load_var.file and loc.start_line == load_var.line:
            return prog._graph.nodes[n].get("scratch_stores")
    return None


def _is_protected_bb_for_seeds(
    prog: SSAProgram,
    bb: BasicBlock,
    field_vars: set[SSAVar],
    *,
    file: Optional[str] = None,
    allow_unary_cmp: bool = False,
) -> bool:
    """Takes the seed set of
    field-source SSAVars directly so callers can swap the source
    (``txn`` / ``global`` / ``gtxn``) or pass a *union* of seeds for
    disjunction (e.g. ``TypeEnum`` OR ``Type``).

    A BB is protected for ``field_vars`` iff it contains a comparison
    consuming a value that flows from any seed AND whose result
    reaches enforcement (``assert`` / ``bnz`` to ``err`` / ``bz`` to
    ``err``). Empty seeds → not protected (vacuously).

    ``allow_unary_cmp``: by default only two-operand comparisons count.
    When a comparison's other operand is an *inlined literal* (e.g.
    ``selector == 0x12345678``), the SSA materialises just one input —
    the seed — so the comparison has arity 1. Field detectors compare
    against opcode-produced values (``global ZeroAddress`` etc.) and
    want the strict two-input form; the ABI-selector detector compares
    against a literal and opts in to the one-input form."""
    if not field_vars:
        return False
    if file is None:
        file = bb.file
    label_lines = _label_to_bb_first_line(prog)
    for cmp in bb.assignments:
        if not is_comparison(cmp):
            continue
        n_in = len(cmp.inputs)
        if n_in != 2 and not (allow_unary_cmp and n_in == 1):
            continue
        if not any(
            _operand_flows_from_field_var(prog, op, field_vars)
            for op in cmp.inputs
        ):
            continue
        if not cmp.outputs or not isinstance(cmp.outputs[0], SSAVar):
            continue
        if def_forward_reaches_enforcement(
            prog, cmp.outputs[0], label_lines=label_lines,
        ):
            return True
    return False


def _approval_exit_protected_for_seeds(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    field_vars: set[SSAVar],
    *,
    file: Optional[str] = None,
    allow_unary_cmp: bool = False,
) -> bool:
    """Core of :func:`approval_exit_protected_for_field` — same path
    walk but parameterised on the seed set so we can reuse the
    machinery for ``global FIELD`` / disjunctions / ``gtxn FIELD``.
    ``allow_unary_cmp`` is threaded to :func:`_is_protected_bb_for_seeds`."""
    if file is None:
        file = exit_bb.file
    if _is_protected_bb_for_seeds(
        prog, exit_bb, field_vars, file=file, allow_unary_cmp=allow_unary_cmp,
    ):
        return True
    # If the exit_bb itself is an entry (no predecessors), the trivial
    # zero-length path is from an unprotected entry — exit_bb is *not*
    # protected. Without this guard the backward BFS below exhausts
    # with no work to do and returns the wrong answer (True).
    if not exit_bb.predecessors:
        return False
    visited: set[BasicBlock] = {exit_bb}
    stack: list[BasicBlock] = [exit_bb]
    while stack:
        bb = stack.pop()
        for pred in bb.predecessors:
            if pred in visited:
                continue
            visited.add(pred)
            if _is_protected_bb_for_seeds(
                prog, pred, field_vars, file=file, allow_unary_cmp=allow_unary_cmp,
            ):
                continue
            if not pred.predecessors:
                return False
            stack.append(pred)
    return True


def _txn_field_seeds(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
    include_gtxn: bool = False,
) -> set[SSAVar]:
    reads = txn_field_reads(prog, field, file=file)
    if include_gtxn:
        # Some fields are validated on a SIBLING transaction in the group, not the
        # app call itself — e.g. AssetCloseTo / XferAsset on the deposit axfer.
        # Opt-in (asset-close-to, asset-id-validation) so the txn-only detectors
        # (rekey-to, fee, …) keep their app-call-scoped semantics.
        reads = reads + gtxn_field_reads(prog, field, file=file)
    return ssavar_outputs(reads)


def _global_field_seeds(
    prog: SSAProgram, gfield: str, *, file: Optional[str] = None,
) -> set[SSAVar]:
    return ssavar_outputs(global_field_reads(prog, gfield, file=file))


def approval_exit_protected_for_field(
    prog: SSAProgram, exit_bb: BasicBlock, field: str,
    *, file: Optional[str] = None, include_gtxn: bool = False,
) -> bool:
    """Approval exit protected for a field: every CFG path from any
    program entry to ``exit_bb`` crosses at least one BB protected
    for ``field``. Equivalently, ``exit_bb`` is *not* reachable from
    any entry along a path of unprotected BBs.

    ``include_gtxn`` also seeds ``gtxn``/``gtxns`` reads of the field — for
    detectors whose field is validated on a sibling group transaction."""
    if file is None:
        file = exit_bb.file
    return _approval_exit_protected_for_seeds(
        prog, exit_bb,
        _txn_field_seeds(prog, field, file=file, include_gtxn=include_gtxn),
        file=file,
    )


def approval_exit_protected_for_global_field(
    prog: SSAProgram, exit_bb: BasicBlock, gfield: str,
    *, file: Optional[str] = None,
) -> bool:
    """Like :func:`approval_exit_protected_for_field` but the seed
    is ``global GFIELD`` rather than ``txn FIELD``. Used by detectors
    whose validation target is a ``global`` field (e.g. ``GroupSize``)."""
    if file is None:
        file = exit_bb.file
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, _global_field_seeds(prog, gfield, file=file), file=file,
    )


def approval_exit_protected_for_any_txn_field(
    prog: SSAProgram, exit_bb: BasicBlock, fields: list[str],
    *, file: Optional[str] = None,
) -> bool:
    """Disjunctive form: protected if *any* of ``fields`` is enforced
    on every path. Used by tx-type-check (validating either ``TypeEnum``
    or ``Type`` counts as fixed)."""
    if file is None:
        file = exit_bb.file
    seeds: set[SSAVar] = set()
    for f in fields:
        seeds |= _txn_field_seeds(prog, f, file=file)
    return _approval_exit_protected_for_seeds(prog, exit_bb, seeds, file=file)


def _txna_reads(
    prog: SSAProgram, immediates: str, *, file: Optional[str] = None,
) -> list[Assignment]:
    """Every ``txna <immediates>`` array read in ``prog`` (e.g.
    ``txna ApplicationArgs 0`` for the ABI method selector)."""
    return [
        a for a in prog.assignments
        if a.op == "txna" and a.immediates.strip() == immediates
        and file_match(a.location.file, file)
    ]


def approval_exit_protected_for_arg_reads(
    prog: SSAProgram, exit_bb: BasicBlock, immediates: str,
    *, file: Optional[str] = None,
) -> bool:
    """Like :func:`approval_exit_protected_for_field` but the seed is a
    ``txna`` *array* read (e.g. ``ApplicationArgs 0``) rather than a
    scalar ``txn FIELD``. Used by the ABI-method-selector detector,
    where the value validated on every approving path is the method
    selector ``txna ApplicationArgs 0``."""
    if file is None:
        file = exit_bb.file
    seeds = {
        out for a in _txna_reads(prog, immediates, file=file)
        for out in a.outputs if isinstance(out, SSAVar)
    }
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, seeds, file=file, allow_unary_cmp=True,
    )


# ---------------------------------------------------------------------------
# Fee / GroupSize one-shot checks
# ---------------------------------------------------------------------------


def _is_txn_field_var(var, field: str) -> bool:
    return is_field_var(var, "txn", field)


def _is_global_field_var(var, field: str) -> bool:
    return is_field_var(var, "global", field)


def _is_sender_eq_creator(cmp: Assignment) -> bool:
    if cmp.op != "==" or len(cmp.inputs) != 2:
        return False
    a0, a1 = cmp.inputs
    return (
        (_is_txn_field_var(a0, "Sender") and _is_global_field_var(a1, "CreatorAddress"))
        or
        (_is_txn_field_var(a1, "Sender") and _is_global_field_var(a0, "CreatorAddress"))
    )


def sender_creator_guard_dominates(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    bb: BasicBlock,
) -> bool:
    """``bb`` is reached only along paths where ``txn Sender == global
    CreatorAddress`` was checked truthy.

    We read this off path predicates: if ``bb``'s path predicates
    include ``(V, "nonzero")`` for some SSAVar ``V`` produced by an
    ``==`` op consuming ``txn Sender`` and ``global CreatorAddress``,
    the guard dominates."""
    for cond in pp.predicates_at(bb.file, bb.first_line):
        if cond.kind != "nonzero":
            continue
        v = cond.value
        if not isinstance(v, SSAVar) or v.defined_by is None:
            continue
        if _is_sender_eq_creator(v.defined_by):
            return True
    return False


# ---------------------------------------------------------------------------
# OnCompletion guards
# ---------------------------------------------------------------------------


def _is_oncompletion_var(var) -> bool:
    return _is_txn_field_var(var, "OnCompletion")


def _oncompletion_eq_const_value(cmp: Assignment) -> Optional[int]:
    """If ``cmp`` is ``txn OnCompletion (==/!=) <const_K>`` (operands in
    either order), return ``K``. Otherwise ``None``. Used by the
    extended OC-guard analysis to recognise ``OC == K`` (or ``!= K``)
    for any ``K``, not just for the action under test."""
    if cmp.op not in ("==", "!=") or len(cmp.inputs) != 2:
        return None
    a0, a1 = cmp.inputs
    if _is_oncompletion_var(a0):
        return const_int(a1)
    if _is_oncompletion_var(a1):
        return const_int(a0)
    return None


def approval_exit_guarded_for_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    """Every approving path to ``exit_bb`` proves ``OnCompletion !=
    action_int``.

    Recognised guard shapes (broader than a plain OnCompletion equality
    guard):

    1. **Direct equality / inequality** with the action under test:
       - ``V = OC == action_int``, on a path where V is false → guarded.
       - ``V = OC != action_int``, on a path where V is true → guarded.

    2. **Equality with some other constant K**:
       - ``V = OC == K``, on a path where V is true → ``OC == K`` →
         ``OC != action_int`` whenever ``K != action_int``. This is what
         catches ``bnz`` dispatch tables (``OC == 0; bnz handle_noop``
         → at handle_noop, ``OC == 0`` → guarded against any non-0 action).
       - Symmetric: ``V = OC != K``, V is false → ``OC == K`` → guarded
         when ``K != action_int``.

    3. **Switch dispatch on OnCompletion** (``txn OnCompletion; switch
       handler_0 handler_1 ...``):
       - On a target edge: predicate ``(OC, "eq", (Const(int, str(K)),))``
         → ``OC == K`` → guarded when ``K != action``.
       - On the fall-through edge: ``(OC, "not_in_range", (lo, hi))``
         → ``OC ∉ [lo, hi)``. Guarded when ``action ∈ [lo, hi)`` (the
         action would have routed to a target, but execution reached
         the fall-through, so OC isn't action).

    4. **Match dispatch on OnCompletion** (``... candidates ...; txn
       OnCompletion; match h0 h1 ...``):
       - On a target edge: predicate ``(OC, "eq", (candidate,))`` →
         ``OC == candidate``. Guarded when the candidate resolves to a
         const ``K != action``.
       - On the fall-through edge: ``(OC, "neq_all", (c0, c1, …))``.
         Guarded when any candidate resolves to ``action`` (the action
         would have matched but didn't, so OC isn't action).

    A plain OnCompletion equality guard only models case 1; everything
    else is a deliberate enhancement (real Algorand routers / Puya
    output use ``match`` dispatch on OC). This is deliberately tight —
    contracts that actually route OC=K to err are not flagged here."""
    for cond in pp.predicates_at(exit_bb.file, exit_bb.first_line):
        v = cond.value

        # Case 0: a DIRECT truth constraint on the OnCompletion field var itself.
        # `txn OnCompletion; !; assert` (the NoOp-only idiom Puya emits, often
        # folded into `(OC == 0) && …`) leaves `(OC, "zero")` — OC == 0 — at the
        # guarded exit; `txn OnCompletion; assert` leaves `(OC, "nonzero")`.
        #   OC == 0  ⇒ guarded against any non-zero action (DeleteApplication=5,
        #              UpdateApplication=4, …).
        #   OC != 0  ⇒ guarded against the NoOp action (0) only (it could still be
        #              any of 1..5, so it does NOT guard Delete/Update).
        if _is_oncompletion_var(v):
            if cond.kind == "zero" and action_int != 0:
                return True
            if cond.kind == "nonzero" and action_int == 0:
                return True

        # Case 3 + 4: switch / match edge predicates against an
        # OnCompletion-typed key.
        if cond.kind == "eq" and _is_oncompletion_var(v) and cond.args:
            k = const_int(cond.args[0])
            if k is not None and k != action_int:
                return True
        if cond.kind == "not_in_range" and _is_oncompletion_var(v):
            lo, hi = cond.args
            if isinstance(lo, int) and isinstance(hi, int) and lo <= action_int < hi:
                return True
        if cond.kind == "neq_all" and _is_oncompletion_var(v):
            for cand in cond.args:
                if const_int(cand) == action_int:
                    return True

        # Cases 1 + 2: SSA-level recognition of ``V = OC ==/!= K``
        # whose truth/falsity is captured by the path predicate.
        if isinstance(v, SSAVar) and v.defined_by is not None:
            a = v.defined_by
            if a.op in ("==", "!="):
                k = _oncompletion_eq_const_value(a)
                if k is not None:
                    if a.op == "==":
                        # V is (OC == K). nonzero ⇒ OC == K. zero ⇒ OC != K.
                        if cond.kind == "nonzero" and k != action_int:
                            return True
                        if cond.kind == "zero" and k == action_int:
                            return True
                    else:  # "!="
                        # V is (OC != K). nonzero ⇒ OC != K. zero ⇒ OC == K.
                        if cond.kind == "nonzero" and k == action_int:
                            return True
                        if cond.kind == "zero" and k != action_int:
                            return True
    return False


def approval_exit_unguarded_for_action(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    exit_bb: BasicBlock,
    action_int: int,
) -> bool:
    return not approval_exit_guarded_for_action(prog, pp, exit_bb, action_int)


# ---------------------------------------------------------------------------
# Inner transaction helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class InnerTxnFieldSet:
    """One ``itxn_field FIELD`` assignment, with the SSA value being
    written."""

    assignment: Assignment
    field: str
    value: object  # SSAVar | Phi | Const

    @property
    def value_const(self) -> Optional[Const]:
        v = self.value
        if isinstance(v, Const):
            return v
        cv = getattr(v, "const_value", None)
        if isinstance(cv, Const):
            return cv
        return None


def inner_txn_field_assigns(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> list[InnerTxnFieldSet]:
    """Iterate every ``itxn_field FIELD`` opcode. The set value is
    ``inputs[0]`` (top-of-stack at the itxn_field call)."""
    out: list[InnerTxnFieldSet] = []
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op != "itxn_field" or not a.inputs:
            continue
        field = a.immediates.strip()
        out.append(InnerTxnFieldSet(assignment=a, field=field, value=a.inputs[0]))
    return out


def _zero_address_seeds(
    prog: SSAProgram, *, file: Optional[str] = None,
) -> set:
    """SSAVars that read ``global ZeroAddress`` — the canonical 32-zero-byte
    address source. Seeds for :func:`value_is_zero_address`."""
    return {
        out for a in global_field_reads(prog, "ZeroAddress", file=file)
        for out in a.outputs if isinstance(out, SSAVar)
    }


def value_is_zero_address(
    prog: SSAProgram, value, *, file: Optional[str] = None,
) -> bool:
    """``value`` provably resolves to the zero address: either a 32-byte all-zero
    bytes constant, or a value flowing (through phi / scratch / proto-frame, via
    :func:`_operand_flows_from_field_var`) from ``global ZeroAddress``.

    Used to suppress *safe* dangerous-field writes — setting ``itxn_field
    RekeyTo`` / ``CloseRemainderTo`` to the zero address is a defensive no-op
    (the field's default), not the drain/rekey antipattern."""
    cv = value if isinstance(value, Const) else getattr(value, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "bytes":
        hexpart = cv.value[2:] if cv.value.startswith("0x") else cv.value
        if len(hexpart) == 64 and set(hexpart) <= {"0"}:   # 32 zero bytes
            return True
    seeds = _zero_address_seeds(prog, file=file)
    if seeds and _operand_flows_from_field_var(prog, value, seeds):
        return True
    return False


def inner_txn_sets_nonzero_fee(field_set: InnerTxnFieldSet) -> bool:
    """``itxn_field Fee`` whose value resolves to a non-zero integer
    constant (a *known* non-zero int — dynamic values aren't
    flagged)."""
    if field_set.field != "Fee":
        return False
    cv = field_set.value_const
    if cv is None or cv.kind != "int":
        return False
    try:
        return int(cv.value) != 0
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# User-input taint + itxn-field guard
#
# Shared by every detector that asks "does an attacker-controlled value reach
# a sensitive inner-transaction field without a dominating check?" — the
# tainted-fund-flow family (payment fields) and arbitrary-inner-appcall (the
# call target). The taint is a forward propagation over the PySSA
# def-use / phi / scratch relation, interprocedural via the frame-flow bridge
# (a value fed into a proto param is tainted from the caller args bound to it).
# ---------------------------------------------------------------------------


_CMP_OPS = frozenset({"==", "!="})


def source_label(op: str, imm: str) -> Optional[str]:
    """The user-input source family ``op`` (with immediates ``imm``) reads, or
    ``None``. ``ApplicationArgs`` (txn/gtxn array reads), LogicSig ``arg``s, and
    the ``itxn ... LastLog`` of a just-called sub-app are all attacker-steerable."""
    from tealtools.opsets import TXN_SOURCE_OPS, ITXN_SOURCE_OPS, LSIG_ARG_OPS
    if op in TXN_SOURCE_OPS and "ApplicationArgs" in imm:
        return "ApplicationArgs"
    if op in LSIG_ARG_OPS:
        return "LogicSigArgs"
    if op in ITXN_SOURCE_OPS and "LastLog" in imm:
        return "ItxnLastLog"
    return None


def user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    """``{SSAVar|Phi: frozenset[(label, slot)]}`` — forward taint from the
    user-input sources over the SSA def-use / phi / scratch relation, where
    ``slot`` = ``(op, immediates)`` so two reads of the SAME input slot match
    (and ``ApplicationArgs[0]`` vs ``[1]`` don't).

    Interprocedural: each ``frame_dig`` param read inherits the taint of the
    caller args bound to it (:func:`frame_param_sources`), so a value fed INTO a
    subroutine parameter and consumed inside the callee is caught natively — no
    IR lift, no per-detector supplement.

    Memoised per ``(prog, file)``: the whole tainted-fund-flow family
    (tainted-fund-flow / partial / arbitrary-inner-appcall / -asset) shares one
    fixpoint instead of recomputing it per detector. Sound because the detectors
    only READ ``prog`` (no mutation between runs in a scan)."""
    cache = getattr(prog, "_sec_user_input_taint", None)
    if cache is None:
        cache = {}
        try:
            prog._sec_user_input_taint = cache
        except Exception:
            pass
    if file in cache:
        return cache[file]
    result = _compute_user_input_taint(prog, file)
    cache[file] = result
    return result


# Warn only once per process if the lift package itself fails to import
# (a real breakage — the pre-IR path is puya-free, so missing puya alone does
# NOT trip this); per-contract lift failures warn individually in ir_lifter.
_LIFT_IMPORT_WARNED = False


def ir_lifter(prog: SSAProgram, file: Optional[str] = None):
    """Build + cache the IR lifter for ``prog`` -- the lifted, Puya-shaped IR the
    interprocedural detectors (e.g. ``ir-tainted-fund-flow``) run on.

    Built from a FRESH ``SSAProgram`` off ``prog.source_path`` rather than ``prog``
    itself: the lift mutates its input CFG (``_prune_dead_assert_edges`` drops dead
    edges + rebuilds join phis), and the SSA-layer detectors read the SAME
    ``prog`` -- so lifting a copy keeps their substrate pristine. Returns the
    ``_Lifter`` instance (post-``build``, carrying ``.subs``/``.regs``/``.reg`` the
    taint + fund-flow analyses consume), or ``None`` when the contract doesn't lift
    (rare; the lift is ~99.9% robust on real mainnet). Cached per ``prog`` -- one
    lift shared by every IR detector in a scan.

    ``file`` is accepted for signature parity with the SSA analyses but unused: the
    lift is whole-program, and SSAPrograms are per-file (xcontract aside).

    Failure is NEVER silent: a per-contract lift failure warns with the
    reason, and a lift-package import failure (which should NOT happen just
    because puya is missing — the pre-IR taint path is puya-free) warns once.
    Either way the ir-* detectors degrade (SSA-sibling fallback or no
    findings), and the user must be able to see the reduced precision."""
    global _LIFT_IMPORT_WARNED
    sentinel = object()
    cached = getattr(prog, "_sec_ir_lifter", sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    try:
        from tealtools.lift.lift import _Lifter
    except ImportError as e:
        # The detector-facing lift is deliberately puya-free, so this is a
        # genuine breakage (not merely puya-not-installed), hence once-only.
        if not _LIFT_IMPORT_WARNED:
            _LIFT_IMPORT_WARNED = True
            logger.warning(
                "IR detections DISABLED — the lift package failed to import "
                "(%s). ir-* detectors with an SSA sibling fall back to it; "
                "the rest report nothing.", e)
    else:
        src = str(getattr(prog, "source_path", "") or "")
        if not src:
            logger.debug(
                "ir_lifter: program has no source path (in-memory build?) — "
                "IR layer skipped")
        else:
            from tealtools.errors import LiftError
            try:
                fresh = SSAProgram(src)
                fresh.propagate_constants()
                lf = _Lifter(fresh)
                lf.build()
                lifter = lf
            except LiftError as e:
                # EXPECTED coverage gap: a contract the lift can't reconstruct
                # (~0.1% of real mainnet). Info, not warning — the ir-* fallback
                # is the designed behaviour, not an anomaly.
                logger.info(
                    "Puya-IR lift did not cover %s (%s) — ir-* detections use "
                    "their SSA fallback; results may be less precise.", src, e)
            except Exception as e:
                # UNEXPECTED: the lift raised something other than a LiftError,
                # which points at a bug rather than a coverage limit. Louder.
                logger.warning(
                    "Puya-IR lift crashed UNEXPECTEDLY for %s (%s: %s) — this "
                    "is likely a bug; ir-* detections fall back. Please report.",
                    src, type(e).__name__, e)
    try:
        prog._sec_ir_lifter = lifter
    except Exception:
        pass
    return lifter


def _compute_user_input_taint(prog: SSAProgram, file: Optional[str] = None) -> dict:
    taint: dict = {}

    def t(o):
        return taint.get(o, frozenset())

    frame_src = _frame_param_sources_cached(prog)

    for a in prog.assignments:                       # seed
        if not file_match(a.location.file, file):
            continue
        lbl = source_label(a.op, a.immediates.strip())
        if lbl:
            key = (lbl, (a.op, a.immediates.strip()))
            for o in a.outputs:
                if isinstance(o, SSAVar):
                    taint[o] = t(o) | {key}

    changed = True
    while changed:
        changed = False
        for ph in prog.phis.values():                # phi: union of args
            new = set()
            for arg in ph.args:
                new |= t(arg)
            if new - t(ph):
                taint[ph] = t(ph) | new
                changed = True
        for dig_out, args in frame_src.items():      # callee param <- caller args
            new = set()
            for arg in args:
                new |= t(arg)
            if new - t(dig_out):
                taint[dig_out] = t(dig_out) | new
                changed = True
        for a in prog.assignments:
            if not file_match(a.location.file, file):
                continue
            ins = set()
            for inp in a.inputs:
                ins |= t(inp)
            if a.op == "load":                       # scratch reaching-def
                for o in a.outputs:
                    for s in (_scratch_stores_for(prog, o) or ()):
                        ins |= t(prog.var(*s))
            if not ins:
                continue
            for o in a.outputs:
                if isinstance(o, SSAVar) and (ins - t(o)):
                    taint[o] = t(o) | ins
                    changed = True
    return {k: frozenset(v) for k, v in taint.items() if v}


def sender_creator_vars(prog: SSAProgram, *, file: Optional[str] = None) -> set:
    """SSAVars reading ``txn Sender`` or ``global CreatorAddress`` — the seeds
    for the "this access is gated on who sent it" suppression."""
    return (
        ssavar_outputs(txn_field_reads(prog, "Sender", file=file))
        | ssavar_outputs(global_field_reads(prog, "CreatorAddress", file=file))
    )


def itxn_value_guarded(
    prog: SSAProgram,
    pp: PathPredicateAnalysis,
    assignment: Assignment,
    sink_slots: frozenset,
    taint: dict,
    sender_vars: set,
) -> bool:
    """The inner-txn field write at ``assignment`` is dominated by a check of
    either the tainted value itself (a predicate derived from the SAME input
    slot — taint propagates through the comparison, so ``arg < N`` carries
    ``arg``'s slot) or of ``txn Sender`` (a sender/creator equality)."""
    preds = pp.predicates_at(file=assignment.location.file, line=assignment.location.line)
    for cond in preds:
        v = cond.value
        if taint.get(v, frozenset()) & sink_slots:        # value-check
            return True
        d = getattr(v, "defined_by", None)
        if d is not None and d.op in _CMP_OPS and any(    # sender-check
                _operand_flows_from_field_var(prog, op, sender_vars)
                for op in d.inputs):
            return True
    return False


# ---------------------------------------------------------------------------
# Contract-kind classification (application vs logic signature)
#
# Several detectors validate fields of the SIGNED/authorizing transaction
# (RekeyTo / CloseRemainderTo / Fee / Lease / TypeEnum). A LOGIC SIGNATURE
# authorizes the txn it is attached to, so it must validate those fields; an
# APPLICATION does not — the caller authorizes the outer txn — so those checks
# are meaningless on the app's own call and firing them is a false positive.
# `applies_to` declares each detector's scope; this classifies the program so a
# runner can honor it without the user declaring a mode.
# ---------------------------------------------------------------------------


# Opcodes valid only in Application mode (the AVM rejects them in Signature
# mode), so their presence proves the program is an application.
_APP_ONLY_OPS = frozenset({
    "app_global_get", "app_global_put", "app_global_del", "app_global_get_ex",
    "app_local_get", "app_local_put", "app_local_del", "app_local_get_ex",
    "app_opted_in", "app_params_get", "asset_params_get", "asset_holding_get",
    "acct_params_get",
    "itxn_begin", "itxn_field", "itxn_submit", "itxn_next",
    "itxn", "itxna", "itxnas", "gitxn", "gitxna", "gitxnas",
    "box_create", "box_put", "box_get", "box_del", "box_replace",
    "box_extract", "box_len", "box_resize", "box_splice",
    "log", "gload", "gloads", "gloadss",
})

def classify_program(prog: SSAProgram, *, file: Optional[str] = None) -> str:
    """``"app"`` if the program uses any application-only OPCODE, else
    ``"logicsig"``.

    Keyed strictly on opcodes the AVM rejects in Signature mode — NOT on txn
    fields. A logic signature can be attached to an ApplicationCall txn and so
    may read ``OnCompletion`` / ``ApplicationArgs`` / ``ApplicationID`` (e.g. a
    proof-verifier lsig); those fields therefore do not prove an application and
    keying on them would misclassify that lsig class. App-only opcodes can't run
    in a logic signature, so their presence is sound. (Verified: all 229 real
    mainnet app probes still classify as ``"app"`` opcodes-only — every real app
    touches state / logs / issues inner txns.)"""
    for a in prog.assignments:
        if not file_match(a.location.file, file):
            continue
        if a.op in _APP_ONLY_OPS:
            return "app"
    return "logicsig"


def loc(a) -> str:
    """``file:line`` formatter — the canonical location format used by
    every existing detector's ``pretty()`` output."""
    if hasattr(a, "location"):
        return f"{a.location.file}:{a.location.line}"
    if hasattr(a, "file") and hasattr(a, "first_line"):
        return f"{a.file}:{a.first_line}"
    return str(a)
