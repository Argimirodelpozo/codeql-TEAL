"""Field-validation reasoning: strict dominance (``field_validated_on_all_
paths``) and the stronger every-path protection family
(``approval_exit_protected_for_*``), parameterised on seed sets.

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.avm import CMP_OPS
from tealql.tealtools.cfg.dominance import iterative_dominators
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar

from ._enforcement import (
    _bb_at,
    _fall_through_bb,
    _label_to_bb_first_line,
    scratch_forward_map,
)
from ._program_shape import (
    _txna_reads,
    approving_exits,
    file_match,
    global_field_reads,
    gtxn_field_reads,
    is_rejection_exit,
    ssavar_outputs,
    txn_field_reads,
)
from ._value_flow import _operand_flows_from_field_var



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




def _collect_field_enforcement_bbs(
    prog: SSAProgram, var: SSAVar, label_lines: dict, out: set, seen: set,
    scratch_fwd: Optional[dict] = None,
) -> None:
    """Forward-walk the SSA chain from a field-comparison result and record the
    BASIC BLOCK of every enforcement site it reaches (``assert`` / ``bnz``
    fall-through-to-reject / ``bz`` target-reject). Same traversal as
    :func:`def_forward_reaches_enforcement`, but it RECORDS the enforcing BB
    instead of returning on the first hit — so the caller can require every
    approving path to CROSS an enforcement site (a MUST-reach) rather than merely
    that one exists somewhere (the may-reach that let a field compared in a
    dominator but asserted on a single branch read as validated-on-all-paths).

    Scratch-aware like its boolean twin: a comparison round-tripped through
    ``store``/``load`` before its ``assert`` still records the enforcing BB, when
    the round-trip provably preserves it (:func:`scratch_forward_map`)."""
    if var in seen:
        return
    seen.add(var)
    if scratch_fwd is None:
        scratch_fwd = scratch_forward_map(prog)
    for fwd in scratch_fwd.get(var, ()):
        _collect_field_enforcement_bbs(prog, fwd, label_lines, out, seen,
                                       scratch_fwd)
    for cons in var.uses:
        if cons.op == "assert":
            if cons.basic_block is not None:
                out.add(cons.basic_block)
        elif cons.op == "bnz":
            bb = cons.basic_block
            if bb is not None:
                ft = _fall_through_bb(prog, bb)
                if ft is not None and is_rejection_exit(ft):
                    out.add(bb)
        elif cons.op == "bz":
            tgt = label_lines.get((cons.location.file, cons.immediates.strip()))
            if tgt is not None:
                tbb = _bb_at(prog, cons.location.file, tgt)
                if (tbb is not None and is_rejection_exit(tbb)
                        and cons.basic_block is not None):
                    out.add(cons.basic_block)
        for o in cons.outputs:
            if isinstance(o, SSAVar):
                _collect_field_enforcement_bbs(prog, o, label_lines, out, seen,
                                               scratch_fwd)


def _field_enforcement_bbs(
    prog: SSAProgram, field_vars: set, *, file: Optional[str],
    allow_unary_cmp: bool = False,
) -> set:
    """The set of BBs that ENFORCE a comparison of the field (an assert /
    branch-to-reject whose condition SSA-derives from a comparison consuming a
    field seed). Empty when the field is compared but never enforced, or never
    compared at all. ``allow_unary_cmp``: accept a 1-input comparison (the field
    against an inlined literal, e.g. an ABI selector) as well as the strict
    2-input form."""
    out: set = set()
    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for cmp in prog.assignments:
        if not file_match(cmp.location.file, file):
            continue
        if not is_comparison(cmp) or not cmp.outputs:
            continue
        n_in = len(cmp.inputs)
        if n_in != 2 and not (allow_unary_cmp and n_in == 1):
            continue
        if not isinstance(cmp.outputs[0], SSAVar):
            continue
        if not any(_operand_flows_from_field_var(prog, op, field_vars)
                   for op in cmp.inputs):
            continue
        _collect_field_enforcement_bbs(prog, cmp.outputs[0], label_lines, out,
                                       set(), scratch_fwd)
    return out


def _all_entry_paths_cross(exit_bb: BasicBlock, gates: set) -> bool:
    """Every CFG path from a program entry (a no-predecessor BB) to ``exit_bb``
    crosses at least one BB in ``gates``. Backward BFS: a predecessor in
    ``gates`` closes that path; reaching an entry NOT in ``gates`` witnesses an
    uncrossed path (return False)."""
    if exit_bb in gates:
        return True
    if not exit_bb.predecessors:
        return False
    visited: set = {exit_bb}
    stack: list = [exit_bb]
    while stack:
        bb = stack.pop()
        for pred in bb.predecessors:
            if pred in visited:
                continue
            visited.add(pred)
            if pred in gates:
                continue
            if not pred.predecessors:
                return False
            stack.append(pred)
    return True


def _pinned_group_index(prog, *, file: Optional[str] = None) -> Optional[int]:
    """The single value ``txn GroupIndex`` is pinned to on EVERY approving path,
    or ``None`` — read off the common group shape (``group_reasoning.analyze``).
    Defensive: any failure yields ``None`` (nothing credited as position-certain)."""
    try:
        from tealql.tealtools import group_reasoning as G
        from tealql.tealtools.ssa import const_int
        for c in G.analyze(prog).constraints:
            if (c.ref.slot == "this" and c.ref.field == "GroupIndex"
                    and c.op == "=="):
                return const_int(c.rhs)
    except Exception:
        pass
    return None


def _signed_txn_field_reads(prog, field: str, *, file: Optional[str] = None) -> list:
    """Reads of the SIGNED transaction's own ``field`` — the only ones that
    protect a delegated logicsig against its own drain. Three forms all read the
    running txn's field: ``txn FIELD`` (self); ``gtxns FIELD`` indexed by
    ``txn GroupIndex`` (dynamic self); and ``gtxn N FIELD`` only when
    ``GroupIndex == N`` is pinned (an absolute index that IS the signed txn). A
    bare ``gtxn N FIELD`` on an unpinned index reads a SIBLING, not the signer, so
    it is excluded — checking it does not protect the signed transaction."""
    from tealql.tealtools import group_reasoning as G
    reads = list(txn_field_reads(prog, field, file=file))
    gtxn_reads = gtxn_field_reads(prog, field, file=file)
    for a in gtxn_reads:                                     # gtxns indexed by GroupIndex
        if a.op in ("gtxns", "gtxnsa", "gtxnsas") and a.inputs \
                and G.relative_slot(a.inputs[0]) == "this":
            reads.append(a)
    # The GroupIndex pin is only needed to credit an ABSOLUTE ``gtxn N`` read — run
    # the (expensive) group-shape analysis ONLY when such a read is present.
    abs_reads = [a for a in gtxn_reads if a.op in ("gtxn", "gtxna", "gtxnas")]
    if abs_reads:
        pinned = _pinned_group_index(prog, file=file)
        if pinned is not None:
            for a in abs_reads:
                toks = a.immediates.split()
                try:
                    n = int(toks[0])
                except (IndexError, ValueError):
                    continue
                if n == pinned:                             # gtxn N, GroupIndex==N pinned
                    reads.append(a)
    return reads


def field_validated_on_all_paths(
    prog: SSAProgram, field: str, *, file: Optional[str] = None,
    signed_txn_only: bool = False,
) -> bool:
    """The field is validated on EVERY approving path: every CFG path from a
    program entry to each approving exit CROSSES a BB that ENFORCES a comparison
    of the field (assert / branch-to-reject).

    Seeds the every-path check on the ENFORCEMENT SITE, not the comparison — the
    must-reach that fixes the false negative in the old dominance formulation. The
    old check accepted "a single comparison dominates all exits AND its result
    reaches *some* enforcement" — existential, so a field compared in a dominating
    BB but asserted on only one branch (``dup``'d, asserted on the Delete branch,
    dropped on an approving NoOp branch) read as validated, letting an attacker set
    the field on the unenforced approving path.

    ``signed_txn_only`` (for delegated-LOGICSIG drain fields): a check protects the
    signer only if it reads the SIGNED transaction's OWN field — ``txn FIELD``,
    ``gtxns FIELD`` indexed by ``GroupIndex``, or ``gtxn N FIELD`` with
    ``GroupIndex == N`` pinned. A bare ``gtxn N`` reads a sibling and does NOT
    count. Default (False) seeds all ``txn`` + sibling ``gtxn`` reads (app-mode:
    a field validated on a group sibling)."""
    exits = approving_exits(prog, file=file)
    if not exits:
        return False
    reads = (_signed_txn_field_reads(prog, field, file=file) if signed_txn_only
             else txn_field_reads(prog, field, file=file)
             + gtxn_field_reads(prog, field, file=file))
    field_vars = {out for a in reads for out in a.outputs if isinstance(out, SSAVar)}
    if not field_vars:
        return False
    gates = _field_enforcement_bbs(prog, field_vars, file=file)
    if not gates:
        return False
    return all(_all_entry_paths_cross(exit_bb, gates) for exit_bb in exits)




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

    A BB is protected for ``field_vars`` iff it is an ENFORCEMENT SITE — it
    contains an ``assert`` / branch-to-reject whose condition SSA-derives from a
    comparison consuming a seed. This is the MUST-reach predicate (crossing the BB
    means the field was enforced), not the old may-reach "a comparison here reaches
    *some* enforcement" — which let a field compared in a dominator but asserted on
    a single branch read as protected (a false negative).

    ``allow_unary_cmp``: also accept the field compared against an *inlined literal*
    (arity-1 comparison, e.g. an ABI selector), not just the strict two-input
    form. Empty seeds → not protected (vacuously)."""
    if not field_vars:
        return False
    if file is None:
        file = bb.file
    return bb in _field_enforcement_bbs(
        prog, field_vars, file=file, allow_unary_cmp=allow_unary_cmp)




def _approval_exit_protected_for_seeds(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    field_vars: set[SSAVar],
    *,
    file: Optional[str] = None,
    allow_unary_cmp: bool = False,
) -> bool:
    """Core of :func:`approval_exit_protected_for_field`: every CFG path from a
    program entry to ``exit_bb`` CROSSES a BB that ENFORCES the field. Seeds the
    every-path (must-reach) check on the enforcement site — the fix for the
    may-reach false negative where a field compared in a dominating BB but
    asserted on only one branch read as protected. Parameterised on the seed set
    to reuse for ``global FIELD`` / disjunctions / ``gtxn`` / ABI-selector."""
    if file is None:
        file = exit_bb.file
    if not field_vars:
        return False
    gates = _field_enforcement_bbs(
        prog, field_vars, file=file, allow_unary_cmp=allow_unary_cmp)
    return _all_entry_paths_cross(exit_bb, gates)




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


def approval_exit_protected_for_signed_txn_field(
    prog: SSAProgram, exit_bb: BasicBlock, field: str,
    *, file: Optional[str] = None,
) -> bool:
    """Like :func:`approval_exit_protected_for_field` but the check must read the
    SIGNED transaction's OWN ``field`` — ``txn FIELD``, ``gtxns FIELD`` indexed by
    ``GroupIndex``, or ``gtxn N FIELD`` with ``GroupIndex == N`` pinned (see
    :func:`_signed_txn_field_reads`). A bare ``gtxn N`` reads a sibling and does
    NOT protect the signer. For the delegated-LOGICSIG drain-field detectors
    (close-remainder-to, rekey-to, asset-close-to)."""
    if file is None:
        file = exit_bb.file
    seeds = ssavar_outputs(_signed_txn_field_reads(prog, field, file=file))
    return _approval_exit_protected_for_seeds(prog, exit_bb, seeds, file=file)




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
