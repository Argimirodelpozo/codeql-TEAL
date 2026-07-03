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

from ._enforcement import _label_to_bb_first_line, def_forward_reaches_enforcement
from ._program_shape import (
    _txna_reads,
    approving_exits,
    file_match,
    global_field_reads,
    gtxn_field_reads,
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
