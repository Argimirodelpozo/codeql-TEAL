"""Field-validation reasoning: ``field_validated_on_all_paths`` and the
``approval_exit_protected_for_*`` family, parameterised on seed sets.
Import via :mod:`tealql.security.common`.

Every member asks the same MUST-reach question — does every entry→exit path CROSS
a block that ENFORCES a comparison of the seeds? A may-reach ("some enforcement
exists") lets a field compared in a dominator but asserted on only one branch read
as validated, leaving the other approving path unguarded.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.avm import CMP_OPS
from tealql.tealtools.ssa import Assignment, BasicBlock, SSAProgram, SSAVar

from ._enforcement import (
    _DISJUNCTION_OPS,
    _disjunction_is_enforcing,
    _label_to_bb_first_line,
    branch_gates_rejection,
    scratch_forward_map,
)
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




def _collect_field_enforcement_bbs(
    prog: SSAProgram, var: SSAVar, label_lines: dict, out: set, seen: set,
    scratch_fwd: Optional[dict] = None, field_vars: Optional[set] = None,
) -> None:
    """Record the BASIC BLOCK of every enforcement site the SSA chain from a
    field-comparison result reaches — :func:`def_forward_reaches_enforcement`'s
    traversal, but collecting instead of returning on the first hit, which is what
    lets the caller demand a MUST-reach. Scratch-aware like its boolean twin."""
    if var in seen:
        return
    seen.add(var)
    if scratch_fwd is None:
        scratch_fwd = scratch_forward_map(prog)
    for fwd in scratch_fwd.get(var, ()):
        _collect_field_enforcement_bbs(prog, fwd, label_lines, out, seen,
                                       scratch_fwd, field_vars)
    for cons in var.uses:
        if cons.op == "assert":
            if cons.basic_block is not None:
                out.add(cons.basic_block)
        elif cons.op in ("bnz", "bz"):
            # Record the BRANCH's own block: every path continuing to an
            # approving exit crosses it whichever edge it takes.
            if (cons.basic_block is not None
                    and branch_gates_rejection(prog, cons, label_lines)):
                out.add(cons.basic_block)
        # A ``||`` carries enforcement to this arm only when every OTHER arm pins
        # the same field, else the other arm alone satisfies the assert and this
        # one is unconstrained. Same rule as the boolean twin.
        if cons.op in _DISJUNCTION_OPS and not _disjunction_is_enforcing(
                prog, cons, var, field_vars):
            continue
        for o in cons.outputs:
            if isinstance(o, SSAVar):
                _collect_field_enforcement_bbs(prog, o, label_lines, out, seen,
                                               scratch_fwd, field_vars)


def _field_enforcement_bbs(
    prog: SSAProgram, field_vars: set, *, file: Optional[str],
    allow_unary_cmp: bool = False,
) -> set:
    """BBs ENFORCING a comparison that consumes a field seed; empty when the field
    is never compared, or compared but never enforced. ``allow_unary_cmp`` also
    accepts a 1-input comparison (field against an inlined literal, e.g. an ABI
    selector)."""
    out: set = set()
    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for cmp in prog.assignments:
        if not file_match(cmp.location.file, file):
            continue
        # `!` is a comparison against zero, and it is how a compiler spells `field === 0`:
        # puya-ts (Algorand TypeScript) emits `gtxns Fee; !; assert` for `assert(txn.fee === 0)`. Requiring a
        # two-operand CMP_OP missed that entirely, so a fee-pinned logicsig was reported as
        # having no fee check -- the exact drain finding it had explicitly guarded against.
        is_zero_test = cmp.op == "!"
        if not (is_comparison(cmp) or is_zero_test) or not cmp.outputs:
            continue
        n_in = len(cmp.inputs)
        if n_in != 2 and not is_zero_test and not (allow_unary_cmp and n_in == 1):
            continue
        if is_zero_test and n_in != 1:
            continue
        if not isinstance(cmp.outputs[0], SSAVar):
            continue
        if not any(_operand_flows_from_field_var(prog, op, field_vars)
                   for op in cmp.inputs):
            continue
        _collect_field_enforcement_bbs(prog, cmp.outputs[0], label_lines, out,
                                       set(), scratch_fwd, field_vars)
    return out


def _all_entry_paths_cross(exit_bb: BasicBlock, gates: set) -> bool:
    """Every path from a no-predecessor entry BB to ``exit_bb`` crosses a ``gates``
    BB — backward BFS, where reaching an entry witnesses an uncrossed path."""
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
    """The value ``txn GroupIndex`` is pinned to on EVERY approving path, else
    ``None`` — any failure yields ``None``, crediting nothing as position-certain."""
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
    """Reads of the SIGNED transaction's own ``field``: ``txn FIELD``, ``gtxns
    FIELD`` indexed by ``txn GroupIndex``, and ``gtxn N FIELD`` only when
    ``GroupIndex == N`` is pinned.

    HAZARD: a bare ``gtxn N FIELD`` on an unpinned index reads a SIBLING, not the
    signer — crediting it would let a delegated logicsig be drained through a check
    that never touched the signed transaction."""
    from tealql.tealtools import group_reasoning as G
    # Resolve stack shuffles first, or `gtxns FIELD` is only credited when its index operand comes
    # DIRECTLY from `txn GroupIndex`. A compiler emits one `txn GroupIndex` and then `dup`s it before
    # each field read of the same transaction, so every guard after the first reads as absent --
    # AutoDraw (AlgoKit / puya-ts) checks TypeEnum, RekeyTo, AssetCloseTo and Fee that way and was
    # reported as protecting NONE of them. Idempotent and cached on the program.
    prog.propagate_stack_shuffles()
    reads = list(txn_field_reads(prog, field, file=file))
    gtxn_reads = gtxn_field_reads(prog, field, file=file)
    for a in gtxn_reads:                                     # gtxns indexed by GroupIndex
        if a.op in ("gtxns", "gtxnsa", "gtxnsas") and a.inputs \
                and G.relative_slot(a.inputs[0]) == "this":
            reads.append(a)
    # Only an ABSOLUTE ``gtxn N`` read needs the pin, so run the expensive
    # group-shape analysis only when one is present.
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
    """The field is enforced on EVERY approving path (must-reach, seeded on the
    ENFORCEMENT SITE rather than the comparison).

    ``signed_txn_only`` restricts the seeds to :func:`_signed_txn_field_reads` for
    the delegated-LOGICSIG drain fields; the default also seeds sibling ``gtxn``
    reads, which is what app-mode wants."""
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




def _approval_exit_protected_for_seeds(
    prog: SSAProgram,
    exit_bb: BasicBlock,
    field_vars: set[SSAVar],
    *,
    file: Optional[str] = None,
    allow_unary_cmp: bool = False,
) -> bool:
    """Every path from an entry to ``exit_bb`` CROSSES a BB enforcing ``field_vars``
    — the shared core of the ``approval_exit_protected_for_*`` family."""
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
    # Reads of THIS transaction's field, in every spelling: `txn F`, and `gtxns F` indexed by
    # GroupIndex -- which is what a compiler emits, and what the plain `txn_field_reads` misses, so
    # a guard written the compiled way counted as no guard at all. `_signed_txn_field_reads` also
    # refuses an unpinned `gtxn N`, which reads a SIBLING and must never be credited to the signer.
    reads = _signed_txn_field_reads(prog, field, file=file)
    if include_gtxn:
        # Some fields are validated on a SIBLING txn, not the app call itself (e.g.
        # AssetCloseTo on the deposit axfer). Opt-in, so the txn-only detectors
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
    """``exit_bb`` is protected for ``txn FIELD``; ``include_gtxn`` also seeds
    ``gtxn``/``gtxns`` reads, for fields validated on a sibling group txn."""
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
    """Protected for the SIGNED txn's own ``field`` only, per
    :func:`_signed_txn_field_reads` — the delegated-LOGICSIG drain-field detectors."""
    if file is None:
        file = exit_bb.file
    seeds = ssavar_outputs(_signed_txn_field_reads(prog, field, file=file))
    return _approval_exit_protected_for_seeds(prog, exit_bb, seeds, file=file)




def approval_exit_protected_for_global_field(
    prog: SSAProgram, exit_bb: BasicBlock, gfield: str,
    *, file: Optional[str] = None,
) -> bool:
    """Protected for ``global GFIELD`` (e.g. ``GroupSize``) rather than a txn field."""
    if file is None:
        file = exit_bb.file
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, _global_field_seeds(prog, gfield, file=file), file=file,
    )




def approval_exit_protected_for_any_txn_field(
    prog: SSAProgram, exit_bb: BasicBlock, fields: list[str],
    *, file: Optional[str] = None,
) -> bool:
    """Protected if ANY of ``fields`` is enforced on every path (``TypeEnum`` or
    ``Type`` both count as pinning the txn type)."""
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
    """Protected for a ``txna`` ARRAY read (e.g. ``ApplicationArgs 0``, the ABI
    method selector) rather than a scalar ``txn FIELD``."""
    if file is None:
        file = exit_bb.file
    seeds = {
        out for a in _txna_reads(prog, immediates, file=file)
        for out in a.outputs if isinstance(out, SSAVar)
    }
    return _approval_exit_protected_for_seeds(
        prog, exit_bb, seeds, file=file, allow_unary_cmp=True,
    )
