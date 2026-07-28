"""Enforcement reachability: does a comparison result actually reach an
``assert`` / branch-to-reject sink (i.e. is the check ENFORCED, not dropped)?

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.avm import CMP_OPS
from tealql.tealtools.ssa import BasicBlock, SSAProgram, SSAVar

from ._program_shape import file_match, is_rejection_exit



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


def scratch_forward_map(prog: SSAProgram) -> dict:
    """``{stored_var: [load_output_var, ...]}`` — the scratch round-trips a value
    PROVABLY survives: a ``load N`` continues a value's forward chain only when
    EVERY ``store N`` that may influence it (per the reaching-definitions
    ``scratch_stores`` annotation) wrote that same SSAVar. Must-semantics — the
    same rule as ``propagate_scratch_values`` — so following these edges never
    claims an assert enforces a value some other store may have replaced. Unlike
    that pass this is NON-mutating, safe on the scan-shared program.

    Without it, a check written as ``==; store 0; load 0; assert`` reads as
    unenforced (the forward walk dies at the output-less ``store``) — a false
    "unvalidated" for every detector in this family."""
    prog._ensure_scratch_influence()
    influence = getattr(prog, "_scratch_influence", None) or {}
    out: dict = {}
    for (load_file, load_line), store_keys in influence.items():
        load_var = prog.var(load_file, load_line, 1)
        if load_var is None or not store_keys:
            continue
        sources = [prog.var(*k) for k in store_keys]
        first = sources[0]
        if (first is not None and first is not load_var
                and all(s is first for s in sources)):
            out.setdefault(first, []).append(load_var)
    return out




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




#: Conditions whose FALSITY is itself a positive pin on the compared value:
#: ``!(a != b)`` is ``a == b``, ``!(!x)`` is ``x``. See
#: :func:`branch_gates_rejection`.
_NEGATED_COND_OPS = frozenset({"!=", "b!=", "!"})

#: Boolean connectives the enforcement walk may cross. ``&&`` is unconditional:
#: ``assert(A && B)`` forces A, so a check composed into a conjunction is still
#: enforced. ``||`` is NOT, and is handled separately -- see
#: :func:`_disjunction_is_enforcing`.
_CONJUNCTION_OPS = frozenset({"&&"})
_DISJUNCTION_OPS = frozenset({"||"})


def _disjunct_constrains_field(prog: SSAProgram, var, field_vars: set,
                               seen: Optional[set] = None) -> bool:
    """``var`` (a boolean) constrains the field: its defining expression compares
    a value flowing from ``field_vars``.

    Recurses through the connectives with their real semantics: a conjunction
    constrains the field when EITHER side does (both are forced), a disjunction
    only when BOTH sides do, and ``!`` is transparent (a negated comparison of
    the field still compares the field)."""
    from ._value_flow import _operand_flows_from_field_var
    if seen is None:
        seen = set()
    if var is None or id(var) in seen:
        return False
    seen.add(id(var))
    d = getattr(var, "defined_by", None)
    if d is None:
        return False
    if d.op in _CONJUNCTION_OPS:
        return any(_disjunct_constrains_field(prog, i, field_vars, seen)
                   for i in d.inputs)
    if d.op in _DISJUNCTION_OPS:
        return bool(d.inputs) and all(
            _disjunct_constrains_field(prog, i, field_vars, seen)
            for i in d.inputs)
    if d.op == "!":
        return any(_disjunct_constrains_field(prog, i, field_vars, seen)
                   for i in d.inputs)
    if d.op in CMP_OPS:
        return any(_operand_flows_from_field_var(prog, op, field_vars)
                   for op in d.inputs)
    return False


def _disjunction_is_enforcing(prog: SSAProgram, disj, arrived_from,
                              field_vars: Optional[set]) -> bool:
    """May the enforcement walk continue THROUGH the ``||`` at ``disj``, having
    arrived along ``arrived_from``?

    ``assert(A || B)`` does **not** force A: whenever B holds, A is free. Walking
    through a disjunction unconditionally is how ``assert(RekeyTo == ZeroAddress
    || Fee < 1000)`` came to read as a rekey guard -- an attacker just sends a
    low-fee transaction and rekeys the account. The same hole existed in every
    detector on this path (rekey-to, close-remainder-to, asset-close-to,
    fee-validation).

    The disjunction IS enforcing when EVERY arm independently constrains the
    same field, because then no arm leaves the field free: ``assert(RekeyTo ==
    ZeroAddress || RekeyTo == knownSafe)`` is a real, if unusual, pin. That test
    needs to know which field is at stake, so with no ``field_vars`` the answer
    is conservatively no -- over-reporting, never under-reporting, the same
    stance :func:`branch_gates_rejection` takes on compound conditions."""
    if not field_vars:
        return False
    others = [i for i in disj.inputs if i is not arrived_from]
    return bool(others) and all(
        _disjunct_constrains_field(prog, o, field_vars) for o in others)


def branch_gates_rejection(
    prog: SSAProgram, branch, label_lines: dict[tuple[str, str], int],
) -> bool:
    """The ``bnz`` / ``bz`` at ``branch`` gates rejection on the condition, so
    reaching an approval past it means the condition held.

    Four shapes, by which edge lands on a rejection exit:

    ====================  ===============================  ====================
    rejecting edge        surviving constraint             credited?
    ====================  ===============================  ====================
    cond is FALSE         the comparison AS WRITTEN holds  yes, always
    cond is TRUE          the comparison's NEGATION holds  only when negated
    ====================  ===============================  ====================

    The first row is the classic ``cmp; bz reject`` / ``cmp; bnz ok; err`` pair
    and was the only thing recognised. The second row was recognised NOWHERE,
    which made the idiomatic hand-written guard ``txn RekeyTo; global
    ZeroAddress; !=; bnz fail`` (``fail: err``) read as UNENFORCED — a false
    positive on a contract that pins RekeyTo to the zero address exactly as
    correctly as the accepted ``==; assert`` form.

    It is credited only when the condition is a NEGATED form (``!=`` / ``b!=``
    / ``!``), because then its falsity is the positive comparison. A plain
    ``==`` whose FALSE side approves is deliberately NOT credited: that pins
    the field AWAY from the compared value — the "the check is inverted, so
    approval requires the dangerous value" antipattern (see the
    ``false_path_approves__vuln_inverted_bz`` fixture). Compound conditions
    (``&&`` / ``||``) on the true-rejects side stay uncredited: conservative,
    i.e. it may still over-report, never under-report."""
    bb = getattr(branch, "basic_block", None)
    if bb is None:
        return False
    target = None
    target_line = label_lines.get((branch.location.file, branch.immediates.strip()))
    if target_line is not None:
        target = _bb_at(prog, branch.location.file, target_line)
    fall_through = _fall_through_bb(prog, bb)
    target_rejects = target is not None and is_rejection_exit(target)
    ft_rejects = fall_through is not None and is_rejection_exit(fall_through)

    if branch.op == "bnz":       # taken on TRUE, falls through on FALSE
        rejects_when_false, rejects_when_true = ft_rejects, target_rejects
    else:                        # bz: taken on FALSE, falls through on TRUE
        rejects_when_false, rejects_when_true = target_rejects, ft_rejects

    if rejects_when_false:
        return True
    if rejects_when_true and branch.inputs:
        cond = branch.inputs[0]
        d = getattr(cond, "defined_by", None)
        return d is not None and d.op in _NEGATED_COND_OPS
    return False




def def_forward_reaches_enforcement(
    prog: SSAProgram,
    var: SSAVar,
    *,
    label_lines: Optional[dict[tuple[str, str], int]] = None,
    seen: Optional[set[SSAVar]] = None,
    scratch_fwd: Optional[dict] = None,
    field_vars: Optional[set] = None,
) -> bool:
    """The def-forward reaches an enforcement: the SSA chain rooted at
    ``var`` terminates in some opcode that enforces rejection when the
    original value is false.

    ``field_vars`` names the field seeds under test, which is what makes a
    disjunction decidable: ``assert(A || B)`` enforces A only when B pins the
    same field too. Without it a ``||`` simply stops the walk (conservative).

    Recognised sinks:
      - ``assert`` consumes the SSA chain.
      - a ``bnz`` / ``bz`` consumes it and EITHER of its two edges lands on a
        *rejection exit* (``err`` or ``return 0`` — see
        :func:`is_rejection_exit`), in either polarity — see
        :func:`branch_gates_rejection`.

    Walks through every consuming opcode that produces an SSA def
    (``&&``, ``||``, ``dup``, etc.), so compositions like ``cmp1; cmp2;
    &&; assert`` and ``cmp; dup; bnz target; err`` are all recognised.

    The ``return 0`` form is essential for LogicSigs and ABI-router
    code that branches on failure to a ``pushint 0; return`` block
    rather than an explicit ``err`` — the old ``first-op-is-err`` check
    silently missed every such guard.

    A value round-tripped through scratch (``store N`` … ``load N``) keeps its
    chain when the round-trip provably preserves it (:func:`scratch_forward_map`,
    must-semantics), so ``cmp; store 0; load 0; assert`` counts as enforced.
    """
    if seen is None:
        seen = set()
    if var in seen:
        return False
    seen.add(var)
    label_lines = label_lines if label_lines is not None else _label_to_bb_first_line(prog)
    if scratch_fwd is None:
        scratch_fwd = scratch_forward_map(prog)
    for fwd in scratch_fwd.get(var, ()):        # survive a store/load round-trip
        if def_forward_reaches_enforcement(
                prog, fwd, label_lines=label_lines, seen=seen,
                scratch_fwd=scratch_fwd):
            return True
    for cons in var.uses:
        if cons.op == "assert":
            return True
        if cons.op in ("bnz", "bz") and branch_gates_rejection(
                prog, cons, label_lines):
            return True
        # A disjunction does not carry enforcement to THIS operand unless every
        # other arm pins the same field -- see _disjunction_is_enforcing.
        if cons.op in _DISJUNCTION_OPS and not _disjunction_is_enforcing(
                prog, cons, var, field_vars):
            continue
        # Step: consume produces an SSA def whose forward chain we walk.
        for out in cons.outputs:
            if not isinstance(out, SSAVar):
                continue
            if def_forward_reaches_enforcement(
                prog, out, label_lines=label_lines, seen=seen,
                scratch_fwd=scratch_fwd, field_vars=field_vars,
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
    label_lines = _label_to_bb_first_line(prog)
    scratch_fwd = scratch_forward_map(prog)
    for op in prog.assignments:
        if op.op not in ops or not file_match(op.location.file, file):
            continue
        if not flows(op):
            continue
        if op.outputs and isinstance(op.outputs[0], SSAVar) and \
                def_forward_reaches_enforcement(
                    prog, op.outputs[0], label_lines=label_lines,
                    scratch_fwd=scratch_fwd):
            return True
    return False
