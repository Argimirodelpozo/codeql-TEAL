"""Enforcement reachability: does a comparison result reach an ``assert`` /
branch-to-reject sink, i.e. is the check ENFORCED rather than dropped?
Import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.avm import CMP_OPS
from tealql.tealtools.ssa import BasicBlock, SSAProgram, SSAVar

from ._program_shape import file_match, is_rejection_exit



# ---------------------------------------------------------------------------
# Path-aware "approval exit protected for field": every entry→exit path crosses a
# BB whose comparison consumes a txn FIELD read (through sub / scratch bridges)
# and whose result reaches an enforcement sink. Stronger than dominance — it
# accepts replicated per-branch checks.
# ---------------------------------------------------------------------------


_ENFORCEMENT_TERM_OPS = frozenset({"assert", "bnz", "bz"})


def scratch_forward_map(prog: SSAProgram) -> dict:
    """``{stored_var: [load_output_var, ...]}`` — the scratch round-trips a value
    PROVABLY survives, so ``==; store 0; load 0; assert`` still reads as enforced.

    HAZARD: MUST-semantics. A ``load N`` continues the chain only when EVERY
    ``store N`` that may influence it wrote that same SSAVar, or the walk would
    claim an assert enforces a value some other store replaced. NON-mutating,
    unlike ``propagate_scratch_values``, so it is safe on the scan-shared program."""
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
    """``(file, label_name) -> source line`` for branch-target resolution."""
    out: dict[tuple[str, str], int] = {}
    for f, ln, code in prog.labels:
        out[(f, code.rstrip(":").strip())] = ln
    return out




def _bb_at(prog: SSAProgram, file: str, line: int) -> Optional[BasicBlock]:
    for bb in prog.blocks.values():
        if bb.file == file and bb.first_line == line:
            return bb
    return None




#: Conditions whose FALSITY is itself a positive pin: ``!(a != b)`` is ``a == b``.
_NEGATED_COND_OPS = frozenset({"!=", "b!=", "!"})

#: ``assert(A && B)`` forces A, so the walk crosses ``&&`` unconditionally.
#: ``||`` does NOT — see :func:`_disjunction_is_enforcing`.
_CONJUNCTION_OPS = frozenset({"&&"})
_DISJUNCTION_OPS = frozenset({"||"})


def _disjunct_constrains_field(prog: SSAProgram, var, field_vars: set,
                               seen: Optional[set] = None) -> bool:
    """``var`` (a boolean) compares a value flowing from ``field_vars``.

    Connectives keep their real semantics: ``&&`` constrains when EITHER side does
    (both are forced), ``||`` only when BOTH do, ``!`` is transparent."""
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
    arrived along ``arrived_from``? Only when EVERY other arm constrains the same
    field, so no arm leaves it free.

    HAZARD: ``assert(A || B)`` does NOT force A — whenever B holds, A is free.
    Crossing a disjunction unconditionally makes ``assert(RekeyTo == ZeroAddress
    || Fee < 1000)`` read as a rekey guard, which an attacker bypasses with a
    low-fee txn. With no ``field_vars`` the answer is conservatively no."""
    if not field_vars:
        return False
    others = [i for i in disj.inputs if i is not arrived_from]
    return bool(others) and all(
        _disjunct_constrains_field(prog, o, field_vars) for o in others)


def branch_gates_rejection(
    prog: SSAProgram, branch, label_lines: dict[tuple[str, str], int],
) -> bool:
    """The ``bnz``/``bz`` at ``branch`` gates rejection on its condition, so
    reaching an approval past it means the condition held.

    HAZARD: polarity decides the verdict. Rejecting on FALSE credits the
    comparison AS WRITTEN, always. Rejecting on TRUE credits only its NEGATION,
    so it counts only for a negated condition (``!=``/``b!=``/``!``) — a plain
    ``==`` whose FALSE side approves pins the field AWAY from the compared value,
    which is the inverted-check antipattern, not a guard. Compound ``&&``/``||``
    on the true-rejects side stay uncredited (over-report, never under-report)."""
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
    """The SSA chain rooted at ``var`` terminates in an ``assert`` or a
    :func:`branch_gates_rejection` branch, walking through every consuming opcode
    that produces a def (``&&``, ``dup``, …) and through provably-preserving
    scratch round-trips.

    ``field_vars`` names the field seeds under test, which is what makes a ``||``
    decidable: ``assert(A || B)`` enforces A only when B pins the same field.
    Without it a ``||`` stops the walk (conservative)."""
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
        # other arm pins the same field — see _disjunction_is_enforcing.
        if cons.op in _DISJUNCTION_OPS and not _disjunction_is_enforcing(
                prog, cons, var, field_vars):
            continue
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
    """The successor reached by NOT taking ``bb``'s terminating branch — identified
    as the successor at the smallest source line strictly greater than
    ``bb.last_line``, since branch targets sit at labels elsewhere.
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
    """Some file-matched assignment with op in ``ops`` satisfying ``flows(op)`` has
    its result reach enforcement — the shared "is there a genuine, ENFORCED check
    of form X?" recogniser, since a check whose result is dropped enforces nothing."""
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
