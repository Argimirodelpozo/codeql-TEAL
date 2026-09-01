"""Enforcement reachability: does a comparison result reach an ``assert`` /
branch-to-reject sink, i.e. is the check ENFORCED rather than dropped?
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.language.avm import CMP_OPS
from tealql.tealtools.ssa import (BasicBlock, SSAProgram, SSAVar,
                                  const_int)

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


def _acted_on(prog: SSAProgram, var, depth: int = 0, truthy: bool = False) -> bool:
    """Does the callee's returned ZERO in ``var`` reject one frame up — reach an
    ``assert`` while still falsy, or a branch whose side taken ON THIS VALUE is
    a real rejection exit? Walks op uses AND phi membership.

    HAZARD: phi consumers are NOT in ``var.uses`` (that holds op uses only), and
    the caller sees a callee's return value precisely AS a phi over the callee's
    ``retsub`` arms — so skipping phis misses every case this exists for.

    HAZARD: POLARITY. On this arm the value is exactly 0 (``truthy=False``) or,
    after ``!`` / a const comparison, exactly 1 — so `callsub check; bnz reject`
    (rejects on NONZERO, approves on the callee's 0) must NOT credit the 0 as a
    rejection, and ``!; assert`` PASSES on the 0. A value laundered through any
    other op has unknown truth and credits nothing.

    Deliberately calls ``is_rejection_exit`` and never ``_rejects``: recursing
    back through the callee-return credit would not terminate."""
    if depth > 6:
        return False
    label_lines = None
    for use in getattr(var, "uses", ()):
        if use.op == "assert":
            if not truthy:                     # assert 0 fails -> rejects
                return True
            continue
        if use.op in ("bnz", "bz"):
            bb = use.basic_block
            if bb is None:
                continue
            if label_lines is None:
                label_lines = _label_to_bb_first_line(prog)
            target = None
            target_line = label_lines.get(
                (use.location.file, use.immediates.strip()))
            if target_line is not None:
                target = _bb_at(prog, use.location.file, target_line)
            taken = (target if (use.op == "bnz") == truthy
                     else _fall_through_bb(prog, bb))
            if taken is not None and is_rejection_exit(taken):
                return True
            continue
        if use.op == "!":
            if any(_acted_on(prog, o, depth + 1, not truthy)
                   for o in use.outputs):
                return True
            continue
        if use.op in ("==", "!=") and len(use.inputs) == 2:
            other = use.inputs[1] if use.inputs[0] is var else use.inputs[0]
            k = const_int(other)
            if k is not None:
                cur = 1 if truthy else 0
                res = (cur == k) if use.op == "==" else (cur != k)
                if any(_acted_on(prog, o, depth + 1, res)
                       for o in use.outputs):
                    return True
            continue
        # Laundered through an arbitrary op: truth unknown, credit nothing.
    for ph in prog.phis.values():
        if any(a is var for a in ph.args) and _acted_on(
                prog, ph, depth + 1, truthy):
            return True
    return False


def _callee_zero_return_rejects(prog: SSAProgram, bb: BasicBlock) -> bool:
    """``bb`` ends ``int 0; retsub`` and the 0 it hands back is ACTED ON by the
    caller, so returning it does reject — just one frame up.

    HAZARD: ``retsub`` is NOT an exit (see ``cfg.exits``); it resumes in the
    caller, which may assert the value, branch on it, or IGNORE it. This is the
    only sound way to credit the Puya validator idiom ``callsub check; assert``
    without also crediting a callee whose verdict the caller DISCARDS — a check
    with no effect on the outcome, i.e. a real vulnerability that the previous
    "retsub counts as a rejection" rule read as safe."""
    if len(bb.assignments) < 2 or bb.assignments[-1].op != "retsub":
        return False
    prev = bb.assignments[-2]
    if not prev.outputs or const_int(prev.outputs[0]) != 0:
        return False
    return _acted_on(prog, prev.outputs[0])


def _rejects(prog: SSAProgram, bb: "Optional[BasicBlock]") -> bool:
    """A real program rejection, or a callee 0-return the caller acts on."""
    if bb is None:
        return False
    return is_rejection_exit(bb) or _callee_zero_return_rejects(prog, bb)


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
    rejects_when_false, rejects_when_true = branch_reject_polarity(
        prog, branch, label_lines)
    if rejects_when_false:
        return True
    if rejects_when_true and branch.inputs:
        cond = branch.inputs[0]
        d = getattr(cond, "defined_by", None)
        return d is not None and d.op in _NEGATED_COND_OPS
    return False


def branch_reject_polarity(
    prog: SSAProgram, branch, label_lines: dict[tuple[str, str], int],
) -> tuple[bool, bool]:
    """``(rejects_when_false, rejects_when_true)`` for a ``bnz``/``bz``.

    The polarity pair is what guard reasoning actually needs: a ``!=``-spelled
    comparison is a guard only when the TRUE side rejects (the surviving path
    then carries equality), and :func:`branch_gates_rejection`'s single boolean
    cannot distinguish that from the rejects-on-FALSE anti-guard."""
    bb = getattr(branch, "basic_block", None)
    if bb is None:
        return False, False
    target = None
    target_line = label_lines.get((branch.location.file, branch.immediates.strip()))
    if target_line is not None:
        target = _bb_at(prog, branch.location.file, target_line)
    fall_through = _fall_through_bb(prog, bb)
    target_rejects = _rejects(prog, target)
    ft_rejects = _rejects(prog, fall_through)

    if branch.op == "bnz":       # taken on TRUE, falls through on FALSE
        return ft_rejects, target_rejects
    # bz: taken on FALSE, falls through on TRUE
    return target_rejects, ft_rejects




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
        # `field_vars` must survive the round-trip too — dropping it made a
        # `||` after a scratch bridge non-enforcing while the collecting twin
        # (`_collect_field_enforcement_bbs`) kept it: same walk, two verdicts.
        if def_forward_reaches_enforcement(
                prog, fwd, label_lines=label_lines, seen=seen,
                scratch_fwd=scratch_fwd, field_vars=field_vars):
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
