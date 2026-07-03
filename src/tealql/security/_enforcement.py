"""Enforcement reachability: does a comparison result actually reach an
``assert`` / branch-to-reject sink (i.e. is the check ENFORCED, not dropped)?

Split out of ``common.py``; import via :mod:`tealql.security.common`.
"""
from __future__ import annotations

from typing import Optional

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
