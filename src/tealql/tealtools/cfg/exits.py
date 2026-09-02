"""Approval / rejection exit classification — ONE source of truth, in the
substrate; ``security._program_shape`` re-exports it (dependency direction is
security -> tealtools, never the reverse).

A TEAL program ends at a ``return`` (the popped value approves when non-zero),
an ``err`` (always rejects), or by RUNNING OFF THE END: ``pc == len(program)``
terminates normally and the AVM then requires exactly one int on the stack and
approves iff it is non-zero. That third ending is how every pre-``return``
(v1/v2) program approves, how a branch to a label at EOF approves, and how a
``callsub`` as the last instruction approves (its ``retsub`` resumes at
``pc == len(program)``). Conservative by construction: an exit whose value is
not provably the constant zero counts as approving, so a detector reasoning
over approving exits never loses one.

HAZARD: ``retsub`` is NEVER an exit. It pops the call frame and resumes in the
CALLER, which then decides what the returned value means — assert it, invert it,
store it, or ignore it. ``int 0; retsub`` therefore is not a rejection: it is a
callee reporting false to code this function cannot see. Treating it as one
credits a guard on the strength of the Puya validator idiom (``callsub check;
assert``) without ever checking that the caller actually asserts, which suppresses
real findings. It fired on 16% of everything previously classified as a rejection
exit across 150 mainnet contracts, so this is not a hypothetical.
"""
from __future__ import annotations

from ..ssa import BasicBlock, const_int, operand_const

#: Terminators that END this block's flow themselves. A successor-less block
#: ending in anything else fell off the program (v1 ``==`` at EOF, a plain op
#: before EOF) or branched to a target the builder could not resolve — both
#: leave the program, and the conservative reading of that is an approval.
_SELF_TERMINATING = frozenset({"return", "err", "retsub"})


def _runs_off_end(bb: BasicBlock) -> bool:
    """Control leaves the program at ``bb``'s end WITHOUT a ``return``/``err``.

    Two spellings of the same fact: construction flagged the block (a branch
    or ``callsub``-return to EOF — the block may well have OTHER successors),
    or the block is successor-less with a terminator that does not end flow
    itself (plain fall-off at EOF)."""
    if getattr(bb, "off_end", False):
        return True
    if bb.successors or not bb.assignments:
        return False
    return bb.assignments[-1].op not in _SELF_TERMINATING


def _off_end_rejects(bb: BasicBlock) -> bool:
    """The AVM PROVABLY rejects when ``bb`` runs off the end.

    The verdict is the exit stack (BOTTOM-first, top = ``[-1]``): a bytes top
    or a zero top rejects; so does any depth other than one — but the sim's
    depth is exact only when every cell is a named value and no cell is a
    ``partial`` merge (a max-window join OVER-reports depth, and a sub body
    cannot see its caller's residual — under-reporting, which can never make
    a too-deep stack look like one cell). Anything not provable approves."""
    stack = bb.exit_stack
    if not stack:
        return False                 # depth 0 rejects, but so does an unwalked
    top = stack[-1]                  # block look — not provable, so approve
    if top is not None:
        c = operand_const(top)
        if c is not None and c.kind == "bytes":
            return True
        if const_int(top) == 0:
            return True
    if len(stack) == 1:
        return False
    return all(cell is not None and not getattr(cell, "partial", False)
               for cell in stack)


def returned_zero(bb: BasicBlock) -> bool:
    """The BB provably terminates the program with the constant zero as its
    verdict: ``int 0; return``, or running off the end with a provably
    rejecting stack.

    Anything not provably zero yields ``False``, leaving the exit a potential
    approval. ``return`` owns its real AVM operand in canonical SSA."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "return":
        return bool(last.inputs) and const_int(last.inputs[0]) == 0
    return _runs_off_end(bb) and _off_end_rejects(bb)


def is_approval_exit(bb: BasicBlock) -> bool:
    """An approval exit: the BB ends in ``return``, or runs off the end of the
    program, with a verdict that is non-zero or not statically resolvable."""
    if not bb.assignments:
        return False
    if bb.assignments[-1].op != "return" and not _runs_off_end(bb):
        return False
    return not returned_zero(bb)


def is_rejection_exit(bb: BasicBlock) -> bool:
    """A rejection exit: the BB ends in ``err``, ``return 0``, or runs off the
    end with a provably rejecting stack.

    Deliberately NOT ``retsub`` — see the module hazard note."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "err":
        return True
    if last.op == "return":
        return returned_zero(bb)
    return _runs_off_end(bb) and _off_end_rejects(bb)
