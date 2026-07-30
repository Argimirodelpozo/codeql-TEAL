"""Approval / rejection exit classification — ONE source of truth, in the
substrate; ``security._program_shape`` re-exports it (dependency direction is
security -> tealtools, never the reverse).

A TEAL program ends at a ``return`` (the popped value approves when non-zero) or
an ``err`` (always rejects). Conservative by construction: an exit whose value is
not provably the constant zero counts as approving, so a detector reasoning over
approving exits never loses one.

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

from ..ssa import BasicBlock, const_int


def returned_zero(bb: BasicBlock) -> bool:
    """The BB provably terminates the program with ``int 0; return``.

    HAZARD: ``return``'s modelled stack effect is ``(0, 0)`` (:data:`avm.SIG`, so
    the exit stack survives for the lift), so the approval value is NEVER on
    ``last.inputs`` — read it off the second-to-last assignment. Anything not
    provably zero yields ``False``, leaving the exit a potential approval."""
    if len(bb.assignments) < 2:
        return False
    if bb.assignments[-1].op != "return":
        return False
    prev = bb.assignments[-2]
    if not prev.outputs:
        return False
    return const_int(prev.outputs[0]) == 0


def is_approval_exit(bb: BasicBlock) -> bool:
    """An approval exit: the BB ends in ``return`` with a value that is non-zero
    or not statically resolvable."""
    if not bb.assignments:
        return False
    if bb.assignments[-1].op != "return":
        return False
    return not returned_zero(bb)


def is_rejection_exit(bb: BasicBlock) -> bool:
    """A rejection exit: the BB ends in ``err`` or ``return 0``.

    Deliberately NOT ``retsub`` — see the module hazard note."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "err":
        return True
    return last.op == "return" and returned_zero(bb)
