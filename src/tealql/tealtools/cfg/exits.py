"""Approval / rejection exit classification — ONE source of truth.

A TEAL program ends at a ``return`` (the popped value approves when non-zero)
or an ``err`` (always rejects). Telling an *approving* exit from a *rejecting*
one is needed all over the stack — group-shape reasoning intersects facts over
approving exits, the cross-contract layer summarises what a caller may assume
after a successful call, and the security detectors ask "is this approving exit
protected?" — and it was previously implemented twice, in two different and
DISAGREEING ways:

* ``security._program_shape`` read the value off the second-to-last assignment
  (correct), and
* ``PathPredicateAnalysis.approving_exits`` read it off ``return``'s stack
  inputs — which are ALWAYS EMPTY, because :data:`tealql.tealtools.avm.SIG`
  deliberately models ``return`` as ``(0, 0)`` so the exit stack survives for
  the lift. That check could never fire, so every ``int 0; return`` reject arm
  counted as an approval and polluted every intersection built over it.

Hence this module: the classification lives here, in the substrate, and
``security._program_shape`` re-exports it (the dependency direction is
security -> tealtools, never the reverse).

Conservative by construction: an exit whose return value is not provably the
constant zero counts as approving, so a detector that reasons over approving
exits never loses one.
"""
from __future__ import annotations

from ..ssa import BasicBlock, const_int


def returned_zero(bb: BasicBlock) -> bool:
    """The BB provably terminates with ``int 0; return`` (or ``retsub``).

    ``return``'s modelled stack effect is ``(0, 0)`` (see :data:`avm.SIG`), so
    the popped approval value is NOT on ``last.inputs`` — the next-best signal
    is the BB's second-to-last assignment: when it produces a const-zero SSAVar
    the program is returning 0. Conservative: anything not provably zero yields
    ``False``, so the exit stays classified as a potential approval."""
    if len(bb.assignments) < 2:
        return False
    if bb.assignments[-1].op not in ("return", "retsub"):
        return False
    prev = bb.assignments[-2]
    if not prev.outputs:
        return False
    return const_int(prev.outputs[0]) == 0


def is_approval_exit(bb: BasicBlock) -> bool:
    """An approval exit: the BB ends in ``return`` and the returned value is
    non-zero or not statically resolvable (see :func:`returned_zero`)."""
    if not bb.assignments:
        return False
    if bb.assignments[-1].op != "return":
        return False
    return not returned_zero(bb)


def is_rejection_exit(bb: BasicBlock) -> bool:
    """A rejection exit: the BB ends in ``err``, ``return 0``, or ``intc_0;
    retsub`` (returning 0 from a subroutine — the compiled form of a validator
    sub's "reject" arm; overwhelmingly a program rejection when reached from a
    failed security check, e.g. ``<check>; bz <return-0-block>``)."""
    if not bb.assignments:
        return False
    last = bb.assignments[-1]
    if last.op == "err":
        return True
    return last.op in ("return", "retsub") and returned_zero(bb)
