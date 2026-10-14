"""sec-guide/group-size-check: an approval exit reachable without crossing an
ENFORCED comparison of ``global GroupSize``.

GATED per EXIT on an ABSOLUTE group index (``gtxn``/``gtxna``/``gtxnas``) read
on a path to it: the concern is "this path reads ``gtxn N`` assuming a sibling
at index N exists", and without that assumption the finding is a false positive.
A dynamic ``gtxns`` index is AVM-bounds-checked and does not count.

HAZARD: per exit, not per program. Gating on "the program has an absolute gtxn
somewhere" flagged every approving exit of an app with one gtxn-reading method
(195 mainnet FP cells, class ``exit-path-reads-no-absolute-gtxn``). The walk
from each read carries a return stack, so a read in one arm does not leak into
another arm's exit through a shared helper's ``retsub`` fan-out.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.security._approval_exit import _ApprovalExitViolation
from tealql.security._field_protection import approval_exit_protected_for_global_field
from tealql.security._program_shape import (approving_exits,
                                            exits_reachable_through,
                                            file_match)


# Absolute-index group-txn reads (index in the first immediate).
_ABS_GROUP_INDEX_OPS = frozenset({"gtxn", "gtxna", "gtxnas"})


def _absolute_group_read_blocks(prog: SSAProgram, file: Optional[str]) -> list:
    blocks = {a.basic_block for a in prog.assignments
              if a.op in _ABS_GROUP_INDEX_OPS and a.basic_block is not None
              and file_match(a.location.file, file)}
    return sorted(blocks, key=lambda b: (b.file, b.first_line))


def exits_after_absolute_group_read(prog: SSAProgram, exits, file: Optional[str]) -> set:
    """``id`` of every exit in ``exits`` that a realizable path reaches THROUGH
    an absolute group-index read."""
    exits = set(exits)
    out: set = set()
    for rbb in _absolute_group_read_blocks(prog, file):
        out.update(id(e) for e in exits_reachable_through(prog, rbb, exits))
        if len(out) == len(exits):
            break
    return out


class GroupSizeCheckViolation(_ApprovalExitViolation):
    message = ('is reachable without a global GroupSize check — attackers can pad the group with extra transactions.')


class GroupSizeCheckDetector:
    severity = "high"
    name = "sec-guide/group-size-check"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[GroupSizeCheckViolation]:
        exits = approving_exits(self.prog, file=self.file)
        # No absolute group index on the exit's path => no "assumes sibling
        # at index N" hazard there.
        in_scope = exits_after_absolute_group_read(self.prog, exits, self.file)
        out: list[GroupSizeCheckViolation] = []
        for exit_bb in sorted(exits, key=lambda b: (b.file, b.first_line)):
            if id(exit_bb) not in in_scope:
                continue
            # `GroupSize >= K` compares the size and caps nothing: only an
            # exact pin or an UPPER bound stops padding.
            if not approval_exit_protected_for_global_field(
                self.prog, exit_bb, "GroupSize", file=self.file, safe="size-bound",
            ):
                out.append(GroupSizeCheckViolation(exit_bb))
        return out
