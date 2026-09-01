"""sec-guide/group-size-check: an approval exit reachable without crossing an
ENFORCED comparison of ``global GroupSize``.

GATED on the program using an ABSOLUTE group index (``gtxn``/``gtxna``/
``gtxnas``): the concern is "the contract reads ``gtxn N`` assuming a sibling at
index N exists", and without that assumption the finding is a false positive on
essentially every contract. A dynamic ``gtxns`` index is AVM-bounds-checked and
does not count.
"""
from __future__ import annotations

from typing import Optional

from tealql.tealtools.ssa import SSAProgram
from tealql.security._approval_exit import _ApprovalExitViolation
from tealql.security._field_protection import approval_exit_protected_for_global_field
from tealql.security._program_shape import approving_exits, file_match


# Absolute-index group-txn reads (index in the first immediate).
_ABS_GROUP_INDEX_OPS = frozenset({"gtxn", "gtxna", "gtxnas"})


def _uses_absolute_group_index(prog: SSAProgram, file: Optional[str]) -> bool:
    return any(
        a.op in _ABS_GROUP_INDEX_OPS and file_match(a.location.file, file)
        for a in prog.assignments
    )


class GroupSizeCheckViolation(_ApprovalExitViolation):
    message = ('is reachable without a global GroupSize check — attackers can pad the group with extra transactions.')


class GroupSizeCheckDetector:
    severity = "high"
    name = "sec-guide/group-size-check"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[GroupSizeCheckViolation]:
        # No absolute group index => no "assumes sibling at index N" hazard.
        if not _uses_absolute_group_index(self.prog, self.file):
            return []
        out: list[GroupSizeCheckViolation] = []
        for exit_bb in sorted(
            approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not approval_exit_protected_for_global_field(
                self.prog, exit_bb, "GroupSize", file=self.file,
            ):
                out.append(GroupSizeCheckViolation(exit_bb))
        return out
