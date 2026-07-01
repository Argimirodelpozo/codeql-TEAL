"""sec-guide/group-size-check: missing GroupSize check (path-aware).

Per-approval-exit: each exit must be reachable only along CFG paths
that cross a BB where ``global GroupSize`` flows into a comparison
whose result reaches enforcement. Uses the same machinery as
:mod:`security.rekey_to`, but seeded from ``global FIELD``
reads instead of ``txn FIELD``.

GATED on the program actually using an **absolute** group index
(``gtxn`` / ``gtxna`` / ``gtxnas`` — index in the first immediate). The
GroupSize concern is "the contract reads ``gtxn N`` assuming a sibling at
index N exists" — without an absolute index there is no such assumption, so
flagging the absence of a GroupSize check is a false positive. (A dynamic
``gtxns`` index is popped off the stack and is bounds-checked by the AVM, so it
doesn't trigger this either.) This matches the reference linter (Tealer), which
fires only on absolute-index usage; without the gate we flagged essentially
every contract.

Replaces the old heuristic (``compared anywhere?`` + per-``gtxn``
finding gated on whole-program presence) which produced false
negatives whenever the validation was on one branch only, or in a
subroutine never called on every path.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import BasicBlock, SSAProgram
from security import common


# Absolute-index group-txn reads (index in the first immediate). The dynamic
# ``gtxns*`` family pops the index off the stack and is AVM-bounds-checked, so it
# does not create the "assumes a sibling at index N" hazard this detector covers.
_ABS_GROUP_INDEX_OPS = frozenset({"gtxn", "gtxna", "gtxnas"})


def _uses_absolute_group_index(prog: SSAProgram, file: Optional[str]) -> bool:
    return any(
        a.op in _ABS_GROUP_INDEX_OPS and common.file_match(a.location.file, file)
        for a in prog.assignments
    )


@dataclass
class GroupSizeCheckViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a global GroupSize check — "
            "attackers can pad the group with extra transactions."
        )

    def __repr__(self) -> str:
        return f"GroupSizeCheckViolation({self.pretty()})"


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
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_global_field(
                self.prog, exit_bb, "GroupSize", file=self.file,
            ):
                out.append(GroupSizeCheckViolation(exit_bb))
        return out
