"""Label -> line / block resolution over a finished :class:`SSAProgram` — ONE
home, shared by every consumer that must re-derive a branch target by NAME
(the switch/match arm test in :mod:`.path_predicates`, the dangling-callsub
recovery in :mod:`.subroutines`).

HAZARD (agreement with :mod:`.build`): a duplicate label resolves to its
FIRST definition, as the CFG builder does. Two maps that disagree about which
block a branch "took" INVERT a predicate's polarity — see the hazard on the
former ``PathPredicateAnalysis._index_labels``.

HAZARD (empty labels): a label owns no :class:`BasicBlock` when nothing but
another label follows it (``on_noop:`` / ``real_noop:`` aliases — TEALScript
emits 18 of them in one contract). The graph forwards its edges to the next
real block, whose ``first_line`` is the SECOND label's line, so matching a
target by LINE finds nothing and the arm is misread as the fall-through. The
target is the first block AT OR AFTER the label's line, and two aliased labels
resolve to the SAME block — which is what lets a positional consumer notice a
target named twice.
"""
from __future__ import annotations

import bisect
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from ..ssa import BasicBlock, SSAProgram


class LabelIndex:
    """``(file, label name) -> line / block`` for one program."""

    __slots__ = ("_lines", "_lines_any", "_starts", "_blocks")

    def __init__(self, prog: "SSAProgram"):
        self._lines: dict[tuple[str, str], int] = {}
        self._lines_any: dict[str, int] = {}
        for f, ln, code in prog.labels:
            # Label code is the source line, e.g. "l_target:".
            name = code.rstrip(":").strip()
            self._lines.setdefault((f, name), ln)
            self._lines_any.setdefault(name, ln)
        # `subroutines` documents a duck-typed block interface (no `.file`);
        # such blocks pool under None and answer for every file.
        by_file: dict[Optional[str], list["BasicBlock"]] = {}
        for bb in prog.blocks.values():
            by_file.setdefault(getattr(bb, "file", None), []).append(bb)
        self._blocks: dict[Optional[str], list["BasicBlock"]] = {}
        self._starts: dict[Optional[str], list[int]] = {}
        for f, blocks in by_file.items():
            blocks.sort(key=lambda b: b.first_line)
            self._blocks[f] = blocks
            self._starts[f] = [b.first_line for b in blocks]

    def line(self, file: Optional[str], name: str) -> Optional[int]:
        """The label's source line (FIRST definition), or ``None``. A ``None``
        file matches the label in any file (duck-typed blocks only)."""
        name = name.strip()
        if file is None:
            return self._lines_any.get(name)
        return self._lines.get((file, name))

    def block(self, file: Optional[str], name: str) -> Optional["BasicBlock"]:
        """The block a branch to ``name`` lands on: the first block in ``file``
        starting at or after the label's line. ``None`` for an unknown label
        or one at EOF (control runs off the end there — see
        :attr:`SSAProgram.off_end_exits`)."""
        ln = self.line(file, name)
        if ln is None:
            return None
        key = file if file in self._blocks else None
        starts = self._starts.get(key, ())
        i = bisect.bisect_left(starts, ln)
        return self._blocks[key][i] if i < len(starts) else None
