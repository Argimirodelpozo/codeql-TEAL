"""sec-guide/unsafe-lsig-args: arg* opcode used as an equality key.

LogicSig arguments aren't covered by delegation signatures and can be changed
per-transaction by the caller, so using them as equality keys for access control
provides no security.

The value-flow is followed over the **interprocedural taint graph**
(:class:`tealtools.dataflow.taint_graph.TaintGraph`) rather than the arg read's
direct ``==`` uses: the graph carries def-use, phi, scratch (store/load) AND
proto-frame edges, so an arg that is stashed in scratch, threaded through one or
more subroutines, and/or hashed (``sha256``) before the comparison is still
caught. The old direct-use scan saw only ``arg; …; ==`` in one basic block and
silently missed every cross-sub / cross-scratch / hash-then-compare guard (the
exact shapes a real LogicSig uses) — a false negative per missed flow.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import Assignment, SSAProgram
from tealtools.dataflow.taint_graph import TaintGraph
from security import common


_ARG_OPS = frozenset({"arg", "arg_0", "arg_1", "arg_2", "arg_3", "args"})
_EQ_OPS = frozenset({"==", "b=="})


@dataclass
class UnsafeLsigArgsViolation:
    arg_op: Assignment
    cmp_op: Assignment

    def pretty(self) -> str:
        return (
            f"{self.arg_op.op}@{common.loc(self.arg_op)}  "
            "LogicSig argument used in equality comparison — args are not covered "
            "by delegation signatures and provide zero security for access control."
        )

    def __repr__(self) -> str:
        return f"UnsafeLsigArgsViolation({self.pretty()})"


class UnsafeLsigArgsDetector:
    severity = "high"
    name = "sec-guide/unsafe-lsig-args"
    applies_to = frozenset({"logicsig"})  # arg* opcodes are logicsig-only

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def _assignment_at(self, node) -> Optional[Assignment]:
        """The ``Assignment`` an op-graph taint node stands for, matched by
        ``(file, line)`` — the node identity the TaintGraph exposes."""
        for a in self.prog.assignments:
            if a.location.file == node.file and a.location.line == node.line:
                return a
        return None

    def detect(self) -> list[UnsafeLsigArgsViolation]:
        tg = TaintGraph.of(self.prog)
        cmp_set = {
            n for n in tg.nodes()
            if tg.op_of(n) in _EQ_OPS and common.file_match(n.file, self.file)
        }
        if not cmp_set:
            return []
        out: list[UnsafeLsigArgsViolation] = []
        seen_args: set[tuple[str, int]] = set()
        for n in sorted(tg.nodes(), key=lambda x: (x.file, x.line)):
            if tg.op_of(n) not in _ARG_OPS or not common.file_match(n.file, self.file):
                continue
            key = (n.file, n.line)
            if key in seen_args:
                continue
            # First equality comparison this arg's value reaches (through any
            # mix of scratch / subroutine / value-op edges the graph models).
            reached = tg.reachable_from(n) & cmp_set
            if not reached:
                continue
            seen_args.add(key)
            cmp_node = min(reached, key=lambda x: (x.file, x.line))
            arg_a = self._assignment_at(n)
            cmp_a = self._assignment_at(cmp_node)
            if arg_a is not None and cmp_a is not None:
                out.append(UnsafeLsigArgsViolation(arg_op=arg_a, cmp_op=cmp_a))
        return out
