"""sec-guide/unsafe-lsig-args: an ``arg*`` opcode used as an equality key. LogicSig
arguments are not covered by delegation signatures and the caller changes them
per-transaction, so they provide zero access control.

Followed over the interprocedural :class:`TaintGraph`, not the arg read's direct
``==`` uses — the graph carries def-use, phi, scratch and proto-frame edges, so an
arg stashed in scratch, threaded through subroutines and/or hashed before the
comparison is still caught. Those are the shapes real LogicSigs use.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import Assignment, SSAProgram
from tealql.tealtools.dataflow.taint_graph import TaintGraph
from tealql.security._program_shape import file_match, loc


_ARG_OPS = frozenset({"arg", "arg_0", "arg_1", "arg_2", "arg_3", "args"})
_EQ_OPS = frozenset({"==", "b=="})


@dataclass
class UnsafeLsigArgsViolation:
    arg_op: Assignment
    cmp_op: Assignment

    @property
    def file(self) -> str:
        return self.arg_op.location.file

    @property
    def line(self) -> int:
        # Must mirror pretty().
        return self.arg_op.location.line

    def pretty(self) -> str:
        return (
            f"{self.arg_op.op}@{loc(self.arg_op)}  "
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

    def _assignment_index(self) -> dict:
        """``{(file, line): Assignment}`` built once — a scan per graph node is
        quadratic on exactly the big proof-verifier LogicSigs this targets."""
        idx = getattr(self, "_asn_index", None)
        if idx is None:
            idx = {}
            for a in self.prog.assignments:
                idx.setdefault((a.location.file, a.location.line), a)
            self._asn_index = idx
        return idx

    def _assignment_at(self, node) -> Optional[Assignment]:
        """The ``Assignment`` a taint node stands for, matched by ``(file, line)``."""
        return self._assignment_index().get((node.file, node.line))

    def detect(self) -> list[UnsafeLsigArgsViolation]:
        tg = TaintGraph.of(self.prog)
        cmp_set = {
            n for n in tg.nodes()
            if tg.op_of(n) in _EQ_OPS and file_match(n.file, self.file)
        }
        if not cmp_set:
            return []
        out: list[UnsafeLsigArgsViolation] = []
        seen_args: set[tuple[str, int]] = set()
        for n in sorted(tg.nodes(), key=lambda x: (x.file, x.line)):
            if tg.op_of(n) not in _ARG_OPS or not file_match(n.file, self.file):
                continue
            key = (n.file, n.line)
            if key in seen_args:
                continue
            # First equality this arg's value reaches, over any mix of edges.
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
