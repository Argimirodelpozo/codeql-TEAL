"""sec-guide/unsafe-lsig-args: arg* opcode used in equality comparison.

Mirrors ``unsafeLsigArgs.ql``. LogicSig arguments aren't covered by
delegation signatures and can be changed per-transaction by the caller,
so using them as equality keys for access control provides no security.
Per-arg-read finding when its SSAVar is consumed by an ``==``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import Assignment, SSAProgram, SSAVar
from . import common


_ARG_OPS = frozenset({"arg", "arg_0", "arg_1", "arg_2", "arg_3", "args"})


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
    name = "sec-guide/unsafe-lsig-args"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[UnsafeLsigArgsViolation]:
        out: list[UnsafeLsigArgsViolation] = []
        seen: set[tuple[int, int]] = set()
        for arg_op in self.prog.assignments:
            if not common._file_match(arg_op.location.file, self.file):
                continue
            if arg_op.op not in _ARG_OPS:
                continue
            for out_var in arg_op.outputs:
                if not isinstance(out_var, SSAVar):
                    continue
                for cons in out_var.uses:
                    if cons.op != "==":
                        continue
                    key = (id(arg_op), id(cons))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.append(UnsafeLsigArgsViolation(
                        arg_op=arg_op, cmp_op=cons,
                    ))
        return out
