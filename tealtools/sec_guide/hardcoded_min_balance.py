"""sec-guide/hardcoded-min-balance: balance op subtracted from a hardcoded const.

Mirrors ``hardcodedMinBalance.ql``. Flags ``balance`` outputs flowing
into a ``-`` (sub) op where the other operand resolves to a known
integer constant — and the program never uses ``min_balance``. The
hardcoded assumption breaks when the contract opts into assets, creates
boxes, or adds local state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..ssa import Assignment, Const, SSAProgram, SSAVar
from . import common


@dataclass
class HardcodedMinBalanceViolation:
    sub_op: Assignment
    balance_op: Assignment

    def pretty(self) -> str:
        return (
            f"-@{common.loc(self.sub_op)}  "
            "Balance minus hardcoded constant — use the min_balance opcode "
            "instead to dynamically account for boxes, opt-ins, and local state."
        )

    def __repr__(self) -> str:
        return f"HardcodedMinBalanceViolation({self.pretty()})"


def _operand_const_int(operand) -> Const | None:
    if isinstance(operand, Const):
        return operand if operand.kind == "int" else None
    cv = getattr(operand, "const_value", None)
    if isinstance(cv, Const) and cv.kind == "int":
        return cv
    return None


class HardcodedMinBalanceDetector:
    name = "sec-guide/hardcoded-min-balance"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        # Constant propagation needed to recognise the hardcoded operand
        # (``intc_*`` / ``int N`` / ``pushint N``).
        prog.propagate_constants()
        self.prog = prog
        self.file = file

    def detect(self) -> list[HardcodedMinBalanceViolation]:
        # Skip silently when the program already uses min_balance — the
        # QL form treats that as evidence the developer is aware of the
        # right primitive.
        if any(
            a.op == "min_balance" for a in self.prog.assignments
            if common._file_match(a.location.file, self.file)
        ):
            return []
        out: list[HardcodedMinBalanceViolation] = []
        for sub in self.prog.assignments:
            if not common._file_match(sub.location.file, self.file):
                continue
            if sub.op != "-" or len(sub.inputs) != 2:
                continue
            a0, a1 = sub.inputs
            # One operand must be a balance read; the other a known int const.
            for bal_idx, const_idx in ((0, 1), (1, 0)):
                bal = sub.inputs[bal_idx]
                cnst = sub.inputs[const_idx]
                if not isinstance(bal, SSAVar) or bal.defined_by is None:
                    continue
                if bal.defined_by.op != "balance":
                    continue
                if _operand_const_int(cnst) is None:
                    continue
                out.append(HardcodedMinBalanceViolation(
                    sub_op=sub, balance_op=bal.defined_by,
                ))
                break
        return out
