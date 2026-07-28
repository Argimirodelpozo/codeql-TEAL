"""sec-guide/hardcoded-min-balance: a ``balance`` value subtracted from a known
integer constant in a program that never uses ``min_balance``. The hardcoded
assumption breaks as soon as the contract opts into assets, creates boxes, or adds
local state. The balance is followed through the phi/scratch/proto-frame bridge,
so the ``balance; store N; … load N; int K; -`` shape is caught too.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.tealtools.ssa import Assignment, SSAProgram, const_int, is_field_var
from tealql.security import common


@dataclass
class HardcodedMinBalanceViolation:
    sub_op: Assignment
    balance_op: Assignment

    @property
    def file(self) -> str:
        return self.sub_op.location.file

    @property
    def line(self) -> int:
        # Must mirror pretty().
        return self.sub_op.location.line

    def pretty(self) -> str:
        return (
            f"-@{common.loc(self.sub_op)}  "
            "Balance minus hardcoded constant — use the min_balance opcode "
            "instead to dynamically account for boxes, opt-ins, and local state."
        )

    def __repr__(self) -> str:
        return f"HardcodedMinBalanceViolation({self.pretty()})"


class HardcodedMinBalanceDetector:
    severity = "medium"
    name = "sec-guide/hardcoded-min-balance"
    applies_to = frozenset({"app"})  # min_balance is an app idiom

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        # Const propagation is needed to recognise the hardcoded operand;
        # idempotent, so this is only a fallback for direct library use.
        common.prepare(prog)
        self.prog = prog
        self.file = file

    def detect(self) -> list[HardcodedMinBalanceViolation]:
        # Using min_balance anywhere is evidence the developer knows the right
        # primitive, so say nothing.
        if any(
            a.op == "min_balance" for a in self.prog.assignments
            if common.file_match(a.location.file, self.file)
        ):
            return []
        # Seed set = every `balance` read output; the flow bridge follows it
        # through scratch / phi / proto-frame into the sub.
        bal_ops = [
            a for a in self.prog.assignments
            if a.op == "balance" and common.file_match(a.location.file, self.file)
        ]
        bal_seeds = common.ssavar_outputs(bal_ops)
        if not bal_seeds:
            return []
        a_bal_op = bal_ops[0]                  # representative, for the finding
        out: list[HardcodedMinBalanceViolation] = []
        for sub in self.prog.assignments:
            if not common.file_match(sub.location.file, self.file):
                continue
            if sub.op != "-" or len(sub.inputs) != 2:
                continue
            # One operand must flow from a balance read, the other be a const.
            for bal_idx, const_idx in ((0, 1), (1, 0)):
                bal = sub.inputs[bal_idx]
                cnst = sub.inputs[const_idx]
                if const_int(cnst) is None:
                    continue
                if not (is_field_var(bal, "balance")
                        or common._operand_flows_from_field_var(
                            self.prog, bal, bal_seeds)):
                    continue
                bop = bal.defined_by if is_field_var(bal, "balance") else a_bal_op
                out.append(HardcodedMinBalanceViolation(sub_op=sub, balance_op=bop))
                break
        return out
