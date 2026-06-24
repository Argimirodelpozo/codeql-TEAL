"""sec-guide/hardcoded-min-balance: balance op subtracted from a hardcoded const.

Flags a ``balance`` value flowing into a ``-`` (sub) op where the other operand
resolves to a known integer constant — and the program never uses ``min_balance``.
The hardcoded assumption breaks when the contract opts into assets, creates boxes,
or adds local state.

The ``balance`` value is followed into the subtraction through the
phi / scratch / proto-frame bridge (:func:`common._operand_flows_from_field_var`),
not just as a direct operand — so the common ``balance; store N; … load N; int K;
-`` shape (the balance stashed in scratch before the subtract) is caught rather
than missed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import Assignment, SSAProgram, SSAVar, const_int, is_field_var
from security import common


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


class HardcodedMinBalanceDetector:
    name = "sec-guide/hardcoded-min-balance"
    applies_to = frozenset({"app"})  # min_balance is an app idiom

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        # Constant propagation needed to recognise the hardcoded operand
        # (``intc_*`` / ``int N`` / ``pushint N``).
        prog.propagate_constants()
        self.prog = prog
        self.file = file

    def detect(self) -> list[HardcodedMinBalanceViolation]:
        # Skip silently when the program already uses min_balance — treat
        # that as evidence the developer is aware of the right primitive.
        if any(
            a.op == "min_balance" for a in self.prog.assignments
            if common.file_match(a.location.file, self.file)
        ):
            return []
        # Seed set = every `balance` (and `min_balance`-absent) read output; the
        # flow bridge follows it through scratch / phi / proto-frame into the sub.
        bal_ops = [
            a for a in self.prog.assignments
            if a.op == "balance" and common.file_match(a.location.file, self.file)
        ]
        bal_seeds = {o for a in bal_ops for o in a.outputs if isinstance(o, SSAVar)}
        if not bal_seeds:
            return []
        a_bal_op = bal_ops[0]                  # representative, for the finding
        out: list[HardcodedMinBalanceViolation] = []
        for sub in self.prog.assignments:
            if not common.file_match(sub.location.file, self.file):
                continue
            if sub.op != "-" or len(sub.inputs) != 2:
                continue
            # One operand must flow from a balance read; the other a known int const.
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
