"""sec-guide/unvalidated-group-sibling: trusting a sibling transfer it never checks.

The single most Algorand-native composition bug. A stateful app routinely relies
on a *sibling* transaction in the same atomic group — "transaction 0 is a payment
of N microAlgo to me" — and reads its value (``gtxn 0 Amount`` / ``gtxn 1
AssetAmount``). The bug is reading that value WITHOUT pinning the sibling's
receiver to this application:

    gtxn 0 Amount            // trust an incoming payment of this size ...
    // ... credit the caller, mint shares, release collateral ...

If the contract never asserts ``gtxn 0 Receiver == Global.CurrentApplicationAddress``,
the attacker submits a group whose transaction 0 pays *someone else* (or themselves)
— the app credits them for funds it never received. ``group-size-check`` only
validates the COUNT of transactions; this validates that a sibling the app draws
VALUE from actually pays the app.

Detection (group reads at a STATICALLY KNOWN sibling index — immediate-index
``gtxn``/``gtxna``/``gtxnas`` plus ``gtxns`` with a const-resolved index, e.g.
``int 0; gtxns Amount``; a genuinely dynamic ``gtxns`` index is skipped soundly):
for each sibling index that the program reads a value field from
(``Amount`` → a payment, ``AssetAmount`` → an asset transfer), require a matching
receiver pin — an equality comparing that sibling's ``Receiver`` / ``AssetReceiver``
against ``global CurrentApplicationAddress`` whose result reaches enforcement
(``assert`` / branch-to-reject). Missing pin → finding. The flow check is the
shared phi/scratch/proto-frame-aware :func:`common._operand_flows_from_field_var`,
so a pin living behind a sub or a scratch slot still counts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common
from tealtools.ssa import SSAProgram, SSAVar, const_int

# Value field -> the receiver field that must be pinned for that transfer kind.
_VALUE_TO_RECEIVER = {
    "Amount": "Receiver",            # payment
    "AssetAmount": "AssetReceiver",  # asset transfer
}


@dataclass
class UnvalidatedGroupSiblingViolation:
    prog: SSAProgram
    index: int = 0
    value_field: str = ""
    receiver_field: str = ""
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "value_field": self.value_field,
            "receiver_field": self.receiver_field,
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"UnvalidatedGroupSiblingViolation({self.message})"


class UnvalidatedGroupSiblingDetector:
    name: ClassVar[str] = "sec-guide/unvalidated-group-sibling"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # gtxn-relying apps
    violation_cls: ClassVar[type] = UnvalidatedGroupSiblingViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list:
        reads = self._gtxn_index_reads()                 # (index, field) -> [assigns]
        app_seeds = self._global_seeds("CurrentApplicationAddress")
        out: list = []
        for (index, field), assigns in sorted(reads.items()):
            if field not in _VALUE_TO_RECEIVER:
                continue
            recv_field = _VALUE_TO_RECEIVER[field]
            if self._receiver_pinned(index, recv_field, reads, app_seeds):
                continue
            a = assigns[0]
            loc = common.loc(a)
            msg = (f"[HIGH] reads gtxn {index} {field} ({loc}) but never pins "
                   f"gtxn {index} {recv_field} == Global.CurrentApplicationAddress "
                   f"— the app trusts a sibling transfer that may not pay it")
            out.append(UnvalidatedGroupSiblingViolation(
                self.prog, index, field, recv_field, loc, msg))
        return out

    # -- internals ------------------------------------------------------

    def _gtxn_index_reads(self) -> dict:
        """``(index, field) -> [assignments]`` for every group read with a
        STATICALLY KNOWN sibling index:

        * the immediate-index opcodes ``gtxn`` / ``gtxna`` / ``gtxnas`` (index in
          the first immediate), and
        * the stack-index ``gtxns`` when its popped index operand is a
          compile-time constant — e.g. ``int 0; gtxns Amount``, the usual
          compiler output for ``gtxn.PaymentTxn(0)``.

        A genuinely DYNAMIC ``gtxns`` index (one not const-resolvable) is still
        skipped: the sibling it reads isn't statically known, so there is no fixed
        index to demand a receiver pin for."""
        out: dict = {}
        for a in self.prog.assignments:
            if not common.file_match(a.location.file, self.file):
                continue
            if a.op in ("gtxn", "gtxna", "gtxnas"):
                toks = a.immediates.split()
                if len(toks) < 2 or not toks[0].lstrip("-").isdigit():
                    continue
                out.setdefault((int(toks[0]), toks[1]), []).append(a)
            elif a.op == "gtxns":
                # field is the only immediate; the sibling index is the popped
                # stack operand, usable only when it is a compile-time constant.
                toks = a.immediates.split()
                if not toks or not a.inputs:
                    continue
                idx = const_int(a.inputs[0])
                if idx is None:
                    continue
                out.setdefault((idx, toks[0]), []).append(a)
        return out

    def _global_seeds(self, gfield: str) -> set:
        return common.ssavar_outputs(
            common.global_field_reads(self.prog, gfield, file=self.file)
        )

    def _receiver_pinned(self, index: int, recv_field: str, reads: dict,
                         app_seeds: set) -> bool:
        """True if some ``gtxn <index> <recv_field>`` value is compared for
        equality against ``Global.CurrentApplicationAddress`` and that comparison
        reaches enforcement."""
        recv_assigns = reads.get((index, recv_field), [])
        recv_seeds = {o for a in recv_assigns for o in a.outputs
                      if isinstance(o, SSAVar)}
        if not recv_seeds or not app_seeds:
            return False
        for cmp in self.prog.assignments:
            if cmp.op != "==" or len(cmp.inputs) != 2:
                continue
            if not common.file_match(cmp.location.file, self.file):
                continue
            x, y = cmp.inputs
            tied = (
                (common._operand_flows_from_field_var(self.prog, x, recv_seeds)
                 and common._operand_flows_from_field_var(self.prog, y, app_seeds))
                or
                (common._operand_flows_from_field_var(self.prog, y, recv_seeds)
                 and common._operand_flows_from_field_var(self.prog, x, app_seeds))
            )
            if not tied:
                continue
            if cmp.outputs and isinstance(cmp.outputs[0], SSAVar) and \
                    common.def_forward_reaches_enforcement(self.prog, cmp.outputs[0]):
                return True
        return False
