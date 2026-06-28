"""sec-guide/arbitrary-inner-appcall: attacker-controlled inner-app-call target.

A user-input-tainted value reaching an inner transaction's ``ApplicationID`` —
the application this contract *calls* — with no dominating check of that value or
of ``txn Sender``. The contract becomes a **confused deputy**: whatever authority
it holds (its own balance, its assets, its admin rights over other apps) is wielded
on behalf of an attacker who simply names the app to call.

Unlike a redirected payment (covered by :mod:`tainted_fund_flow`, which owns the
``Receiver`` / ``Amount`` family), an arbitrary call target is rarely a legitimate
pattern — a contract that genuinely proxies to "any app the user names" still pins
the set of allowed callees, or gates the call on the sender. So the bar to flag is
the same shape as tainted-fund-flow but the field is the call *target*:

  itxn_begin
  int appl;                  itxn_field TypeEnum
  txna ApplicationArgs 1; btoi; itxn_field ApplicationID   <-- attacker picks callee
  itxn_submit

Reuses the shared taint + guard machinery (:func:`common.user_input_taint`,
:func:`common.itxn_value_guarded`): a guard is either a check of the same input
slot (``ApplicationArgs[1] == <pinned> ; assert``) or a ``txn Sender`` gate. The
taint is interprocedural via the frame-flow bridge, so a callee that is fed the
target through a proto parameter is covered too.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common
from tealtools.path_predicates import PathPredicateAnalysis
from tealtools.ssa import SSAProgram

# The inner-txn fields that select WHICH application the call dispatches to.
# ApplicationID is the appl-call target; the foreign-app array (Applications)
# can also feed an attacker-named callee, but ApplicationID is the precise,
# unambiguous "this is the app we call" field, so we key on it alone to keep
# precision high.
_TARGET_FIELDS = frozenset({"ApplicationID"})


@dataclass
class ArbitraryInnerAppcallViolation:
    prog: SSAProgram
    field: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "sources": list(self.sources),
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"ArbitraryInnerAppcallViolation({self.message})"


class ArbitraryInnerAppcallDetector:
    name: ClassVar[str] = "sec-guide/arbitrary-inner-appcall"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn_* is app-only
    violation_cls: ClassVar[type] = ArbitraryInnerAppcallViolation
    # Superseded by ir-arbitrary-inner-appcall (IR layer: across-callsub dominance,
    # validation-sub guards, typed, cross-contract), which falls back to this one
    # when the lift fails. Kept registered (benchmark + fallback + by-name use);
    # skipped in default scans. See scan._drop_superseded.
    superseded_by: ClassVar[str] = "ir-arbitrary-inner-appcall"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        if getattr(prog, "_materialized", False):
            raise ValueError(
                "ArbitraryInnerAppcallDetector requires the pre-materialized SSA "
                "(path predicates + def-use traversal)."
            )
        if getattr(prog, "_dead_eliminated", False):
            raise ValueError(
                "ArbitraryInnerAppcallDetector requires the pre-dead-elimination SSA."
            )
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        taint = common.user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = common.sender_creator_vars(self.prog, file=self.file)
        violations: list = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field not in _TARGET_FIELDS:
                continue
            sink_slots = taint.get(fs.value, frozenset())
            if not sink_slots:
                continue                              # target not attacker-controlled
            if common.itxn_value_guarded(
                self.prog, self.pp, fs.assignment, sink_slots, taint, sender_vars):
                continue
            sources = tuple(sorted({lbl for lbl, _ in sink_slots}))
            loc = common.loc(fs.assignment)
            msg = (f"[HIGH] attacker-controlled inner-app-call target "
                   f"itxn {fs.field} <- {'+'.join(sources)} ({loc}); the contract "
                   f"will call any application the attacker names — no dominating "
                   f"check of the target or txn Sender")
            violations.append(ArbitraryInnerAppcallViolation(
                self.prog, fs.field, "HIGH", sources, loc, msg))
        return violations
