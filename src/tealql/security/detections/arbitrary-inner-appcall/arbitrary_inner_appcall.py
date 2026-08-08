"""sec-guide/arbitrary-inner-appcall: a user-input-tainted value reaching an inner
transaction's ``ApplicationID`` — the app this contract CALLS — with no dominating
check of the value or of ``txn Sender``. The contract becomes a confused deputy,
wielding its balance, assets and admin rights for whoever names the callee.

Same shape as tainted-fund-flow but on the call TARGET, and a legitimate proxy
still pins its allowed callees or gates on the sender. A guard is a check of the
same input slot or a ``txn Sender`` gate; the taint is interprocedural, so a
target fed in through a proto parameter is covered.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram

# ApplicationID alone: the foreign-app array can also feed an attacker-named
# callee, but this is the unambiguous "the app we call" field.
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
    # The IR sibling adds across-callsub dominance and falls back to this one on
    # lift failure; kept registered but skipped in default scans.
    superseded_by: ClassVar[str] = "ir-arbitrary-inner-appcall"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        taint = common.user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = common.sender_vars(self.prog, file=self.file)
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
