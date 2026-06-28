"""sec-guide/ir-arbitrary-inner-appcall: attacker-controlled inner-appcall target (IR).

The IR-layer sibling of :mod:`arbitrary_inner_appcall`: a user-input-tainted value
reaching an inner transaction's ``ApplicationID`` lets the attacker pick WHICH
application the contract calls (and thus what it does with the app's state /
holdings). Same taint-to-sink shape as :mod:`ir_tainted_fund_flow`, run on the
``ApplicationID`` field via :func:`common.ir_unguarded_itxn_flows`, so it inherits
the IR layer's edges the SSA detector can't reach: across-``callsub`` guard
dominance (a sender/target check before a callsub on the path to the sink),
validation-subroutine guards, typed reasoning, and cross-contract caller-pinned
suppression (``trusted_args``).

Primary over the SSA ``arbitrary-inner-appcall``, which it ``supersede``s -- and
falls back to when the lift fails -- so it is the single complete entry point.
Emits only the UNGUARDED, call-resolved flows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

# The inner-txn field that selects WHICH application the call dispatches to.
_FIELDS = {"ApplicationID": "HIGH"}


@dataclass
class IrArbitraryInnerAppcallViolation:
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
        return f"IrArbitraryInnerAppcallViolation({self.message})"


class IrArbitraryInnerAppcallDetector:
    name: ClassVar[str] = "sec-guide/ir-arbitrary-inner-appcall"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # inner txns are app-only
    violation_cls: ClassVar[type] = IrArbitraryInnerAppcallViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates           # for the SSA fallback

    def detect(self) -> list:
        lifted, findings = common.ir_unguarded_itxn_flows(
            self.prog, self.file, _FIELDS, self.trusted_args)
        if not lifted:
            from security import DETECTORS                # lift failed -> SSA fallback
            return DETECTORS["arbitrary-inner-appcall"](
                self.prog, file=self.file, path_predicates=self.path_predicates,
            ).detect()
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            message = (
                f"[{f.severity}] attacker-controlled inner-app-call target itxn "
                f"{f.field} <- {'+'.join(sources)} ({location}, {f.sub_id}); the "
                f"contract will call any application the attacker names — no "
                f"dominating check of the target or txn Sender (IR interprocedural)")
            out.append(IrArbitraryInnerAppcallViolation(
                f.field, f.severity, sources, location, message))
        return out
