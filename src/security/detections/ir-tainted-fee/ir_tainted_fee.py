"""sec-guide/ir-tainted-fee: attacker-controlled inner-transaction fee (IR).

A user-input-tainted ``itxn_field Fee`` lets the attacker choose the fee the app
pays on an inner transaction -- set it large and drain the app's algo balance one
inflated inner txn at a time (a griefing / fund-leak vector). Distinct from the
``inner-txn-fee`` detector, which flags a CONSTANT non-zero fee and explicitly
skips dynamic ones; this covers exactly that skipped attacker-controlled case.

A new capability (no SSA sibling) on the generalized IR taint-to-sink engine
(:func:`common.ir_unguarded_itxn_flows` over ``Fee``), inheriting across-``callsub``
guard dominance, validation-sub guards, typed reasoning, and cross-contract
caller-pin suppression. Lift-only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

_FIELDS = {"Fee": "MEDIUM"}


@dataclass
class IrTaintedFeeViolation:
    field: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {"field": self.field, "severity": self.severity,
                "sources": list(self.sources), "location": self.location,
                "message": self.message}

    def __repr__(self) -> str:
        return f"IrTaintedFeeViolation({self.message})"


class IrTaintedFeeDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-fee"
    applies_to: ClassVar[frozenset] = frozenset({"app"})
    violation_cls: ClassVar[type] = IrTaintedFeeViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates

    def detect(self) -> list:
        lifted, findings = common.ir_unguarded_itxn_flows(
            self.prog, self.file, _FIELDS, self.trusted_args)
        if not lifted:
            return []
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            message = (
                f"[{f.severity}] attacker-controlled inner-txn fee itxn {f.field} "
                f"<- {'+'.join(sources)} ({location}, {f.sub_id}); the attacker sets "
                f"the fee the app pays and can drain its balance via inflated fees — "
                f"no dominating check of the value (IR interprocedural)")
            out.append(IrTaintedFeeViolation(
                f.field, f.severity, sources, location, message))
        return out
