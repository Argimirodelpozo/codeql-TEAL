"""sec-guide/ir-tainted-freeze: attacker-controlled inner asset-freeze target (IR).

An inner asset-freeze (``afrz``) transaction freezes a specific holder's units of
an ASA. A user-input-tainted ``FreezeAssetAccount`` lets the attacker freeze ANY
account they name -- a targeted denial-of-service on a victim's holdings (and, with
a tainted ``FreezeAsset``, of any asset the app can freeze). Only meaningful when
the app is the asset's freeze address, but when it is, the value should be fixed or
checked, never attacker-chosen.

A new capability (no SSA sibling) on the generalized IR taint-to-sink engine
(:func:`common.ir_unguarded_itxn_flows` over the freeze fields), inheriting
across-``callsub`` guard dominance, validation-sub guards, typed reasoning, and
cross-contract caller-pin suppression. Lift-only.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

_FIELDS = {"FreezeAssetAccount": "HIGH", "FreezeAsset": "MEDIUM"}


@dataclass
class IrTaintedFreezeViolation:
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
        return f"IrTaintedFreezeViolation({self.message})"


class IrTaintedFreezeDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-freeze"
    applies_to: ClassVar[frozenset] = frozenset({"app"})
    violation_cls: ClassVar[type] = IrTaintedFreezeViolation

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
            what = ("freeze any account it names" if f.field == "FreezeAssetAccount"
                    else "target any asset it can freeze")
            message = (
                f"[{f.severity}] attacker-controlled asset-freeze target itxn "
                f"{f.field} <- {'+'.join(sources)} ({location}, {f.sub_id}); the "
                f"contract will {what} — no dominating check of the value or txn "
                f"Sender (IR interprocedural)")
            out.append(IrTaintedFreezeViolation(
                f.field, f.severity, sources, location, message))
        return out
