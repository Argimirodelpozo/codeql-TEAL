"""sec-guide/ir-tainted-asset-admin: attacker-controlled asset ADMIN role (IR).

An inner asset-config (``acfg``) transaction sets the ASA's privileged roles --
``ConfigAssetManager`` (reconfigure / destroy the asset), ``ConfigAssetClawback``
(claw back ANYONE's holdings), ``ConfigAssetFreeze`` (freeze any holder),
``ConfigAssetReserve``. A user-input-tainted value reaching one of these lets the
attacker install THEMSELVES as that role -- e.g. set the clawback address to their
own and then claw the asset out of every holder. A new capability with no SSA-layer
sibling, built directly on the generalized IR taint-to-sink engine
(:func:`common.ir_unguarded_itxn_flows`), so it gets the IR layer's across-
``callsub`` guard dominance, validation-subroutine guards, typed reasoning, and
cross-contract caller-pin suppression for free.

Lift-only (no SSA fallback): returns nothing on the rare contract that doesn't
lift. Emits only the UNGUARDED, call-resolved flows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

# acfg admin-role fields, by blast radius if an attacker controls them.
_FIELDS = {
    "ConfigAssetManager": "CRITICAL",    # reconfigure / destroy the asset
    "ConfigAssetClawback": "CRITICAL",   # claw back anyone's holdings
    "ConfigAssetFreeze": "HIGH",         # freeze any holder
    "ConfigAssetReserve": "MEDIUM",
}


@dataclass
class IrTaintedAssetAdminViolation:
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
        return f"IrTaintedAssetAdminViolation({self.message})"


class IrTaintedAssetAdminDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-asset-admin"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn_* is app-only
    violation_cls: ClassVar[type] = IrTaintedAssetAdminViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates           # (unused; no SSA sibling)

    def detect(self) -> list:
        lifted, findings = common.ir_unguarded_itxn_flows(
            self.prog, self.file, _FIELDS, self.trusted_args)
        if not lifted:                                   # didn't lift; no SSA sibling
            return []
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        _ROLE = {
            "ConfigAssetManager": "reconfigure or destroy the asset",
            "ConfigAssetClawback": "claw back any holder's units",
            "ConfigAssetFreeze": "freeze any holder",
            "ConfigAssetReserve": "control the reserve",
        }
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            role = _ROLE.get(f.field, "administer the asset")
            message = (
                f"[{f.severity}] attacker-controlled asset-admin role itxn "
                f"{f.field} <- {'+'.join(sources)} ({location}, {f.sub_id}); the "
                f"attacker can install themselves as the address that can {role} — "
                f"no dominating check of the value or txn Sender (IR interprocedural)")
            out.append(IrTaintedAssetAdminViolation(
                f.field, f.severity, sources, location, message))
        return out
