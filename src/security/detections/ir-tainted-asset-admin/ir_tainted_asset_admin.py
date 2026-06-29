"""sec-guide/ir-tainted-asset-admin: attacker-controlled asset ADMIN role (IR).

An inner asset-config (``acfg``) transaction sets the ASA's privileged roles. A
user-input-tainted value reaching ``ConfigAssetManager`` (reconfigure / destroy),
``ConfigAssetClawback`` (claw back ANYONE's holdings), ``ConfigAssetFreeze``
(freeze any holder), or ``ConfigAssetReserve`` lets the attacker install THEMSELVES
as that role -- e.g. set clawback to their own address and then claw the asset out
of every holder. A new capability (no SSA sibling); lift-only.
"""
from __future__ import annotations

from security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation

_ROLE = {
    "ConfigAssetManager": "reconfigure or destroy the asset",
    "ConfigAssetClawback": "claw back any holder's units",
    "ConfigAssetFreeze": "freeze any holder",
    "ConfigAssetReserve": "control the reserve",
}


class IrTaintedAssetAdminViolation(_IrTaintSinkViolation):
    pass


class IrTaintedAssetAdminDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-asset-admin"
    violation_cls = IrTaintedAssetAdminViolation
    fields = {
        "ConfigAssetManager": "CRITICAL", "ConfigAssetClawback": "CRITICAL",
        "ConfigAssetFreeze": "HIGH", "ConfigAssetReserve": "MEDIUM",
    }

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        role = _ROLE.get(f.field, "administer the asset")
        return (f"[{f.severity}] attacker-controlled asset-admin role itxn "
                f"{f.field} <- {src} ({location}, {f.sub_id}); the attacker can "
                f"install themselves as the address that can {role} — no dominating "
                f"check of the value or txn Sender (IR interprocedural)")
