"""sec-guide/ir-tainted-freeze: a user-input-tainted ``FreezeAssetAccount`` on an
inner ``afrz`` lets the attacker freeze ANY account they name — a targeted DoS on
a victim's holdings, and with a tainted ``FreezeAsset``, of any asset the app can
freeze. Lift-only; no SSA sibling.
"""
from __future__ import annotations

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrTaintedFreezeViolation(_IrTaintSinkViolation):
    pass


class IrTaintedFreezeDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-freeze"
    violation_cls = IrTaintedFreezeViolation
    fields = {"FreezeAssetAccount": "HIGH", "FreezeAsset": "MEDIUM"}

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        what = ("freeze any account it names" if f.field == "FreezeAssetAccount"
                else "target any asset it can freeze")
        return (f"[{f.severity}] attacker-controlled asset-freeze target itxn "
                f"{f.field} <- {src} ({location}, {f.sub_id}); the contract will "
                f"{what} — no dominating check of the value or txn Sender "
                f"(IR interprocedural)")
