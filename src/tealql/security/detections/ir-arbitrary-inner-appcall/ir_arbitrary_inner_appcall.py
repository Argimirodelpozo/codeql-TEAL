"""sec-guide/ir-arbitrary-inner-appcall: a user-input-tainted inner-txn
``ApplicationID`` lets the attacker pick WHICH application the contract calls.
The IR-layer sibling of ``arbitrary-inner-appcall``, falling back to it on lift
failure.
"""
from __future__ import annotations

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrArbitraryInnerAppcallViolation(_IrTaintSinkViolation):
    pass


class IrArbitraryInnerAppcallDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-arbitrary-inner-appcall"
    violation_cls = IrArbitraryInnerAppcallViolation
    fields = {"ApplicationID": "HIGH"}
    fallback = "arbitrary-inner-appcall"

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled inner-app-call target itxn "
                f"{f.field} <- {src} ({location}, {f.sub_id}); the contract will "
                f"call any application the attacker names — no dominating check of "
                f"the target or txn Sender (IR interprocedural)")
