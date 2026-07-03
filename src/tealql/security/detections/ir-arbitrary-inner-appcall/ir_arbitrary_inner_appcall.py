"""sec-guide/ir-arbitrary-inner-appcall: attacker-controlled inner-appcall target (IR).

A user-input-tainted value reaching an inner transaction's ``ApplicationID`` lets
the attacker pick WHICH application the contract calls. Same taint-to-sink shape as
:mod:`ir_tainted_fund_flow` on the ``ApplicationID`` field, so it inherits the IR
layer's across-``callsub`` guard dominance, validation-subroutine guards, typed
reasoning, and cross-contract caller-pinned suppression. Supersedes the SSA
``arbitrary-inner-appcall`` and falls back to it on lift failure.
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
