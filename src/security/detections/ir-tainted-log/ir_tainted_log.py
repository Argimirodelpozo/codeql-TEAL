"""sec-guide/ir-tainted-log: attacker-controlled data emitted via log (IR).

A contract that ``log``s a user-input-tainted value emits FORGED data to anything
that trusts its logs: a CALLER reading its ``LastLog`` after an inner appcall --
which is itself a taint source (``ItxnLastLog``); a spoofed ARC-4 return value or
event can make the caller act on attacker-chosen data -- and off-chain indexers /
dapps that treat the contract's logged events as truth. Output-integrity rather
than direct fund loss, so LOW severity -- but it is the on-chain SOURCE of the
cross-contract ``ItxnLastLog`` taint the caller-side detectors react to. A new
capability (no SSA sibling); lift-only.
"""
from __future__ import annotations

from security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrTaintedLogViolation(_IrTaintSinkViolation):
    pass


class IrTaintedLogDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-log"
    violation_cls = IrTaintedLogViolation

    def _raw_findings(self, lifter):
        from tealtools.lift import fund_flow as FF
        return FF.tainted_logs(lifter, trusted_args=self.trusted_args)

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled data emitted via log <- {src} "
                f"({location}, {f.sub_id}); a caller reading this contract's LastLog "
                f"(or an off-chain indexer) can be fed forged data — no dominating "
                f"check of the value (IR interprocedural)")
