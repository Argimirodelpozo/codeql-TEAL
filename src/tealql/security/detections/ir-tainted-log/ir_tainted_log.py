"""sec-guide/ir-tainted-log: a contract that ``log``s a user-input-tainted value
emits FORGED data to anything trusting its logs — a caller reading its ``LastLog``
after an inner appcall, or an off-chain indexer treating its events as truth.

Output-integrity rather than direct fund loss, hence LOW, but it is the on-chain
SOURCE of the cross-contract ``ItxnLastLog`` taint the caller-side detectors react
to. Lift-only; no SSA sibling.
"""
from __future__ import annotations

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrTaintedLogViolation(_IrTaintSinkViolation):
    pass


class IrTaintedLogDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-tainted-log"
    violation_cls = IrTaintedLogViolation

    def _raw_findings(self, lifter):
        from tealql.tealtools.lift import fund_flow as FF
        return FF.tainted_logs(lifter, trusted_args=self.trusted_args)

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled data emitted via log <- {src} "
                f"({location}, {f.sub_id}); a caller reading this contract's LastLog "
                f"(or an off-chain indexer) can be fed forged data — no dominating "
                f"check of the value (IR interprocedural)")
