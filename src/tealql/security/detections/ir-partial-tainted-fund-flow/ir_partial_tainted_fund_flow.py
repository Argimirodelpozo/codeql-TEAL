"""sec-guide/ir-partial-tainted-fund-flow: byte-precise fund-flow on the IR.

The IR-layer successor to ``partial-tainted-fund-flow``. It closes the same
partial-validation blind spot the SSA detector does -- a contract that packs
several logical fields into ONE argument and validates only some of them
(checking ``arg[0..2]`` while an embedded address at ``arg[2..34]`` steers
``Receiver``) leaves the boolean fund-flow detector a false negative, because its
guard reasons at input-SLOT granularity -- but does it on the lifted Puya IR, so
it also gets the IR's across-``callsub`` guard dominance and interprocedural
frame-resolved taint that the SSA detector lacks. The whole fund-flow family now
lives on one layer.

Mechanism: :func:`byte_taint_view` carries the SSA byte-interval taint
(``validate=True`` -- an ``assert(slice == clean)`` guard clears exactly the
bytes it pins) UP onto the IR registers. A register still holding un-validated
attacker bytes drives a synthetic taint map into the IR fund-flow engine with
``sender_only=True``: byte-taint already owns input-validation at byte precision,
so only sender/creator guards suppress (an input-slot guard would reproduce the
very blind spot -- one sub-field's check spuriously guarding another). Reports
only the NET-NEW findings the boolean ``ir-tainted-fund-flow`` misses.
"""
from __future__ import annotations

from tealql.tealtools.avm import PAYMENT_FUND_FIELDS

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation


class IrPartialTaintedFundFlowViolation(_IrTaintSinkViolation):
    pass


class IrPartialTaintedFundFlowDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-partial-tainted-fund-flow"
    violation_cls = IrPartialTaintedFundFlowViolation
    fields = PAYMENT_FUND_FIELDS               # destination/amount fields (no close/rekey)
    fallback = "partial-tainted-fund-flow"     # SSA sibling when the contract doesn't lift

    def _taint_view(self, lifter):
        # The road witness uses the SAME byte-precise view the findings do.
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        return byte_taint_view(lifter)

    def _byte_taint_map(self, lifter) -> dict:
        """Synthetic boolean taint for the guard engine: a register is tainted iff
        the carried-up byte-taint (validate=True) leaves it with UN-validated
        attacker bytes -- checked byte ranges are already cleared, so only
        genuinely-unchecked bytes remain."""
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        view = byte_taint_view(lifter)         # validate=True by default
        taint: dict = {}
        for reg in lifter.regs.values():
            if view.tainted_bytes(reg) or view.is_scalar_tainted(reg):
                taint[id(reg)] = {"attacker-bytes"}
        return taint

    def _raw_findings(self, lifter) -> list:
        from tealql.tealtools.lift import fund_flow as FF
        return FF.tainted_itxn_flows(
            lifter, self.fields, taint=self._byte_taint_map(lifter),
            trusted_args=self.trusted_args, sender_only=True,
        )

    def _suppress(self, lifter, findings) -> list:
        # Net-new only: the boolean ir-tainted-fund-flow owns the whole-value
        # cases; surface exactly the partial-validation class it cannot see.
        from tealql.tealtools.lift import fund_flow as FF
        owned = {
            (f.field, f.line) for f in FF.tainted_fund_flows(lifter, trusted_args=self.trusted_args)
            if not f.guarded and not f.param_derived
        }
        return [f for f in findings if (f.field, f.line) not in owned]

    def _message(self, f, location: str) -> str:
        return (f"[{f.severity}] partially-validated attacker bytes reach itxn "
                f"{f.field} ({location}, {f.sub_id}); the argument is validated "
                f"elsewhere but not on the bytes that steer the funds "
                f"(IR byte-precise, interprocedural)")
