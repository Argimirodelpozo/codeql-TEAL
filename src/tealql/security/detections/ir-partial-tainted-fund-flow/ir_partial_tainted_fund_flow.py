"""sec-guide/ir-partial-tainted-fund-flow: the IR-layer successor to
``partial-tainted-fund-flow``, closing the same partial-validation blind spot but
with the IR's across-``callsub`` guard dominance and frame-resolved taint.

``byte_taint_view`` carries the SSA byte-interval taint (``validate=True``) UP
onto the IR registers; registers still holding un-validated attacker bytes drive
a synthetic taint map into the fund-flow engine with ``sender_only=True``, since
byte-taint already owns input-validation at byte precision and an input-slot
guard would reproduce the blind spot. Reports only NET-NEW findings.
"""
from __future__ import annotations

from tealql.tealtools.avm import PAYMENT_FUND_FIELDS

from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation

# Ops reading a specific BYTE POSITION of a buffer, i.e. partial sub-field
# provenance. A scalar with none of them is a WHOLE value belonging to
# ir-tainted-fund-flow's full guard reasoning, not here.
_BYTE_POSITION_OPS = frozenset({
    "getbyte", "extract_uint16", "extract_uint32", "extract_uint64",
    "extract", "extract3", "substring", "substring3",
})


def _ir_byte_extracted(reg, def_of) -> bool:
    """``reg``'s lifted-IR def-tree reads a specific byte position."""
    from tealql.tealtools.lift import fund_flow as FF
    for _r, o in FF._walk(reg, def_of):
        s = FF._intr(o) if o is not None else None
        if s is not None and s.op in _BYTE_POSITION_OPS:
            return True
    return False


class IrPartialTaintedFundFlowViolation(_IrTaintSinkViolation):
    pass


class IrPartialTaintedFundFlowDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-partial-tainted-fund-flow"
    violation_cls = IrPartialTaintedFundFlowViolation
    fields = PAYMENT_FUND_FIELDS               # destination/amount, no close/rekey
    fallback = "partial-tainted-fund-flow"     # SSA sibling when the lift fails

    def _taint_view(self, lifter):
        # The road witness must use the SAME byte-precise view the findings do.
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        return byte_taint_view(lifter)

    def _byte_taint_map(self, lifter) -> dict:
        """Synthetic boolean taint for the guard engine: tainted iff the carried-up
        byte-taint leaves the register with UN-validated attacker bytes."""
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        view = byte_taint_view(lifter)         # validate=True by default
        taint: dict = {}
        # Include frame parameters and representation-level clones, not just
        # direct opcode result registers.  ``byte_taint_view`` bridges those
        # through lifter.register_sources when their SSA provenance is known.
        regs = getattr(lifter, "register_objects", {})
        for reg in regs.values() if regs else lifter.regs.values():
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
        # Net-new only: ir-tainted-fund-flow owns the whole-value cases.
        from tealql.tealtools.lift import fund_flow as FF
        owned = {
            (f.field, f.line) for f in FF.tainted_fund_flows(lifter, trusted_args=self.trusted_args)
            if not f.guarded and not f.param_derived
        }
        findings = [f for f in findings if (f.field, f.line) not in owned]
        # Keep only the byte-granular class. A WHOLE-VALUE scalar has no sub-field
        # blind spot and byte_taint cannot clear its validation, so reporting it
        # under sender_only would surface an already-validated amount as an FP.
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        view = byte_taint_view(lifter)
        def_of = FF._def_map(lifter)
        kept = []
        for f in findings:
            reg = getattr(f, "sink_reg", None)
            # HAZARD: suppress only a COVERED, byte-empty, non-byte-extracted
            # scalar. An UNCOVERED register (the carry-up never reached it) is
            # UNKNOWN — suppressing on uncertainty is a false negative.
            if (reg is not None and view.is_covered(reg)
                    and not view.tainted_bytes(reg)
                    and not _ir_byte_extracted(reg, def_of)):
                continue                               # whole-value scalar → defer
            kept.append(f)
        return kept

    def _message(self, f, location: str) -> str:
        return (f"[{f.severity}] partially-validated attacker bytes reach itxn "
                f"{f.field} ({location}, {f.sub_id}); the argument is validated "
                f"elsewhere but not on the bytes that steer the funds "
                f"(IR byte-precise, interprocedural)")
