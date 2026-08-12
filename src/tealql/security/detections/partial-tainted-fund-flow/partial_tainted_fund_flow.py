"""Byte-precise partial-validation fund flow on lifted pre-IR."""
from __future__ import annotations

from tealql.tealtools.language.avm import PAYMENT_FUND_FIELDS

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)

_BYTE_POSITION_OPS = frozenset({
    "getbyte", "extract_uint16", "extract_uint32", "extract_uint64",
    "extract", "extract3", "substring", "substring3",
})


def _byte_extracted(reg, definitions) -> bool:
    from tealql.tealtools.lift import fund_flow

    for _reg, operation in fund_flow._walk(reg, definitions):
        intrinsic = fund_flow._intr(operation) if operation is not None else None
        if intrinsic is not None and intrinsic.op in _BYTE_POSITION_OPS:
            return True
    return False


class PartialTaintedFundFlowViolation(_LiftedTaintSinkViolation):
    pass


class PartialTaintedFundFlowDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/partial-tainted-fund-flow"
    violation_cls = PartialTaintedFundFlowViolation
    fields = PAYMENT_FUND_FIELDS

    def _taint_view(self, lifter):
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        return byte_taint_view(lifter)

    def _byte_taint_map(self, lifter) -> dict:
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view

        view = byte_taint_view(lifter)
        taint: dict = {}
        for register in lifter.register_objects.values():
            if view.tainted_bytes(register) or view.is_scalar_tainted(register):
                taint[id(register)] = {"attacker-bytes"}
        return taint

    def _raw_findings(self, lifter) -> list:
        from tealql.tealtools.lift import fund_flow

        return fund_flow.tainted_itxn_flows(
            lifter,
            self.fields,
            taint=self._byte_taint_map(lifter),
            trusted_args=self.trusted_args,
            sender_only=True,
        )

    def _suppress(self, lifter, findings) -> list:
        from tealql.tealtools.dataflow.byte_taint import byte_taint_view
        from tealql.tealtools.lift import fund_flow

        owned = {
            (finding.field, finding.line)
            for finding in fund_flow.tainted_fund_flows(
                lifter, trusted_args=self.trusted_args,
            )
            if not finding.guarded and not finding.param_derived
        }
        view = byte_taint_view(lifter)
        definitions = fund_flow._def_map(lifter)
        kept = []
        for finding in findings:
            if (finding.field, finding.line) in owned:
                continue
            register = finding.sink_reg
            intervals = view.tainted_bytes(register) if register is not None else None
            if (
                register is not None
                and view.is_covered(register)
                and not intervals
                and not _byte_extracted(register, definitions)
            ):
                continue
            parts = list(getattr(intervals, "parts", ()) or ())
            finding.address_sized = (
                len(parts) == 1 and parts[0][1] - parts[0][0] == 32
            )
            kept.append(finding)
        return kept

    def _message(self, finding, location: str) -> str:
        hint = " (32 bytes — address-sized)" if finding.address_sized else ""
        return (
            f"[{finding.severity}] partially-validated attacker bytes reach "
            f"itxn {finding.field}{hint} ({location}, {finding.sub_id}); the argument "
            "is validated elsewhere but not on the bytes that steer the funds "
            "(lifted byte-precise, interprocedural)"
        )
