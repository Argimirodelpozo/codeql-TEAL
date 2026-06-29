"""sec-guide/ir-arbitrary-inner-asset: attacker-controlled inner asset-transfer (IR).

A user-input-tainted ``XferAsset`` -- *which* ASA moves out of the app's holdings
-- lets the attacker pick the asset, draining a balance the contract didn't mean to
touch. Same taint-to-sink shape as :mod:`ir_tainted_fund_flow` on ``XferAsset``,
inheriting the IR layer's across-``callsub`` guard dominance + cross-contract
suppression. Plus the asset-specific RECEIVER-CONTEXT suppression: if the asset
returns to the caller (``AssetReceiver`` flows from the sender / the app itself),
the chooser is only moving an asset to themselves -- not a third-party drain -- so
it is not a finding. Supersedes the SSA ``arbitrary-inner-asset``.
"""
from __future__ import annotations

from security import common
from security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation

_BLOCK_DELIMS = frozenset({"itxn_begin", "itxn_next"})
_RECEIVER_FIELD = "AssetReceiver"
_SELECTOR_FIELD = "XferAsset"


class IrArbitraryInnerAssetViolation(_IrTaintSinkViolation):
    pass


class IrArbitraryInnerAssetDetector(_IrTaintSinkDetector):
    name = "sec-guide/ir-arbitrary-inner-asset"
    violation_cls = IrArbitraryInnerAssetViolation
    fields = {"XferAsset": "HIGH"}
    fallback = "arbitrary-inner-asset"

    def _message(self, f, location):
        src = "+".join(sorted(f.sources))
        return (f"[{f.severity}] attacker-controlled inner asset-transfer target "
                f"itxn {f.field} <- {src} ({location}, {f.sub_id}); the app will "
                f"move whichever asset the attacker names out of its holdings — no "
                f"dominating check and the asset is not returned to the caller "
                f"(IR interprocedural)")

    def _suppress(self, lifter, findings):
        skip = self._xfer_lines_returning_to_caller()
        return [f for f in findings if f.line not in skip]

    def _xfer_lines_returning_to_caller(self) -> set:
        """Source lines of ``XferAsset`` ops whose inner-txn block sets an
        ``AssetReceiver`` that flows from the sender / the app -- the named asset
        returns to the caller, so it isn't a third-party drain. Computed on the SSA
        ``prog`` (orthogonal to the IR taint/guard work; reuses the shared
        sender-flow helper), correlated by XferAsset source line."""
        prog = self.prog
        sender_vars = common.sender_creator_vars(prog, file=self.file)
        if not sender_vars:
            return set()
        ops = sorted(
            (a for a in prog.assignments
             if (a.op in _BLOCK_DELIMS or a.op == "itxn_field")
             and common.file_match(a.location.file, self.file)),
            key=lambda a: (a.location.file, a.location.line),
        )
        blocks: list = []
        cur = None
        for a in ops:
            if a.op in _BLOCK_DELIMS:
                cur = {"recv": None, "xfers": []}
                blocks.append(cur)
            elif a.op == "itxn_field" and cur is not None:
                fld = a.immediates.strip()
                if fld == _RECEIVER_FIELD and a.inputs:
                    cur["recv"] = a.inputs[0]
                elif fld == _SELECTOR_FIELD:
                    cur["xfers"].append(a.location.line)
        out: set = set()
        for blk in blocks:
            if blk["recv"] is not None and common._operand_flows_from_field_var(
                    prog, blk["recv"], sender_vars):
                out.update(blk["xfers"])
        return out
