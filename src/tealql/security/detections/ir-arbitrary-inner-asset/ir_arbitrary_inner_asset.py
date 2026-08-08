"""sec-guide/ir-arbitrary-inner-asset: a user-input-tainted ``XferAsset`` lets the
attacker pick WHICH ASA leaves the app's holdings. The IR-layer sibling of
``arbitrary-inner-asset``, plus the asset-specific RECEIVER-CONTEXT suppression:
if ``AssetReceiver`` flows from the sender, the chooser is only moving an asset to
themselves, not draining a third party.
"""
from __future__ import annotations

from tealql.security import common
from tealql.security._ir_taint_sink import _IrTaintSinkDetector, _IrTaintSinkViolation

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
        ``AssetReceiver`` flowing from the sender. Computed on the SSA ``prog`` and
        correlated back by source line, orthogonally to the IR taint work."""
        prog = self.prog
        sender_vars = common.sender_vars(prog, file=self.file)
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
