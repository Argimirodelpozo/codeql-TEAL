"""Attacker-controlled inner asset selector, evaluated on lifted pre-IR."""
from __future__ import annotations

from tealql.security._lifted_taint_sink import (
    _LiftedTaintSinkDetector,
    _LiftedTaintSinkViolation,
)


class ArbitraryInnerAssetViolation(_LiftedTaintSinkViolation):
    pass


class ArbitraryInnerAssetDetector(_LiftedTaintSinkDetector):
    name = "sec-guide/arbitrary-inner-asset"
    violation_cls = ArbitraryInnerAssetViolation
    fields = {"XferAsset": "HIGH"}

    def _message(self, finding, location):
        sources = "+".join(sorted(finding.sources))
        return (
            f"[{finding.severity}] attacker-controlled inner asset-transfer "
            f"target itxn {finding.field} <- {sources} ({location}, "
            f"{finding.sub_id}); the app will move whichever asset the attacker "
            "names out of its holdings — no dominating check and the asset is "
            "not returned to the caller (lifted interprocedural)"
        )

    def _suppress(self, lifter, findings):
        from tealql.tealtools.lift.fund_flow import (
            itxn_selector_lines_returned_to_sender,
        )

        returned = itxn_selector_lines_returned_to_sender(
            lifter,
            selector_field="XferAsset",
            receiver_field="AssetReceiver",
        )
        return [finding for finding in findings if finding.line not in returned]
