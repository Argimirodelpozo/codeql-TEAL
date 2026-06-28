"""sec-guide/ir-arbitrary-inner-asset: attacker-controlled inner asset-transfer (IR).

The IR-layer sibling of :mod:`arbitrary_inner_asset`: a user-input-tainted
``XferAsset`` -- *which* ASA moves out of the app's holdings -- lets the attacker
pick the asset, draining a balance the contract didn't mean to touch. Same
taint-to-sink shape as :mod:`ir_tainted_fund_flow` on the ``XferAsset`` field via
:func:`common.ir_unguarded_itxn_flows`, so it inherits the IR layer's
across-``callsub`` guard dominance, validation-subroutine guards, typed reasoning,
and cross-contract caller-pinned suppression.

Plus the asset-specific RECEIVER-CONTEXT suppression (shared with the SSA
detector): if the asset returns to the caller (the inner txn's ``AssetReceiver``
flows from ``txn Sender`` / the app itself), the chooser is only moving an asset
to themselves -- they can't drain a third party -- so it is not a finding.

Primary over the SSA ``arbitrary-inner-asset``, which it ``supersede``s and falls
back to on lift failure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

_FIELDS = {"XferAsset": "HIGH"}
_BLOCK_DELIMS = frozenset({"itxn_begin", "itxn_next"})
_RECEIVER_FIELD = "AssetReceiver"
_SELECTOR_FIELD = "XferAsset"


@dataclass
class IrArbitraryInnerAssetViolation:
    field: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "field": self.field,
            "severity": self.severity,
            "sources": list(self.sources),
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"IrArbitraryInnerAssetViolation({self.message})"


class IrArbitraryInnerAssetDetector:
    name: ClassVar[str] = "sec-guide/ir-arbitrary-inner-asset"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn_* is app-only
    violation_cls: ClassVar[type] = IrArbitraryInnerAssetViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates           # for the SSA fallback

    def detect(self) -> list:
        lifted, findings = common.ir_unguarded_itxn_flows(
            self.prog, self.file, _FIELDS, self.trusted_args)
        if not lifted:
            from security import DETECTORS                # lift failed -> SSA fallback
            return DETECTORS["arbitrary-inner-asset"](
                self.prog, file=self.file, path_predicates=self.path_predicates,
            ).detect()
        # "withdraw the asset I name to myself" is not a third-party drain: drop a
        # tainted XferAsset whose itxn block returns the asset to the caller.
        return_to_caller = self._xfer_lines_returning_to_caller()
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in findings:
            if f.line in return_to_caller:
                continue
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            message = (
                f"[{f.severity}] attacker-controlled inner asset-transfer target "
                f"itxn {f.field} <- {'+'.join(sources)} ({location}, {f.sub_id}); the "
                f"app will move whichever asset the attacker names out of its "
                f"holdings — no dominating check and the asset is not returned to "
                f"the caller (IR interprocedural)")
            out.append(IrArbitraryInnerAssetViolation(
                f.field, f.severity, sources, location, message))
        return out

    def _xfer_lines_returning_to_caller(self) -> set:
        """Source lines of ``XferAsset`` ops whose inner-txn block sets an
        ``AssetReceiver`` that flows from the sender / the app -- the named asset
        returns to the caller, so it isn't a third-party drain. Computed on the SSA
        ``prog`` (the receiver-context check is orthogonal to the IR taint/guard
        work, and reuses the shared sender-flow helper)."""
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
        cur: Optional[dict] = None
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
