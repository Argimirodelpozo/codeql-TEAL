"""sec-guide/arbitrary-inner-asset: an inner asset transfer whose ``XferAsset`` —
WHICH ASA leaves the application account — is attacker-controlled, unguarded, and
not returned to the caller. The asset-confusion shape (Tinyman-class): the app
moves whichever asset the attacker names to a party they never deposited for.

``AssetReceiver``/``AssetAmount`` belong to tainted-fund-flow; this owns the asset
SELECTOR. Suppressed when the same inner txn's ``AssetReceiver`` flows from ``txn
Sender`` (withdrawing your own named asset to yourself drains nobody), or on a
value/sender guard. Only the immediate ``itxn_begin``/``itxn_next`` block is
correlated.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from tealql.security import common
from tealql.tealtools.path_predicates import PathPredicateAnalysis
from tealql.tealtools.ssa import SSAProgram

_ASSET_SELECTOR_FIELD = "XferAsset"
_RECEIVER_FIELD = "AssetReceiver"
_BLOCK_DELIMS = frozenset({"itxn_begin", "itxn_next"})


@dataclass
class ArbitraryInnerAssetViolation:
    prog: SSAProgram
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
        return f"ArbitraryInnerAssetViolation({self.message})"


class ArbitraryInnerAssetDetector:
    name: ClassVar[str] = "sec-guide/arbitrary-inner-asset"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn_* is app-only
    violation_cls: ClassVar[type] = ArbitraryInnerAssetViolation
    # The IR sibling adds IR taint/guards and falls back to this one on lift
    # failure; kept registered but skipped in default scans.
    superseded_by: ClassVar[str] = "ir-arbitrary-inner-asset"

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None,
                 path_predicates: "Optional[PathPredicateAnalysis]" = None):
        self.prog = prog
        self.file = file
        self.pp = path_predicates or common.cached_path_predicates(prog)

    def detect(self) -> list:
        taint = common.user_input_taint(self.prog, self.file)
        if not taint:
            return []
        sender_vars = common.sender_creator_vars(self.prog, file=self.file)
        receiver_by_block = self._block_receivers()
        violations: list = []
        for fs in common.inner_txn_field_assigns(self.prog, file=self.file):
            if fs.field != _ASSET_SELECTOR_FIELD:
                continue
            sink_slots = taint.get(fs.value, frozenset())
            if not sink_slots:
                continue                              # asset not attacker-controlled
            if common.itxn_value_guarded(
                self.prog, self.pp, fs.assignment, sink_slots, taint, sender_vars):
                continue
            # The asset returns to the caller, so the chooser drains nobody.
            recv = receiver_by_block.get(self._block_id(fs.assignment))
            if recv is not None and common._operand_flows_from_field_var(
                    self.prog, recv, sender_vars):
                continue
            sources = tuple(sorted({lbl for lbl, _ in sink_slots}))
            loc = common.loc(fs.assignment)
            msg = (f"[HIGH] attacker-controlled inner asset-transfer target "
                   f"itxn {fs.field} <- {'+'.join(sources)} ({loc}); the app will "
                   f"move whichever asset the attacker names out of its holdings — "
                   f"no dominating check and the asset is not returned to the caller")
            violations.append(ArbitraryInnerAssetViolation(
                self.prog, fs.field, "HIGH", sources, loc, msg))
        return violations

    # -- inner-txn block correlation -----------------------------------

    def _ordered_itxn_ops(self) -> list:
        return sorted(
            (a for a in self.prog.assignments
             if (a.op in _BLOCK_DELIMS or a.op == "itxn_field")
             and common.file_match(a.location.file, self.file)),
            key=lambda a: (a.location.file, a.location.line),
        )

    def _block_id(self, assignment) -> tuple:
        """The ``(file, line)`` of the delimiter opening ``assignment``'s itxn block."""
        cur = None
        for a in self._ordered_itxn_ops():
            if a.location.file != assignment.location.file:
                continue
            if a.op in _BLOCK_DELIMS:
                cur = (a.location.file, a.location.line)
            if a is assignment:
                return cur
        return cur

    def _block_receivers(self) -> dict:
        """``block_id -> AssetReceiver value`` for each inner-txn block."""
        out: dict = {}
        cur = None
        for a in self._ordered_itxn_ops():
            if a.op in _BLOCK_DELIMS:
                cur = (a.location.file, a.location.line)
            elif a.op == "itxn_field" and a.immediates.strip() == _RECEIVER_FIELD \
                    and a.inputs and cur is not None:
                out[cur] = a.inputs[0]
        return out
