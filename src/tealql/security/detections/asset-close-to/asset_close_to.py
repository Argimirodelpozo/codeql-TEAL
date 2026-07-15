"""sec-guide/asset-close-to: missing AssetCloseTo validation.

Every-path form: ``AssetCloseTo`` must be ENFORCED (asserted / branch-to-reject)
on every approving path — a must-reach on the enforcement site, not merely a
comparison that dominates the exits (see :func:`common.field_validated_on_all_paths`).

Signed-txn scope: this is a delegated-LOGICSIG concern, so the field that matters
is the SIGNED transaction's own ``AssetCloseTo``. A ``gtxn N AssetCloseTo`` check
reads a SIBLING and protects the signer only when ``txn GroupIndex == N`` is
pinned (so ``gtxn N`` IS the signed txn) — otherwise the signed txn's own field is
still unchecked, and the finding says exactly that.
"""
from __future__ import annotations

from typing import Optional

from tealql.security import common
from tealql.security._field_validated import _FieldValidatedDetector, _FieldValidatedViolation
from tealql.tealtools.ssa import SSAProgram


class AssetCloseToViolation(_FieldValidatedViolation):
    pass


class AssetCloseToDetector(_FieldValidatedDetector):
    severity = "high"
    name = "sec-guide/asset-close-to"
    field = ("AssetCloseTo",)
    applies_to = frozenset({"logicsig"})
    message = (
        "Contract does not validate txn AssetCloseTo "
        "— all asset units can be drained from the account."
    )
    # The signed txn IS validated by a sibling check, but only on an index the
    # program never pins itself to — so the signed txn's own field is unprotected.
    unpinned_index_message = (
        "Contract validates a sibling gtxn N AssetCloseTo but does not pin "
        "txn GroupIndex == N — the SIGNED transaction's own AssetCloseTo is still "
        "unchecked, so all asset units can be drained from the account."
    )
    violation_cls = AssetCloseToViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        super().__init__(prog, file=file)

    def detect(self) -> list:
        if not common.has_instructions(self.prog, file=self.file):
            return []
        f = self.field[0]
        # The signed txn's OWN AssetCloseTo is validated (txn / dynamic-self /
        # gtxn N with GroupIndex==N pinned) — safe.
        if common.field_validated_on_all_paths(
                self.prog, f, file=self.file, signed_txn_only=True):
            return []
        # A gtxn N check IS enforced, but on an index the program didn't pin to
        # itself — the signed txn is still exposed; warn specifically.
        if common.field_validated_on_all_paths(self.prog, f, file=self.file):
            return [self.violation_cls(self.prog, self.unpinned_index_message)]
        return [self.violation_cls(self.prog, self.message)]
