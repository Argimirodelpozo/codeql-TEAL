"""sec-guide/asset-close-to: ``AssetCloseTo`` not ENFORCED on every approving path.

A delegated-LOGICSIG concern, so what matters is the SIGNED transaction's own
field. A ``gtxn N AssetCloseTo`` check reads a SIBLING and protects the signer
only when ``txn GroupIndex == N`` is pinned; unpinned, the signed txn's own field
is still unchecked and the finding says exactly that.
"""
from __future__ import annotations

from typing import Optional

from tealql.security._field_validated import _FieldValidatedDetector, _FieldValidatedViolation
from tealql.security._field_protection import field_validated_on_all_paths
from tealql.security._program_shape import has_instructions
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
    # A sibling check exists, but on an index the program never pins itself to.
    unpinned_index_message = (
        "Contract validates a sibling gtxn N AssetCloseTo but does not pin "
        "txn GroupIndex == N — the SIGNED transaction's own AssetCloseTo is still "
        "unchecked, so all asset units can be drained from the account."
    )
    violation_cls = AssetCloseToViolation

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        super().__init__(prog, file=file)

    def detect(self) -> list:
        if not has_instructions(self.prog, file=self.file):
            return []
        f = self.field[0]
        # The signed txn's OWN field is validated — safe.
        if field_validated_on_all_paths(
                self.prog, f, file=self.file, signed_txn_only=True):
            return []
        # A gtxn N check IS enforced, but on an unpinned index, so the signed txn
        # is still exposed; warn specifically rather than clearing it.
        if field_validated_on_all_paths(self.prog, f, file=self.file):
            return [self.violation_cls(self.prog, self.unpinned_index_message)]
        return [self.violation_cls(self.prog, self.message)]
