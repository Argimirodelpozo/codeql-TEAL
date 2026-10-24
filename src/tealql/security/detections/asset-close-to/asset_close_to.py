"""sec-guide/asset-close-to: ``AssetCloseTo`` not ENFORCED on every approving path.

A delegated-LOGICSIG concern, so what matters is the SIGNED transaction's own
field. A ``gtxn N AssetCloseTo`` check reads a SIBLING and protects the signer
only when ``txn GroupIndex == N`` is pinned; unpinned, the signed txn's own field
is still unchecked and the finding says exactly that.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealql.security._field_protection import field_validated_on_all_paths
from tealql.security._program_shape import approving_exits, has_instructions
from tealql.tealtools.ssa import SSAProgram


@dataclass
class AssetCloseToViolation:
    prog: SSAProgram
    message: str = ""

    # The violation is the ABSENCE of a validation, so there is no anchor line.
    file = None
    line = None

    def pretty(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message})"


class AssetCloseToDetector:
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
        self.prog = prog
        self.file = file

    def in_scope(self) -> bool:
        """The ABSENCE of a validation is a finding only for a program that
        parsed to instructions AND can approve.

        HAZARD: an empty / fully-unparsed program trivially "lacks" the
        validation — unanalyzable input, not a finding. And the claim is "a
        drain can be APPROVED without the check": a program with no approving
        exit (`int 0; return`, `err`) approves nothing, so the absent check
        protects nothing and is not a finding either."""
        return (has_instructions(self.prog, file=self.file)
                and bool(approving_exits(self.prog, file=self.file)))

    def detect(self) -> list:
        if not self.in_scope():
            return []
        f = self.field[0]
        # The signed txn's OWN field is validated — safe.
        # Pinned to ZeroAddress / a fixed address — not merely compared.
        if field_validated_on_all_paths(
                self.prog, f, file=self.file, signed_txn_only=True,
                safe="address-pin"):
            return []
        # A gtxn N check IS enforced, but on an unpinned index, so the signed txn
        # is still exposed; warn specifically rather than clearing it.
        if field_validated_on_all_paths(self.prog, f, file=self.file,
                                        safe="address-pin"):
            return [self.violation_cls(self.prog, self.unpinned_index_message)]
        return [self.violation_cls(self.prog, self.message)]
