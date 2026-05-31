"""sec-guide/abi-method-selector: unvalidated ABI method dispatch.

An ABI application routes on the method selector in
``txna ApplicationArgs 0`` — comparing it to each method's 4-byte
signature hash and rejecting anything unrecognised. If an approval
exit is reachable *without* the selector being checked (e.g. a bare
``int 1; return`` fall-through past the dispatch, or a router that
routes but never rejects an unknown selector), a caller can reach
application logic the method table was supposed to gate.

Heuristic (scoped to ABI-shaped apps): only programs that actually
read ``txna ApplicationArgs 0`` are considered — a non-ABI app that
never inspects the selector is out of scope (it isn't doing method
dispatch at all), which keeps the false-positive rate down. For such
apps, flag each approval exit not protected by a selector comparison
whose result reaches enforcement on every path to it. Reuses the same
``approval_exit_protected_for_*`` path-walk as the field detectors,
seeded on the selector read.

KNOWN IMPRECISION (heuristic, over-approximating): "protected" means a
selector comparison whose result reaches *enforcement* (assert / branch-
to-err) dominates the exit. A pure dispatch ``selector == M; bnz
handler`` routes without rejecting, so reaching ``handler`` does not
count as enforcement here — a correct multi-method router whose only
rejection is a final fall-through ``err`` will have its *handlers*
flagged, not just the missing-reject path. The precise form needs
path-predicate reasoning ("this exit is reached only on the matched-
selector edge") plus selector-value canonicalisation through ``dup`` —
a shared follow-up (the same canonicalisation the disjunction work
needs). Treat findings as "selector dispatch worth auditing", not
proof of a hole. Scoped to ABI-shaped apps to bound the noise.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from tealtools.ssa import BasicBlock, SSAProgram
from tealtools.detections import common

_SELECTOR = "ApplicationArgs 0"


@dataclass
class AbiMethodSelectorViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without validating the ABI method selector "
            "(txna ApplicationArgs 0) — unrecognised methods are not rejected."
        )

    def __repr__(self) -> str:
        return f"AbiMethodSelectorViolation({self.pretty()})"


class AbiMethodSelectorDetector:
    name = "sec-guide/abi-method-selector"
    applies_to = frozenset({"app"})  # ABI dispatch is an application concern

    def __init__(self, prog: SSAProgram, *, file: Optional[str] = None):
        self.prog = prog
        self.file = file

    def detect(self) -> list[AbiMethodSelectorViolation]:
        # Only ABI-shaped apps: if the program never reads the method
        # selector, it isn't doing method dispatch — nothing to validate.
        if not common._txna_reads(self.prog, _SELECTOR, file=self.file):
            return []
        out: list[AbiMethodSelectorViolation] = []
        for exit_bb in sorted(
            common.approving_exits(self.prog, file=self.file),
            key=lambda b: (b.file, b.first_line),
        ):
            if not common.approval_exit_protected_for_arg_reads(
                self.prog, exit_bb, _SELECTOR, file=self.file,
            ):
                out.append(AbiMethodSelectorViolation(exit_bb))
        return out
