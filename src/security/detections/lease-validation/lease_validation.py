"""sec-guide/lease-validation: delegated-LogicSig replay protection.

A delegated LogicSig signs the *shape* of a transaction, not a specific
instance. If it approves a spend without constraining ``txn Lease``, the
same signed transaction can be resubmitted (replayed) until the
delegating key rotates — there is no other per-instance uniqueness. A
non-zero ``Lease`` makes the (Sender, Lease) pair single-use within the
lease window, which is the canonical fix.

Heuristic (advisory, scoped to LogicSigs): for each approval exit, flag
it when no path to it constrains ``txn Lease`` via a comparison whose
result reaches enforcement. Reuses the same ``approval_exit_protected_
for_field`` machinery as the RekeyTo / TypeEnum detectors; "protected"
here means "Lease is compared and the comparison gates approval"
(polarity-agnostic — ``Lease != ZeroAddress`` and ``Lease == <const>``
both count).

Deliberately narrow to ``logicsig`` programs: a stateful application has
other replay protection (its own global/local state), so a missing
Lease check there is usually not a finding. This keeps the false-
positive rate down for the common app case. Like the other sec-guide
ports this is intentionally conservative — a contract that enforces
uniqueness by some means this heuristic doesn't model (e.g. a state
nonce in an app) is out of scope by the logicsig gating, not a target.
"""
from __future__ import annotations

from dataclasses import dataclass

from tealtools.ssa import BasicBlock
from security._approval_exit import _ApprovalExitProtectedDetector


@dataclass
class LeaseValidationViolation:
    exit_bb: BasicBlock

    def pretty(self) -> str:
        line = self.exit_bb.last_line
        return (
            f"Approval exit at {self.exit_bb.file}:{line} "
            "is reachable without a Lease check — a delegated LogicSig that "
            "doesn't pin txn Lease can have its signed transaction replayed."
        )

    def __repr__(self) -> str:
        return f"LeaseValidationViolation({self.pretty()})"


class LeaseValidationDetector(_ApprovalExitProtectedDetector):
    name = "sec-guide/lease-validation"
    applies_to = frozenset({"logicsig"})  # apps have state-based replay protection
    field = "Lease"
    violation_cls = LeaseValidationViolation
