"""sec-guide/ir-tainted-state-write: attacker-controlled state-write KEY (IR).

A user-input-tainted value reaching the KEY (the destination slot) of a persistent
state write -- ``app_global_put`` / ``app_local_put`` / ``box_put`` /
``box_create`` / ``box_replace`` -- lets the attacker write to a slot they choose:
overwrite the contract's own owner / admin / accounting GLOBAL state, or collide
with a sensitive box. The VALUE written is NOT flagged (storing user data is
normal); only the attacker-chosen KEY.

A NEW sink CATEGORY (no SSA-layer sibling): the first detector built on the IR
engine generalised past inner-txn fields to arbitrary sink ops
(:func:`fund_flow.tainted_state_writes`). It inherits the IR layer's across-
``callsub`` guard dominance, validation-subroutine guards, typed reasoning, and
cross-contract caller-pin suppression. Low false-positive by construction: a key
derived from ``txn Sender`` (the ubiquitous per-caller ``box[Sender]`` pattern) is
NOT a taint source so never surfaces, and a key checked ``== Sender`` / against
stored state is guard-cleared.

Lift-only (no SSA fallback). Emits only the UNGUARDED, call-resolved writes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common

_STATE = {
    "app_global_put": "global", "app_local_put": "local",
    "box_put": "box", "box_create": "box", "box_replace": "box",
}


@dataclass
class IrTaintedStateWriteViolation:
    field: str = ""
    severity: str = ""
    sources: tuple = ()
    location: str = ""
    message: str = ""

    def pretty(self) -> str:
        return self.message

    def to_dict(self) -> dict:
        return {
            "op": self.field,
            "severity": self.severity,
            "sources": list(self.sources),
            "location": self.location,
            "message": self.message,
        }

    def __repr__(self) -> str:
        return f"IrTaintedStateWriteViolation({self.message})"


class IrTaintedStateWriteDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-state-write"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # state writes are app-only
    violation_cls: ClassVar[type] = IrTaintedStateWriteViolation

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates           # (unused; no SSA sibling)

    def detect(self) -> list:
        lifter = common.ir_lifter(self.prog, self.file)
        if lifter is None:                               # didn't lift; no SSA sibling
            return []
        from tealtools.WIP_lift2puyaIR import fund_flow as FF
        findings = [
            f for f in FF.tainted_state_writes(lifter, trusted_args=self.trusted_args)
            if not f.guarded and not f.param_derived
        ]
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            kind = _STATE.get(f.field, "state")
            message = (
                f"[{f.severity}] attacker-controlled {kind}-state write KEY in "
                f"{f.field} <- {'+'.join(sources)} ({location}, {f.sub_id}); the "
                f"attacker chooses the destination slot — can overwrite owner/admin "
                f"{kind} state — with no dominating check of the key or txn Sender "
                f"(IR interprocedural)")
            out.append(IrTaintedStateWriteViolation(
                f.field, f.severity, sources, location, message))
        return out
