"""sec-guide/ir-tainted-log: attacker-controlled data emitted via log (IR).

A contract that ``log``s a user-input-tainted value emits FORGED data to anything
that trusts its logs:

  * a CALLER that reads this contract's ``LastLog`` after an inner appcall -- which
    is itself a taint source (``ItxnLastLog``); a spoofed ARC-4 return value or
    event can make the caller act on attacker-chosen data, and
  * off-chain indexers / dapps that treat the contract's logged events as truth.

Output-integrity rather than direct fund loss, so LOW severity -- but it is the
on-chain SOURCE of the cross-contract ``ItxnLastLog`` taint the caller-side
detectors react to. Built on the generalized IR taint-to-sink engine
(:func:`fund_flow.tainted_logs`), so it inherits across-``callsub`` guard
dominance, validation-subroutine guards, typed reasoning, and cross-contract
caller-pin suppression; a logged value that was validated first is guard-cleared.

A new capability with no SSA-layer sibling; lift-only. Emits only the UNGUARDED,
call-resolved logs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from security import common


@dataclass
class IrTaintedLogViolation:
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
        return f"IrTaintedLogViolation({self.message})"


class IrTaintedLogDetector:
    name: ClassVar[str] = "sec-guide/ir-tainted-log"
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # log is app-only
    violation_cls: ClassVar[type] = IrTaintedLogViolation

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
            f for f in FF.tainted_logs(lifter, trusted_args=self.trusted_args)
            if not f.guarded and not f.param_derived
        ]
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            sources = tuple(sorted(f.sources))
            message = (
                f"[{f.severity}] attacker-controlled data emitted via log "
                f"<- {'+'.join(sources)} ({location}, {f.sub_id}); a caller reading "
                f"this contract's LastLog (or an off-chain indexer) can be fed "
                f"forged data — no dominating check of the value (IR interprocedural)")
            out.append(IrTaintedLogViolation(
                "log", f.severity, sources, location, message))
        return out
