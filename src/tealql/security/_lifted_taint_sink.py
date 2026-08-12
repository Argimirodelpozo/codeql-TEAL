"""Shared driver for security policies evaluated on lifted pre-IR.

The representation layer owns interprocedural value flow and guard dominance;
detector modules supply only sink policy, severity, suppression, and prose.  A
failed lift is an incomplete analysis, never an invitation to silently answer a
different question with a weaker SSA implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional


@dataclass
class _LiftedTaintSinkViolation:
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
        return f"{type(self).__name__}({self.message})"


class _BoolTaintView:
    """Boolean pre-IR taint adapted to the road-witness view protocol."""

    def __init__(self, taint: dict):
        self._taint = taint

    def tainted_bytes(self, reg):
        return id(reg) in self._taint

    def is_scalar_tainted(self, reg) -> bool:
        return id(reg) in self._taint

    def is_covered(self, reg) -> bool:
        return True


class _LiftedTaintSinkDetector:
    """Policy shell around the canonical lifted taint/guard analysis."""

    name: ClassVar[str]
    applies_to: ClassVar[frozenset] = frozenset({"app"})
    violation_cls: ClassVar[type] = _LiftedTaintSinkViolation
    fields: ClassVar[Optional[dict]] = None

    def __init__(self, prog, *, file: Optional[str] = None,
                 trusted_args=frozenset()):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.degraded: Optional[str] = None

    def _raw_findings(self, lifter) -> list:
        from tealql.tealtools.lift import fund_flow
        return fund_flow.tainted_itxn_flows(
            lifter, self.fields, trusted_args=self.trusted_args,
        )

    def _suppress(self, lifter, findings) -> list:
        return findings

    def _message(self, finding, location: str) -> str:
        raise NotImplementedError

    def _taint_view(self, lifter):
        from tealql.tealtools.lift.taint import user_input_taint
        return _BoolTaintView(user_input_taint(lifter, self.trusted_args))

    def _road(self, lifter, finding, view) -> str:
        reg = getattr(finding, "sink_reg", None)
        if reg is None:
            return ""
        from tealql.tealtools.lift.fund_flow import ir_taint_road
        try:
            road = ir_taint_road(lifter, reg, view)
        except Exception:
            return ""
        return "" if road.startswith("(no ") else road

    def detect(self) -> list:
        import tealql.tealtools.lift as lift_layer

        lifter = lift_layer.build_lifter(self.prog, self.file)
        if lifter is None:
            self.degraded = (
                "lifted pre-IR construction failed, so this detector did NOT "
                "run — findings are incomplete"
            )
            return []

        findings = [
            finding for finding in self._raw_findings(lifter)
            if not finding.guarded and not finding.param_derived
        ]
        findings = self._suppress(lifter, findings)
        source = getattr(self.prog, "source_path", None)
        files = getattr(self.prog, "source_files", ())
        filename = (
            self.file
            or (files[0] if len(files) == 1 else None)
            or (source.name if source is not None and getattr(source, "name", "") else None)
            or "<program>"
        )
        view = self._taint_view(lifter) if findings else None
        out: list = []
        for finding in findings:
            location = f"{filename}:{finding.line}"
            message = self._message(finding, location)
            road = self._road(lifter, finding, view) if view is not None else ""
            if road:
                message = f"{message}  via: {road}"
            out.append(self.violation_cls(
                finding.field,
                finding.severity,
                tuple(sorted(finding.sources)),
                location,
                message,
            ))
        return out

