"""Shared base for the IR-layer taint-to-sink detector family: the lift, the
unguarded-filter, the emit loop, and the violation dataclass.

A concrete detector sets ``name``, ``violation_cls``, and EITHER ``fields`` (a
``{field_name: severity}`` itxn map, feeding the default ``_raw_findings``) OR an
override of ``_raw_findings``; plus ``_message(finding, location)``. Optional:
``fallback`` (an SSA detector kebab to defer to when the contract doesn't lift)
and ``_suppress(lifter, findings)``."""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Optional

from . import common


@dataclass
class _IrTaintSinkViolation:
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
    """Adapts a boolean IR taint map to the view interface the road witness needs.
    Boolean taint covers every register, hence ``is_covered`` is always True."""

    def __init__(self, taint: dict):
        self._t = taint

    def tainted_bytes(self, reg):
        return bool(id(reg) in self._t)

    def is_scalar_tainted(self, reg) -> bool:
        return id(reg) in self._t

    def is_covered(self, reg) -> bool:
        return True


class _IrTaintSinkDetector:
    name: ClassVar[str]
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn/log/state are app-only
    violation_cls: ClassVar[type] = _IrTaintSinkViolation
    fields: ClassVar[Optional[dict]] = None      # default sink: these itxn fields
    fallback: ClassVar[Optional[str]] = None     # SSA sibling to defer to on lift-fail

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates    # forwarded to the SSA fallback
        #: Set by ``detect`` when this detector could not run at full strength.
        #: ``scan`` reads it afterwards and reports it, because an empty finding
        #: list from a detector that never ran is indistinguishable from a clean
        #: bill of health -- the worst answer a security tool can give.
        self.degraded: Optional[str] = None

    # -- hooks ----------------------------------------------------------------

    def _raw_findings(self, lifter) -> list:
        """Taint-to-sink findings, BEFORE the unguarded-filter; override for a
        non-itxn sink (state write / log)."""
        from tealql.tealtools.lift import fund_flow as FF
        return FF.tainted_itxn_flows(lifter, self.fields, trusted_args=self.trusted_args)

    def _suppress(self, lifter, findings) -> list:
        """Optional per-detector post-filter; identity by default."""
        return findings

    def _message(self, f, location: str) -> str:
        raise NotImplementedError

    def _taint_view(self, lifter):
        """The taint oracle for the road witness; must match ``_raw_findings``'
        granularity (boolean by default, byte-precise where that detector overrides)."""
        from tealql.tealtools.lift.taint import user_input_taint
        return _BoolTaintView(user_input_taint(lifter, self.trusted_args))

    def _road(self, lifter, f, view) -> str:
        """The lifted-IR ``source → … → sink`` road for ``f``, or empty."""
        reg = getattr(f, "sink_reg", None)
        if reg is None:
            return ""
        from tealql.tealtools.lift.fund_flow import ir_taint_road
        try:
            road = ir_taint_road(lifter, reg, view)
        except Exception:
            return ""
        return "" if road.startswith("(no ") else road

    # -- driver ---------------------------------------------------------------

    def detect(self) -> list:
        lifter = common.ir_lifter(self.prog, self.file)
        if lifter is None:                        # didn't lift (~0.1% of mainnet)
            if self.fallback is not None:
                from . import DETECTORS             # defer to the SSA sibling
                self.degraded = (
                    f"IR lift failed; answered with the SSA detector "
                    f"'{self.fallback}' instead, which is less precise")
                return DETECTORS[self.fallback](
                    self.prog, file=self.file, path_predicates=self.path_predicates,
                ).detect()
            self.degraded = (
                "IR lift failed and this detector has no SSA fallback, so it "
                "did NOT run — finding nothing here means nothing")
            return []
        findings = [f for f in self._raw_findings(lifter)
                    if not f.guarded and not f.param_derived]
        findings = self._suppress(lifter, findings)
        src = getattr(self.prog, "source_path", None)
        files = getattr(self.prog, "source_files", ())
        fname = (self.file or (files[0] if len(files) == 1 else None)
                 or (src.name if src is not None and getattr(src, "name", "") else None)
                 or "<program>")
        view = self._taint_view(lifter) if findings else None
        out: list = []
        for f in findings:
            location = f"{fname}:{f.line}"
            msg = self._message(f, location)
            road = self._road(lifter, f, view) if view is not None else ""
            if road:
                msg = f"{msg}  via: {road}"
            out.append(self.violation_cls(
                f.field, f.severity, tuple(sorted(f.sources)), location, msg))
        return out
