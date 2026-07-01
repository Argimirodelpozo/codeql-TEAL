"""Shared base for the IR-layer taint-to-sink detector family.

Eight detectors run the generalized IR engine (``fund_flow.tainted_itxn_flows`` /
``tainted_state_writes`` / ``tainted_logs``) and differ only in: the SINK (an
inner-txn field set, or a flow function), an optional SSA ``fallback`` to defer to
when the contract doesn't lift, an optional post-filter, and the finding message.
This base factors out the rest -- the lift, the unguarded-filter, the emit loop,
and the violation dataclass -- so each concrete detector is ~15 lines of config
(cf. :mod:`security._field_validated`).

A concrete detector sets ``name``, ``violation_cls``, and EITHER ``fields`` (a
``{field_name: severity}`` itxn map -> the default ``_raw_findings``) OR overrides
``_raw_findings``; plus ``_message(finding, location)``. Optional: ``fallback`` (an
SSA detector kebab) and ``_suppress(lifter, findings)`` (a post-filter)."""
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
    """Adapts a boolean IR taint map ``{id(register): sources}`` to the tiny
    view interface :func:`fund_flow.ir_taint_chain` needs (``tainted_bytes`` /
    ``is_scalar_tainted`` / ``is_covered``), so the road witness works for the
    boolean detectors too. Boolean taint covers every register, so
    ``is_covered`` is always True (no uncovered fallback)."""

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
    applies_to: ClassVar[frozenset] = frozenset({"app"})  # itxn / log / state are app-only
    violation_cls: ClassVar[type] = _IrTaintSinkViolation
    fields: ClassVar[Optional[dict]] = None      # default sink: these itxn fields
    fallback: ClassVar[Optional[str]] = None     # SSA sibling to defer to on lift-fail

    def __init__(self, prog, *, file: Optional[str] = None, trusted_args=frozenset(),
                 path_predicates=None):
        self.prog = prog
        self.file = file
        self.trusted_args = frozenset(trusted_args)
        self.path_predicates = path_predicates    # forwarded to the SSA fallback

    # -- hooks ----------------------------------------------------------------

    def _raw_findings(self, lifter) -> list:
        """The taint-to-sink findings (before the unguarded-filter). Default:
        tainted values reaching the inner-txn ``fields``; override for a non-itxn
        sink (state write / log)."""
        from tealtools.lift import fund_flow as FF
        return FF.tainted_itxn_flows(lifter, self.fields, trusted_args=self.trusted_args)

    def _suppress(self, lifter, findings) -> list:
        """Optional per-detector post-filter (default: identity)."""
        return findings

    def _message(self, f, location: str) -> str:
        raise NotImplementedError

    def _taint_view(self, lifter):
        """The taint oracle for the road WITNESS -- boolean user-input taint by
        default (matches the boolean ``_raw_findings``); the byte-precise detector
        overrides with ``byte_taint_view``."""
        from tealtools.lift.taint import user_input_taint
        return _BoolTaintView(user_input_taint(lifter, self.trusted_args))

    def _road(self, lifter, f, view) -> str:
        """The lifted-IR taint road for finding ``f`` -- ``source → … → sink``, as
        a witness appended to the message. Empty when unavailable."""
        reg = getattr(f, "sink_reg", None)
        if reg is None:
            return ""
        from tealtools.lift.fund_flow import ir_taint_road
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
                return DETECTORS[self.fallback](
                    self.prog, file=self.file, path_predicates=self.path_predicates,
                ).detect()
            return []
        findings = [f for f in self._raw_findings(lifter)
                    if not f.guarded and not f.param_derived]
        findings = self._suppress(lifter, findings)
        src = getattr(self.prog, "source_path", None)
        fname = src.name if src is not None and getattr(src, "name", "") else "<program>"
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
