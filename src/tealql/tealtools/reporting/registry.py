"""Registry over both analysis shapes — :class:`Detector` (``run(prog)`` yields
findings, anything with ``.pretty()``) and :class:`Report` (``run(prog)`` returns
one pre-rendered text block) — so callers iterate instead of dispatching by name.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Protocol, runtime_checkable

from ..ssa import SSAProgram

logger = logging.getLogger("tealql.tealtools")


def _safe(label: str, fn: "Callable[[], object]", default, *, strict: bool):
    """Run ``fn()`` crash-isolated — one detector that dies on a weird contract must
    not sink the whole output; logs and returns ``default``, ``strict`` re-raises."""
    try:
        return fn()
    except Exception as e:
        if strict:
            raise
        logger.error("%s crashed (skipped): %s", label, e)
        return default


@runtime_checkable
class Finding(Protocol):
    """Any value a :class:`Detector` may yield: it must render itself via
    ``.pretty()``."""

    def pretty(self) -> str: ...


@runtime_checkable
class Detector(Protocol):
    name: str

    def run(self, prog: SSAProgram) -> Iterable[Finding]: ...


@runtime_checkable
class Report(Protocol):
    name: str

    def run(self, prog: SSAProgram) -> str: ...


# --- minimal adapters ----------------------------------------------


@dataclass(frozen=True)
class _FnDetector:
    name: str
    fn: Callable[[SSAProgram], Iterable[Finding]]

    def run(self, prog: SSAProgram) -> Iterable[Finding]:
        return self.fn(prog)


@dataclass(frozen=True)
class _FnReport:
    name: str
    fn: Callable[[SSAProgram], str]
    #: JSON form; when absent ``run_all_dict`` emits ``{}`` rather than dropping
    #: the key.
    dict_fn: "Optional[Callable[[SSAProgram], dict]]" = None

    def run(self, prog: SSAProgram) -> str:
        return self.fn(prog)

    def run_dict(self, prog: SSAProgram) -> dict:
        return self.dict_fn(prog) if self.dict_fn is not None else {}


# Lazy imports inside each adapter keep import-time cheap and avoid circulars.

def _auth(prog: SSAProgram):
    from ..analysis.auth import AuthDominationDetector
    return AuthDominationDetector(prog).detect()


def _box_into(prog: SSAProgram):
    from ..dataflow.box import detect_into_box_flows
    return detect_into_box_flows(prog)


def _box_out(prog: SSAProgram):
    from ..dataflow.box import detect_out_of_box_flows
    return detect_out_of_box_flows(prog)


def _box_corr(prog: SSAProgram):
    from ..dataflow.box import detect_correlated_flows
    return detect_correlated_flows(prog)


def _state_out(prog: SSAProgram):
    from ..dataflow.state import detect_out_of_state_flows
    return detect_out_of_state_flows(prog)


def _state_corr(prog: SSAProgram):
    from ..dataflow.state import detect_correlated_state_flows
    return detect_correlated_state_flows(prog)


def _itxn_report(prog: SSAProgram) -> str:
    from .inner_transactions import InnerTxnReport
    return InnerTxnReport(prog).render()


def _group_shape(prog: SSAProgram) -> str:
    from ..cfg.group import analyze
    return analyze(prog).render()


def _group_layout(prog: SSAProgram) -> str:
    from ..cfg.group import analyze_layout
    return analyze_layout(prog).render()


def _path_preds(prog: SSAProgram) -> str:
    from ..cfg.path_predicates import PathPredicateAnalysis
    return PathPredicateAnalysis(prog).render()


def _itxn_report_d(prog: SSAProgram) -> dict:
    from .inner_transactions import InnerTxnReport
    return InnerTxnReport(prog).to_dict()


def _group_shape_d(prog: SSAProgram) -> dict:
    from ..cfg.group import analyze
    return analyze(prog).to_dict()


def _group_layout_d(prog: SSAProgram) -> dict:
    from ..cfg.group import analyze_layout
    return analyze_layout(prog).to_dict()


def _path_preds_d(prog: SSAProgram) -> dict:
    from ..cfg.path_predicates import PathPredicateAnalysis
    return PathPredicateAnalysis(prog).to_dict()


# Only analysis-layer detectors live here; the security/ ones are injected as
# ``extra_detectors`` by ``tealql.security.run``, keeping tealtools free of any
# dependency on the security registry.
ALL_DETECTORS: list[Detector] = [
    _FnDetector("auth-domination", _auth),
    _FnDetector("box-df-into", _box_into),
    _FnDetector("box-df-out", _box_out),
    _FnDetector("box-df-correlated", _box_corr),
    _FnDetector("state-df-out", _state_out),
    _FnDetector("state-df-correlated", _state_corr),
]


ALL_REPORTS: list[Report] = [
    _FnReport("itxn-report", _itxn_report, _itxn_report_d),
    _FnReport("group-shape", _group_shape, _group_shape_d),
    _FnReport("group-layout", _group_layout, _group_layout_d),
    _FnReport("path-predicates", _path_preds, _path_preds_d),
]


def run_all_findings(
    prog: SSAProgram, *, extra_detectors: Iterable[Detector] = (),
    strict: bool = False,
) -> tuple[str, int]:
    """Like :func:`run_all` but also returns the total finding count, so a caller can
    set a findings exit code without re-running every detector."""
    out: list[str] = []
    n_findings = 0
    for det in [*ALL_DETECTORS, *extra_detectors]:
        out.append(f"=== {det.name} ===")
        findings = _safe(f"detector {det.name}",
                         lambda d=det: list(d.run(prog)), [], strict=strict)
        if findings:
            n_findings += len(findings)
            out.extend(f.pretty() for f in findings)
        else:
            out.append("(no findings)")
        out.append("")
    for rep in ALL_REPORTS:
        out.append(f"=== {rep.name} ===")
        out.append(_safe(f"report {rep.name}", lambda r=rep: r.run(prog),
                         "(report crashed — skipped)", strict=strict))
        out.append("")
    return "\n".join(out).rstrip() + "\n", n_findings


def run_all(prog: SSAProgram, *, extra_detectors: Iterable[Detector] = (),
            strict: bool = False) -> str:
    """Run every core detector (+ any ``extra_detectors``) and report against ``prog``,
    returning one text block sectioned by analysis name."""
    return run_all_findings(prog, extra_detectors=extra_detectors, strict=strict)[0]


def run_all_dict(prog: SSAProgram, *, extra_detectors: Iterable[Detector] = (),
                 strict: bool = False) -> dict:
    """Same coverage as :func:`run_all`, as a JSON-shaped dict."""
    from .._utils.serialize import finding_to_dict

    detectors: dict[str, list[dict]] = {}
    for det in [*ALL_DETECTORS, *extra_detectors]:
        findings = _safe(f"detector {det.name}",
                         lambda d=det: list(d.run(prog)), [], strict=strict)
        detectors[det.name] = [finding_to_dict(f) for f in findings]
    # Driven by ALL_REPORTS like the text path — a second hardcoded list here
    # silently drops any newly registered report from --json.
    reports = {
        rep.name: _safe(f"report {rep.name}",
                        lambda r=rep: r.run_dict(prog), {}, strict=strict)
        for rep in ALL_REPORTS
    }
    return {"detectors": detectors, "reports": reports}
