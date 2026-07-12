"""Unified detector / report registry.

Each existing analysis already has its own surface — some emit
"findings" (zero-or-more violation records), others emit a single
rendered string. This module gives both shapes a stable protocol so
callers can iterate over the registry instead of dispatching by
analysis name.

Two shapes, one registry each:

- :class:`Detector` — ``run(prog) -> Iterable[Finding]``. A finding
  is anything with a ``.pretty()`` method.
- :class:`Report` — ``run(prog) -> str``. Produces one block of
  pre-rendered text (suitable for ``print``-ing as-is).

Adapters live here so the underlying analysis modules stay focused;
adding a new detector is one extra entry in :data:`ALL_DETECTORS`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, runtime_checkable

from .ssa import SSAProgram

logger = logging.getLogger("tealql.tealtools")


def _safe(label: str, fn: "Callable[[], object]", default, *, strict: bool):
    """Run ``fn()`` in isolation — a detector or report that crashes on one weird
    contract must not sink the whole ``tealql all`` output (the same contract the
    security scanner honours in ``scan.py``). Logs the crash and returns
    ``default``; ``strict`` re-raises instead. Covers construction too: the
    sec-guide detector adapters build their underlying detector inside ``run()``."""
    try:
        return fn()
    except Exception as e:
        if strict:
            raise
        logger.error("%s crashed (skipped): %s", label, e)
        return default


@runtime_checkable
class Finding(Protocol):
    """Any value an :class:`Detector` may yield. Must render
    itself via ``.pretty()`` (existing :class:`Violation`,
    :class:`AuthViolation`, :class:`CorrelatedViolation`, etc. all
    satisfy this)."""

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

    def run(self, prog: SSAProgram) -> str:
        return self.fn(prog)


# Lazy imports inside each adapter keep import-time cheap and avoid
# circulars.

def _auth(prog: SSAProgram):
    from .auth_domination import AuthDominationDetector
    return AuthDominationDetector(prog).detect()


def _box_into(prog: SSAProgram):
    from .dataflow.box import detect_into_box_flows
    return detect_into_box_flows(prog)


def _box_out(prog: SSAProgram):
    from .dataflow.box import detect_out_of_box_flows
    return detect_out_of_box_flows(prog)


def _box_corr(prog: SSAProgram):
    from .dataflow.box import detect_correlated_flows
    return detect_correlated_flows(prog)


def _state_out(prog: SSAProgram):
    from .dataflow.state import detect_out_of_state_flows
    return detect_out_of_state_flows(prog)


def _itxn_report(prog: SSAProgram) -> str:
    from .inner_txn_report import InnerTxnReport
    return InnerTxnReport(prog).render()


def _group_shape(prog: SSAProgram) -> str:
    from .group_reasoning import analyze
    return analyze(prog).render()


def _group_layout(prog: SSAProgram) -> str:
    from .group_reasoning import analyze_layout
    return analyze_layout(prog).render()


def _cost(prog: SSAProgram) -> str:
    from .cost_analysis import render
    return render(prog)


def _path_preds(prog: SSAProgram) -> str:
    from .path_predicates import PathPredicateAnalysis
    return PathPredicateAnalysis(prog).render()


# Only the analysis-layer detectors live here — this module is pure tealtools
# and knows nothing about the security/ detector registry. The sec-guide
# detectors are injected as ``extra_detectors`` by ``tealql.security.run`` (which the
# CLI uses for ``tealql all``), keeping the dependency one-directional.
ALL_DETECTORS: list[Detector] = [
    _FnDetector("auth-domination", _auth),
    _FnDetector("box-df-into", _box_into),
    _FnDetector("box-df-out", _box_out),
    _FnDetector("box-df-correlated", _box_corr),
    _FnDetector("state-df-out", _state_out),
]


ALL_REPORTS: list[Report] = [
    _FnReport("itxn-report", _itxn_report),
    _FnReport("group-shape", _group_shape),
    _FnReport("group-layout", _group_layout),
    _FnReport("cost", _cost),
    _FnReport("path-predicates", _path_preds),
]


def run_all_findings(
    prog: SSAProgram, *, extra_detectors: Iterable[Detector] = (),
    strict: bool = False,
) -> tuple[str, int]:
    """Like :func:`run_all` but also returns the total detector-finding
    count, so callers (the CLI's ``all``) can set a findings exit code
    without re-running every detector. Per-detector/report crash-isolated
    (``strict=True`` re-raises) so one broken analysis can't sink the report."""
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
    """Run every core detector (+ any ``extra_detectors``) + report against
    ``prog`` and return one big text block, sectioned by analysis name.
    ``extra_detectors`` lets ``tealql.security.run`` inject the sec-guide detectors
    without this module importing the registry."""
    return run_all_findings(prog, extra_detectors=extra_detectors, strict=strict)[0]


def run_all_dict(prog: SSAProgram, *, extra_detectors: Iterable[Detector] = (),
                 strict: bool = False) -> dict:
    """Same coverage as :func:`run_all` but returns a structured dict
    suitable for JSON. Detector findings use each finding's
    ``to_dict()`` if available, falling back to ``{"message": ...}``.
    """
    from ._utils.serialize import finding_to_dict
    from .inner_txn_report import InnerTxnReport
    from .group_reasoning import analyze, analyze_layout
    from .cost_analysis import to_dict as cost_to_dict
    from .path_predicates import PathPredicateAnalysis

    detectors: dict[str, list[dict]] = {}
    for det in [*ALL_DETECTORS, *extra_detectors]:
        findings = _safe(f"detector {det.name}",
                         lambda d=det: list(d.run(prog)), [], strict=strict)
        detectors[det.name] = [finding_to_dict(f) for f in findings]
    reports = {
        "itxn-report": _safe("report itxn-report",
                             lambda: InnerTxnReport(prog).to_dict(), {}, strict=strict),
        "group-shape": _safe("report group-shape",
                             lambda: analyze(prog).to_dict(), {}, strict=strict),
        "group-layout": _safe("report group-layout",
                              lambda: analyze_layout(prog).to_dict(), {}, strict=strict),
        "cost": _safe("report cost", lambda: cost_to_dict(prog), {}, strict=strict),
        "path-predicates": _safe("report path-predicates",
                                 lambda: PathPredicateAnalysis(prog).to_dict(), {},
                                 strict=strict),
    }
    return {"detectors": detectors, "reports": reports}
