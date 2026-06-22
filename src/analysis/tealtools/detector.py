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

from dataclasses import dataclass
from typing import Callable, Iterable, Protocol, runtime_checkable

from .ssa import SSAProgram


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


def _detection_factory(short_name):
    """Build a one-off ``Detector`` adapter that instantiates the
    detector class registered under ``short_name``. The detector
    class is looked up lazily so importing this module stays cheap."""
    def _run(prog: SSAProgram):
        from .detections import DETECTORS
        return DETECTORS[short_name](prog).detect()
    return _FnDetector(f"detections/{short_name}", _run)


_DETECTION_NAMES = (
    "asset-close-to",
    "asset-id-validation",
    "box-key",
    "close-remainder-to",
    "delete-funds-check",
    "fee-validation",
    "group-size-check",
    "hardcoded-min-balance",
    "inner-txn-close-rekey",
    "inner-txn-fee",
    "is-deletable",
    "is-updatable",
    "rekey-to",
    "timelock-upgrade",
    "tx-type-check",
    "unprotected-deletable",
    "unprotected-updatable",
    "unsafe-lsig-args",
)


ALL_DETECTORS: list[Detector] = [
    _FnDetector("auth-domination", _auth),
    _FnDetector("box-df-into", _box_into),
    _FnDetector("box-df-out", _box_out),
    _FnDetector("box-df-correlated", _box_corr),
    _FnDetector("state-df-out", _state_out),
    *(_detection_factory(n) for n in _DETECTION_NAMES),
]


ALL_REPORTS: list[Report] = [
    _FnReport("itxn-report", _itxn_report),
    _FnReport("group-shape", _group_shape),
    _FnReport("group-layout", _group_layout),
    _FnReport("cost", _cost),
    _FnReport("path-predicates", _path_preds),
]


def run_all(prog: SSAProgram) -> str:
    """Run every detector + report against ``prog`` and return one
    big text block, sectioned by analysis name. Convenient for
    ``tealql all <target>``."""
    out: list[str] = []
    for det in ALL_DETECTORS:
        out.append(f"=== {det.name} ===")
        findings = list(det.run(prog))
        if findings:
            out.extend(f.pretty() for f in findings)
        else:
            out.append("(no findings)")
        out.append("")
    for rep in ALL_REPORTS:
        out.append(f"=== {rep.name} ===")
        out.append(rep.run(prog))
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def run_all_dict(prog: SSAProgram) -> dict:
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
    for det in ALL_DETECTORS:
        findings = list(det.run(prog))
        detectors[det.name] = [finding_to_dict(f) for f in findings]
    reports = {
        "itxn-report": InnerTxnReport(prog).to_dict(),
        "group-shape": analyze(prog).to_dict(),
        "group-layout": analyze_layout(prog).to_dict(),
        "cost": cost_to_dict(prog),
        "path-predicates": PathPredicateAnalysis(prog).to_dict(),
    }
    return {"detectors": detectors, "reports": reports}
