"""Cross-contract sec-guide runner: for each callee discovered in the caller's
``itxn_submit`` sites, run the registered detectors and tag the violations with
the caller-side AppID. Answers the callee's own hygiene half of "is the app I'm
about to call safe?"; the auth half is
``tealtools.intercontract.analysis.cross_auth_findings``.

Detectors accepting ``path_predicates`` get the callee's SEEDED analysis, so
caller-side constraints (``ApplicationArgs[0] == "do_thing"``) reach the callee's
approval exits and a guard expressed only on certain method paths is recognised.
"""
from __future__ import annotations

import inspect
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from tealql.tealtools.intercontract.analysis import XContractGraph
from tealql.tealtools.intercontract.health import call_graph_health
from tealql.tealtools.diagnostics.health import AnalysisDegradation, AnalysisHealth, AnalysisResult
from . import DETECTORS

logger = logging.getLogger("tealql.security.xcontract")


@dataclass(frozen=True)
class CrossSecGuideFinding:
    """One violation found in a callee, tagged with the AppID that surfaced it."""

    app_id: int
    detector_name: str   # e.g. "sec-guide/is-deletable"
    violation: object    # any Finding (with .pretty())

    def render(
        self,
        callee_source: Optional[Path] = None,
        *,
        relative_to: Optional[Path] = None,
    ) -> str:
        if callee_source is None:
            src_str = ""
        else:
            src = callee_source
            if relative_to is not None:
                try:
                    src = src.relative_to(relative_to)
                except ValueError:
                    pass
            src_str = f"{src}  "
        return (
            f"app{self.app_id}  {self.detector_name}  {src_str}"
            f"{self.violation.pretty()}"  # type: ignore[attr-defined]
        )


def _construct_detector(cls, callee, callee_analysis):
    """Instantiate a detector, wiring caller-side context it accepts: the seeded
    ``path_predicates``, and ``trusted_args`` (call-site-pinned ApplicationArgs
    indices, which the IR fund-flow detector treats as not attacker-controlled)."""
    sig = inspect.signature(cls.__init__)
    kwargs: dict = {}
    if "path_predicates" in sig.parameters:
        kwargs["path_predicates"] = callee_analysis.analysis
    if "trusted_args" in sig.parameters:
        kwargs["trusted_args"] = frozenset(callee_analysis.site.const_args)
    return cls(callee, **kwargs)


def cross_detection_result(
    graph: XContractGraph,
    *,
    detector_names: Optional[Iterable[str]] = None,
    strict: bool = False,
) -> AnalysisResult[list[CrossSecGuideFinding]]:
    """Run the detectors named by ``detector_names`` (default: all) against every
    callee in ``graph``.

    Crash isolation is per-(callee, detector): one detector faulting on one weird
    callee is logged and skipped rather than sinking every other callee's findings.
    ``strict=True`` re-raises."""
    names = list(detector_names) if detector_names is not None else list(DETECTORS)
    for name in names:
        if name not in DETECTORS:
            raise KeyError(f"unknown sec-guide detector: {name!r}")
    out: list[CrossSecGuideFinding] = []
    notes = list(call_graph_health(graph).degradations)
    for app_id, callee in graph.callees.items():
        ca = graph.analyses[app_id]
        # A callee reached through an appcall itxn is by construction a stateful
        # Application, so filter to app detectors directly — no inference needed.
        for name in names:
            cls = DETECTORS.get(name)
            if cls is None:
                raise KeyError(f"unknown sec-guide detector: {name!r}")
            applies = getattr(
                cls, "applies_to", frozenset({"app", "logicsig"}),
            )
            if "app" not in applies:
                continue
            try:
                detector = _construct_detector(cls, callee, ca)
                violations = list(detector.detect())
                if getattr(detector, 'degraded', None):
                    notes.append(AnalysisDegradation('detector-degraded',
                        f'app{app_id}: {detector.degraded}', str(graph.callee_sources[app_id]),
                        detector=name))
            except Exception as e:
                if strict:
                    raise
                logger.error("detector %s crashed on callee app%s (skipped): %s",
                             name, app_id, e)
                notes.append(AnalysisDegradation('detector-failed',
                    f'app{app_id}: {type(e).__name__}: {e}', str(graph.callee_sources[app_id]),
                    detector=name))
                continue
            for v in violations:
                out.append(CrossSecGuideFinding(
                    app_id=app_id,
                    detector_name=f"sec-guide/{name}",
                    violation=v,
                ))
    health = AnalysisHealth(tuple(dict.fromkeys(notes)))
    if strict and not health.complete:
        from tealql.tealtools.diagnostics.errors import TealQLError
        raise TealQLError('; '.join(health.messages()))
    return AnalysisResult(out, health)


def cross_detection_findings(graph, *, detector_names=None, strict=False):
    """Compatibility list projection; new consumers should retain result health."""
    return cross_detection_result(graph, detector_names=detector_names, strict=strict).value


def render_findings(
    graph: XContractGraph,
    findings: list[CrossSecGuideFinding],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    """Findings grouped by AppID, one line each."""
    if not findings:
        return "(no cross-contract sec-guide findings)"
    by_app: dict[int, list[CrossSecGuideFinding]] = {}
    for f in findings:
        by_app.setdefault(f.app_id, []).append(f)
    lines: list[str] = []
    for app_id in sorted(by_app):
        callee_source = graph.callee_sources.get(app_id)
        for f in by_app[app_id]:
            lines.append(f.render(callee_source, relative_to=relative_to))
    return "\n".join(lines)
