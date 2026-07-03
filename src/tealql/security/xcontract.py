"""Cross-contract sec-guide runner.

Glue between :class:`tealql.tealtools.xcontract.XContractGraph` and the
sec-guide detectors. For each callee discovered in the caller's
``itxn_submit`` sites, runs the registered sec-guide detectors and
returns the violations tagged with the caller-side AppID context.

Why this is useful: the caller's perspective on "is the app I'm
about to call safe?" is exactly the union of (a) cross-contract auth
domination on the callee — already in :func:`tealql.tealtools.xcontract.cross_auth_findings`
— and (b) the callee's own sec-guide hygiene (deletable? updatable?
inner-txn fees set? rekey unchecked?). This module surfaces (b).

Detectors that accept a ``path_predicates`` kwarg (the OnCompletion-guard
family, plus a few others) are constructed with the callee's
*seeded* :class:`PathPredicateAnalysis` from
:class:`tealql.tealtools.xcontract.CalleeAnalysis`. That means caller-side
constraints (e.g. ``ApplicationArgs[0] == "do_thing"``) influence
the predicates available at the callee's approval exits — so a
guard expressed only on certain method paths is still recognised.

Example::

    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.xcontract import XContractGraph, load_registry
    from tealql.security.xcontract import (
        cross_detection_findings, render_findings,
    )

    caller = SSAProgram("caller.teal")
    graph = XContractGraph.build(caller, load_registry("registry.yml"))
    for f in cross_detection_findings(graph):
        print(f.render(relative_to=...))
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from tealql.tealtools.xcontract import XContractGraph
from . import DETECTORS


@dataclass(frozen=True)
class CrossSecGuideFinding:
    """One sec-guide violation found in a callee, tagged with the
    AppID of the appcall site that surfaced it. The wrapped
    ``violation`` carries the detector's own ``pretty()`` output."""

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
    """Instantiate a detector, wiring caller-side context when the detector accepts
    it: the callee's seeded ``PathPredicateAnalysis`` (``path_predicates`` -- the
    OnCompletion-guard family) and/or the call site's pinned ApplicationArgs
    indices (``trusted_args`` -- the IR fund-flow detector treats a caller-pinned
    arg as not attacker-controlled). Detectors that take neither get the bare
    ``cls(callee)`` form."""
    sig = inspect.signature(cls.__init__)
    kwargs: dict = {}
    if "path_predicates" in sig.parameters:
        kwargs["path_predicates"] = callee_analysis.analysis
    if "trusted_args" in sig.parameters:
        kwargs["trusted_args"] = frozenset(callee_analysis.site.const_args)
    return cls(callee, **kwargs)


def cross_detection_findings(
    graph: XContractGraph,
    *,
    detector_names: Optional[Iterable[str]] = None,
) -> list[CrossSecGuideFinding]:
    """Run sec-guide detectors against every callee in ``graph``.

    ``detector_names``: kebab-case short names (the keys of
    :data:`tealql.security.DETECTORS`). If omitted, every
    registered sec-guide detector runs.

    OnCompletion-guard family detectors (and any other detector that
    accepts a ``path_predicates`` kwarg) get the callee's *seeded*
    :class:`PathPredicateAnalysis` so caller-side facts propagate.
    Detectors that don't take seeds run as plain
    ``cls(callee).detect()`` — they're program-level and don't depend
    on the call-site context."""
    names = list(detector_names) if detector_names is not None else list(DETECTORS)
    out: list[CrossSecGuideFinding] = []
    for app_id, callee in graph.callees.items():
        ca = graph.analyses[app_id]
        # A callee reached through an appcall itxn is, by construction, a
        # stateful Application — you can only ``itxn`` an app. So filter
        # to App-applicable detectors directly; no inference needed.
        for name in names:
            cls = DETECTORS.get(name)
            if cls is None:
                raise KeyError(f"unknown sec-guide detector: {name!r}")
            applies = getattr(
                cls, "applies_to", frozenset({"app", "logicsig"}),
            )
            if "app" not in applies:
                continue
            det = _construct_detector(cls, callee, ca)
            for v in det.detect():
                out.append(CrossSecGuideFinding(
                    app_id=app_id,
                    detector_name=f"sec-guide/{name}",
                    violation=v,
                ))
    return out


def render_findings(
    graph: XContractGraph,
    findings: list[CrossSecGuideFinding],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    """Group findings by AppID for legibility. Each line carries the
    detector name + the wrapped violation's ``pretty()`` output."""
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
