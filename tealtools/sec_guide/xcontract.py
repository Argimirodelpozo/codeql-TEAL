"""Cross-contract sec-guide runner.

Glue between :class:`tealtools.xcontract.XContractGraph` and the
sec-guide detectors. For each callee discovered in the caller's
``itxn_submit`` sites, runs the registered sec-guide detectors and
returns the violations tagged with the caller-side AppID context.

Why this is useful: the caller's perspective on "is the app I'm
about to call safe?" is exactly the union of (a) cross-contract auth
domination on the callee — already in :func:`tealtools.xcontract.cross_auth_findings`
— and (b) the callee's own sec-guide hygiene (deletable? updatable?
inner-txn fees set? rekey unchecked?). This module surfaces (b).

Detectors that accept a ``path_predicates`` kwarg (the OnCompletion-guard
family, plus a few others) are constructed with the callee's
*seeded* :class:`PathPredicateAnalysis` from
:class:`tealtools.xcontract.CalleeAnalysis`. That means caller-side
constraints (e.g. ``ApplicationArgs[0] == "do_thing"``) influence
the predicates available at the callee's approval exits — so a
guard expressed only on certain method paths is still recognised.

Example::

    from tealtools.ssa import SSAProgram
    from tealtools.xcontract import XContractGraph, load_registry
    from tealtools.sec_guide.xcontract import (
        cross_sec_guide_findings, render_findings,
    )

    caller = SSAProgram("caller-db")
    graph = XContractGraph.build(caller, load_registry("registry.yml"))
    for f in cross_sec_guide_findings(graph):
        print(f.render(relative_to=...))
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from ..xcontract import XContractGraph
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
        callee_db: Optional[Path] = None,
        *,
        relative_to: Optional[Path] = None,
    ) -> str:
        if callee_db is None:
            db_str = ""
        else:
            db = callee_db
            if relative_to is not None:
                try:
                    db = db.relative_to(relative_to)
                except ValueError:
                    pass
            db_str = f"{db}  "
        return (
            f"app{self.app_id}  {self.detector_name}  {db_str}"
            f"{self.violation.pretty()}"  # type: ignore[attr-defined]
        )


def _construct_detector(cls, callee, callee_analysis):
    """Instantiate a detector, wiring the callee's seeded
    PathPredicateAnalysis when the detector accepts one. Detectors
    that don't take the kwarg get the bare ``cls(callee)`` form."""
    sig = inspect.signature(cls.__init__)
    if "path_predicates" in sig.parameters:
        return cls(callee, path_predicates=callee_analysis.analysis)
    return cls(callee)


def cross_sec_guide_findings(
    graph: XContractGraph,
    *,
    detector_names: Optional[Iterable[str]] = None,
) -> list[CrossSecGuideFinding]:
    """Run sec-guide detectors against every callee in ``graph``.

    ``detector_names``: kebab-case short names (the keys of
    :data:`tealtools.sec_guide.DETECTORS`). If omitted, every
    registered sec-guide detector runs.

    OnCompletion-guard family detectors (and any other detector that
    accepts a ``path_predicates`` kwarg) get the callee's *seeded*
    :class:`PathPredicateAnalysis` so caller-side facts propagate.
    Detectors that don't take seeds run as plain
    ``cls(callee).detect()`` — they're program-level and don't depend
    on the call-site context."""
    from .common import infer_program_type
    names = list(detector_names) if detector_names is not None else list(DETECTORS)
    out: list[CrossSecGuideFinding] = []
    for app_id, callee in graph.callees.items():
        ca = graph.analyses[app_id]
        program_type = infer_program_type(callee)
        for name in names:
            cls = DETECTORS.get(name)
            if cls is None:
                raise KeyError(f"unknown sec-guide detector: {name!r}")
            applies = getattr(
                cls, "applies_to", frozenset({"app", "logicsig"}),
            )
            if program_type not in applies:
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
        callee_db = graph.callee_dbs.get(app_id)
        for f in by_app[app_id]:
            lines.append(f.render(callee_db, relative_to=relative_to))
    return "\n".join(lines)
