"""Cross-contract analysis layer for TEAL `itxn_submit` app calls.

Slice 1: identification only. Walks a caller :class:`SSAProgram` for
`itxn_submit` groups whose first txn is an `appl` (TypeEnum == 6) with
a constant `ApplicationID` resolvable in a registry, and returns
:class:`AppcallSite` records describing the call.

Slice 2 (planned) extends :class:`PathPredicateAnalysis` with entry
seeds and computes an approving-exit summary on the callee. Slice 3
adds an :class:`XContractGraph` orchestrator and the first
cross-contract detector.

The substrate (``tealtools.ssa``) is *not* modified — this module only
consumes ``SSAProgram`` and ``InnerTxnReport``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from .inner_txn_report import InnerTxn, InnerTxnReport
from .path_predicates import BranchCondition, PathPredicateAnalysis
from .ssa import Const, SSAProgram

# TEAL TypeEnum integer for application calls. The assembler folds
# `int appl` and `byte "appl"` into the integer literal 6 before SSA.
TYPEENUM_APPL = "6"

Registry = dict[int, str]


@dataclass(frozen=True)
class AppcallSite:
    """One identified cross-contract call site in a caller program."""

    file: str
    submit_line: int
    app_id: int
    callee_db: Path
    # Constant ApplicationArgs by index. Non-constant args are absent;
    # consumers can still walk the underlying ``InnerTxn`` for
    # full operand info.
    const_args: dict[int, str] = field(default_factory=dict)

    def render(self, relative_to: Optional[Path] = None) -> str:
        if self.const_args:
            args = ", ".join(
                f"args[{i}]={v}"
                for i, v in sorted(self.const_args.items())
            )
        else:
            args = "(no constant args)"
        db = self.callee_db
        if relative_to is not None:
            try:
                db = db.relative_to(relative_to)
            except ValueError:
                pass
        return (
            f"{self.file}:L{self.submit_line}  "
            f"appl→{self.app_id}  ({db})  {args}"
        )

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "submit_line": self.submit_line,
            "app_id": self.app_id,
            "callee_db": str(self.callee_db),
            "const_args": {str(i): v for i, v in sorted(self.const_args.items())},
        }


def load_registry(path: str | Path) -> Registry:
    """Load an AppID → DB-path mapping from a yaml file.

    Paths in the yaml are resolved relative to the yaml's parent dir
    so fixtures can carry self-contained registries.
    """
    p = Path(path).resolve()
    raw = yaml.safe_load(p.read_text()) or {}
    base = p.parent
    out: Registry = {}
    for app_id, db in raw.items():
        out[int(app_id)] = str((base / db).resolve())
    return out


def _const_only(values: list[str]) -> Optional[str]:
    """Return the single literal if ``values`` is exactly one literal,
    else ``None``. A literal is anything that didn't get prefixed with
    ``?`` (unresolved) or come back as a non-literal source-op
    description (containing whitespace or ``(``)."""
    if len(values) != 1:
        return None
    v = values[0]
    if v.startswith("?"):
        return None
    if " " in v or "(" in v:
        return None
    return v


def _is_appcall(txn: InnerTxn) -> bool:
    by_name = txn.fields_by_name()
    type_fields = by_name.get("TypeEnum") or []
    if not type_fields:
        return False
    # Every TypeEnum-set must agree on `appl`. If multiple sets
    # disagree (e.g. branchy code that sometimes makes pay sometimes
    # appl), be conservative and skip — we don't have a reliable
    # callee in that case.
    for f in type_fields:
        if _const_only(f.possible_values()) != TYPEENUM_APPL:
            return False
    return True


def _const_app_id(txn: InnerTxn) -> Optional[int]:
    fields = txn.fields_by_name().get("ApplicationID") or []
    if not fields:
        return None
    seen: set[str] = set()
    for f in fields:
        v = _const_only(f.possible_values())
        if v is None:
            return None
        seen.add(v)
    if len(seen) != 1:
        return None
    try:
        return int(next(iter(seen)))
    except ValueError:
        return None


def _const_args(txn: InnerTxn) -> dict[int, str]:
    """Index the constant ApplicationArgs by their stack-set order.

    Each ``itxn_field ApplicationArgs`` op pushes one element onto
    the array; ``InnerTxnReport`` lists them in source order.
    """
    fields = txn.fields_by_name().get("ApplicationArgs") or []
    out: dict[int, str] = {}
    for i, f in enumerate(fields):
        v = _const_only(f.possible_values())
        if v is not None:
            out[i] = v
    return out


def find_appcall_sites(prog: SSAProgram, registry: Registry) -> list[AppcallSite]:
    """Find every appcall itxn submit in ``prog`` whose ApplicationID
    is a constant present in ``registry``.

    Returns sites sorted by (file, submit_line) for deterministic
    output. Submits whose first txn isn't an appl, or whose AppID is
    non-constant or unregistered, are silently skipped — slice 1 is
    only about resolvable cross-contract calls.
    """
    report = InnerTxnReport(prog)
    sites: list[AppcallSite] = []
    for group in report.groups:
        if not group.txns:
            continue
        # An appcall group typically contains one txn; if more, the
        # appcall is whichever txn(s) had TypeEnum=appl. Emit one
        # site per appcall txn.
        for txn in group.txns:
            if not _is_appcall(txn):
                continue
            app_id = _const_app_id(txn)
            if app_id is None or app_id not in registry:
                continue
            sites.append(
                AppcallSite(
                    file=group.file,
                    submit_line=group.submit_line,
                    app_id=app_id,
                    callee_db=Path(registry[app_id]),
                    const_args=_const_args(txn),
                )
            )
    sites.sort(key=lambda s: (s.file, s.submit_line))
    return sites


def render(sites: list[AppcallSite], relative_to: Optional[Path] = None) -> str:
    if not sites:
        return "(no cross-contract appcall sites)"
    return "\n".join(s.render(relative_to=relative_to) for s in sites)


# --- slice 2: seeded callee analysis ----------------------------------


def seeds_for_callee(
    callee: SSAProgram, site: AppcallSite
) -> frozenset[BranchCondition]:
    """Translate caller-side constant ApplicationArgs into entry
    predicates over the callee's ``txna ApplicationArgs N`` SSAVars.

    Conservative: emits one ``eq`` predicate per (index, constant)
    pair where the callee actually references that arg via ``txna``.
    Indices the callee never reads are dropped — they'd dangle on
    unreferenced SSAVars and pollute the predicate space.
    """
    if not site.const_args:
        return frozenset()
    seeds: set[BranchCondition] = set()
    for a in callee.assignments:
        if a.op != "txna" or not a.outputs:
            continue
        parts = a.immediates.split()
        if len(parts) != 2 or parts[0] != "ApplicationArgs":
            continue
        try:
            idx = int(parts[1])
        except ValueError:
            continue
        if idx not in site.const_args:
            continue
        const = Const("bytes", site.const_args[idx])
        seeds.add(
            BranchCondition(value=a.outputs[0], kind="eq", args=(const,))
        )
    return frozenset(seeds)


@dataclass
class CalleeAnalysis:
    """Result of running the seeded path-predicate analysis on a
    callee, plus the approving-exit summary the caller can rely on."""

    site: AppcallSite
    analysis: PathPredicateAnalysis
    seeds: frozenset[BranchCondition]
    summary: frozenset[BranchCondition]


def analyze_callee(callee: SSAProgram, site: AppcallSite) -> CalleeAnalysis:
    seeds = seeds_for_callee(callee, site)
    analysis = PathPredicateAnalysis(callee, entry_seeds=seeds)
    return CalleeAnalysis(
        site=site,
        analysis=analysis,
        seeds=seeds,
        summary=analysis.approving_exit_summary(),
    )


def _fmt_preds(preds: frozenset[BranchCondition]) -> str:
    if not preds:
        return "(none)"
    return ", ".join(
        repr(p) for p in sorted(preds, key=lambda c: (c.kind, repr(c.value)))
    )


def render_xcontract(
    sites: list[AppcallSite],
    callee_analyses: dict[int, CalleeAnalysis],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    """Combined slice-1 + slice-2 rendering: each call site followed
    by the callee's seeded approving-exit summary."""
    if not sites:
        return "(no cross-contract appcall sites)"
    out: list[str] = []
    for site in sites:
        out.append("call site: " + site.render(relative_to=relative_to))
        ca = callee_analyses.get(site.app_id)
        if ca is None:
            out.append("  callee not analysed")
            continue
        out.append("  seeds:   " + _fmt_preds(ca.seeds))
        out.append("  summary: " + _fmt_preds(ca.summary))
    return "\n".join(out)


# --- slice 3: graph orchestrator + first cross-contract detector ------


@dataclass
class XContractGraph:
    """Caller + every reachable callee, keyed by AppID, with their
    seeded path-predicate analyses precomputed.

    Owns no analysis logic itself — detectors are external functions
    (see ``cross_auth_findings``) that consume this graph. This keeps
    detector composition explicit and avoids accreting features here.
    """

    caller: SSAProgram
    sites: list[AppcallSite]
    callees: dict[int, SSAProgram]
    callee_dbs: dict[int, Path]
    analyses: dict[int, CalleeAnalysis]

    @classmethod
    def build(cls, caller: SSAProgram, registry: Registry) -> "XContractGraph":
        sites = find_appcall_sites(caller, registry)
        callees: dict[int, SSAProgram] = {}
        callee_dbs: dict[int, Path] = {}
        analyses: dict[int, CalleeAnalysis] = {}
        for site in sites:
            if site.app_id in callees:
                continue
            callee = SSAProgram(str(site.callee_db))
            callees[site.app_id] = callee
            callee_dbs[site.app_id] = site.callee_db
            analyses[site.app_id] = analyze_callee(callee, site)
        return cls(
            caller=caller, sites=sites, callees=callees,
            callee_dbs=callee_dbs, analyses=analyses,
        )


@dataclass(frozen=True)
class CrossAuthFinding:
    """One auth-domination violation in a callee, surfaced via the
    cross-contract graph. Includes the calling AppID so the report
    can be grouped per callee."""

    app_id: int
    violation: "object"  # AuthViolation; avoid heavy import at module load

    def render(self, callee_db: Path, relative_to: Optional[Path] = None) -> str:
        db = callee_db
        if relative_to is not None:
            try:
                db = db.relative_to(relative_to)
            except ValueError:
                pass
        return f"{db}  {self.violation.pretty()}"  # type: ignore[attr-defined]

    def to_dict(self, callee_db: Optional[Path] = None) -> dict:
        out: dict = {
            "app_id": self.app_id,
            "violation": self.violation.to_dict(),  # type: ignore[attr-defined]
        }
        if callee_db is not None:
            out["callee_db"] = str(callee_db)
        return out


@dataclass(frozen=True)
class ForeignVar:
    """Tag wrapping a callee-side operand when it surfaces in a caller's
    predicate set after submit-feedback. Without this, callee
    SSAVars print as ``V#1@L4`` and collide visually with caller-side
    vars (both source files are typically named ``prog.teal``).

    ``inner`` is the original :class:`SSAVar` / :class:`Phi` /
    :class:`MatPhiVar` from the callee; ``app_id`` is the AppID of
    the callee. Consts are not wrapped — they're literals with no
    provenance ambiguity.
    """

    inner: object
    app_id: int

    def __repr__(self) -> str:
        return f"app{self.app_id}:{self.inner!r}"


def _foreign_wrap(op: object, app_id: int) -> object:
    """Wrap callee-side operands; leave literals and primitives alone."""
    if isinstance(op, (Const, int, str)):
        return op
    return ForeignVar(inner=op, app_id=app_id)


def _wrap_callee_pred(pred: BranchCondition, app_id: int) -> BranchCondition:
    return BranchCondition(
        value=_foreign_wrap(pred.value, app_id),  # type: ignore[arg-type]
        kind=pred.kind,
        args=tuple(_foreign_wrap(a, app_id) for a in pred.args),
    )


def caller_feedback_bb_seeds(graph: XContractGraph) -> dict:
    """Map each caller BB containing an ``itxn_submit`` to the
    matching callee's approving-exit summary, with callee-side
    operands tagged via :class:`ForeignVar` so the renderer can
    disambiguate them from caller-side vars.

    Imprecision note: predicates land on the *whole* BB containing
    the submit, so any sink in that BB at a line *before* the submit
    will appear to have the summary in its predicate set. Most TEAL
    has control flow shortly after a submit, so this is rarely an
    issue in practice — but a sink-before-submit would be falsely
    over-guarded. A finer model would split the BB at the submit
    boundary; that's a follow-up.
    """
    seeds: dict = {}
    for site in graph.sites:
        ca = graph.analyses.get(site.app_id)
        if ca is None or not ca.summary:
            continue
        bb = graph.caller.block_containing(site.file, site.submit_line)
        if bb is None:
            continue
        wrapped = frozenset(
            _wrap_callee_pred(p, site.app_id) for p in ca.summary
        )
        existing = seeds.get(bb, frozenset())
        seeds[bb] = existing | wrapped
    return seeds


def caller_with_feedback(graph: XContractGraph) -> PathPredicateAnalysis:
    """Run :class:`PathPredicateAnalysis` on the caller with each
    submit-containing BB seeded with the matching callee's summary."""
    return PathPredicateAnalysis(
        graph.caller, bb_seeds=caller_feedback_bb_seeds(graph)
    )


def render_caller_feedback(
    graph: XContractGraph, *, relative_to: Optional[Path] = None
) -> str:
    """Render the caller's path predicates after callee-summary
    feedback. Only shows BBs that received feedback — the rest match
    a vanilla :class:`PathPredicateAnalysis`."""
    bb_seeds = caller_feedback_bb_seeds(graph)
    if not bb_seeds:
        return "(no callee-summary feedback to caller)"
    pp = caller_with_feedback(graph)
    out: list[str] = []
    for bb in sorted(bb_seeds.keys(), key=lambda b: (b.file, b.first_line)):
        preds = pp.bb_preds.get(bb, frozenset())
        out.append(
            f"caller {bb.file}:L{bb.first_line}-L{bb.last_line}  "
            + _fmt_preds(preds)
        )
    return "\n".join(out)


def cross_auth_findings(graph: XContractGraph) -> list[CrossAuthFinding]:
    """Run :class:`AuthDominationDetector` on every callee using its
    seeded :class:`PathPredicateAnalysis`. Returns one finding per
    sensitive sink that no recognised guard dominates.
    """
    from .auth_domination import AuthDominationDetector

    out: list[CrossAuthFinding] = []
    for app_id, callee in graph.callees.items():
        ca = graph.analyses[app_id]
        det = AuthDominationDetector(callee, path_predicates=ca.analysis)
        for v in det.detect():
            out.append(CrossAuthFinding(app_id=app_id, violation=v))
    return out


def render_findings(
    graph: XContractGraph,
    findings: list[CrossAuthFinding],
    *,
    relative_to: Optional[Path] = None,
) -> str:
    if not findings:
        return "(no cross-contract auth-domination findings)"
    return "\n".join(
        f.render(graph.callee_dbs[f.app_id], relative_to=relative_to)
        for f in findings
    )
