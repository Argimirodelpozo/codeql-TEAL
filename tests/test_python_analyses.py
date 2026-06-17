"""Snapshot harness for the tealtools detectors.

Discovers fixtures under ``tests/tealtools/<analysis>/[<case>/]db/``
and runs the matching analysis against each. Output is compared to a
checked-in ``expected.txt`` next to the fixture; mismatches fail the
test with a unified diff.

Missing CodeQL DBs are built on demand by a session-scoped fixture in
``conftest.py`` — no separate build step needed.

Regenerate snapshots with::

    UPDATE_SNAPSHOTS=1 pytest tests/test_python_analyses.py
"""
import difflib
import os
from collections import Counter
from pathlib import Path

import pytest

PY_TESTS = Path(__file__).resolve().parent / "tealtools"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Fixture dirs without a detector — exercised as SSA construction
# smoke tests (snapshot a structural summary).
SSA_SMOKE = {
    "loop_dig_deep", "loop_frame_dig", "stack_growing_loop",
    "conditional_swap",
}


XC_ROOT = PY_TESTS / "xcontract"
XC_SG_ROOT = PY_TESTS / "xcontract_sec_guide"
SGS_ROOT = PY_TESTS / "sec_guide_scan"
# Cross-contract taint fixtures own a multi-DB caller/callee layout and
# are covered by the dedicated tests/test_xcontract_taint.py integration
# test, not the snapshot harness.
XC_TAINT_ROOT = PY_TESTS / "xcontract_taint"


def _discover():
    # xcontract cases own a multi-DB layout (caller/db, callee/db); the
    # case_dir is the parent of those, not the parent of any one db/.
    if XC_ROOT.exists():
        for case in sorted(p for p in XC_ROOT.iterdir() if p.is_dir()):
            yield pytest.param("xcontract", case, id=f"xcontract/{case.name}")
    if XC_SG_ROOT.exists():
        for case in sorted(p for p in XC_SG_ROOT.iterdir() if p.is_dir()):
            yield pytest.param(
                "xcontract_sec_guide", case,
                id=f"xcontract_sec_guide/{case.name}",
            )
    # sec_guide_scan cases hand a directory of raw .teal files (no
    # pre-built DB) to the recursive scanner. The DB build happens
    # inside scan() against a tmp cache, not via the standard
    # case_dir/db convention.
    if SGS_ROOT.exists():
        for case in sorted(p for p in SGS_ROOT.iterdir() if p.is_dir()):
            yield pytest.param(
                "sec_guide_scan", case,
                id=f"sec_guide_scan/{case.name}",
            )
    for db_yml in sorted(PY_TESTS.rglob("codeql-database.yml")):
        case_dir = db_yml.parent.parent
        if XC_ROOT in case_dir.parents or case_dir == XC_ROOT:
            continue  # already collected as a single xcontract case
        if XC_SG_ROOT in case_dir.parents or case_dir == XC_SG_ROOT:
            continue  # ditto for the sec-guide xcontract tree
        if SGS_ROOT in case_dir.parents or case_dir == SGS_ROOT:
            continue  # sec_guide_scan cases collected above
        if XC_TAINT_ROOT in case_dir.parents or case_dir == XC_TAINT_ROOT:
            continue  # covered by tests/test_xcontract_taint.py
        rel = case_dir.relative_to(PY_TESTS)
        analysis = rel.parts[0]
        yield pytest.param(analysis, case_dir, id=str(rel))


@pytest.fixture(scope="session")
def scan_cache(tmp_path_factory):
    """Session-scoped cache root for ``sec_guide_scan`` fixtures.
    Lives under pytest's tmp tree so it survives within a run (DBs
    are reused across cases) but doesn't pollute ``~/.cache/``."""
    return tmp_path_factory.mktemp("tealql_sec_guide_scan_cache")


def _ssa_summary(prog) -> str:
    """Structural digest of an SSAProgram. Stable across cosmetic
    changes; sensitive to opcode set, block/var/phi counts, and
    assignment count — i.e. anything that would indicate the SSA
    builder shifted."""
    op_hist = Counter(a.op for a in prog.assignments)
    lines = [
        f"blocks      = {len(prog.blocks)}",
        f"assignments = {len(prog.assignments)}",
        f"phis        = {len(prog.phis)}",
        f"vars        = {len(prog.vars)}",
        "opcodes:",
    ]
    for op, n in sorted(op_hist.items()):
        lines.append(f"  {op:<24} {n}")
    return "\n".join(lines) + "\n"


def _render(analysis: str, case_dir: Path, *, scan_cache: Path = None) -> str:
    from tealtools.ssa import SSAProgram

    if analysis == "sec_guide_scan":
        from tealtools.detections.scan import ScanConfig, render_text, scan

        rules = case_dir / "rules.yml"
        config = ScanConfig.from_path(rules) if rules.exists() else ScanConfig.empty()
        findings = scan(
            case_dir / "src",
            config=config,
            cache_root=scan_cache if scan_cache is not None else case_dir / ".cache",
        )
        return render_text(findings) + "\n"

    if analysis == "xcontract":
        from tealtools.xcontract import (
            XContractGraph,
            cross_auth_findings,
            load_registry,
            render_caller_feedback,
            render_findings,
            render_xcontract,
        )

        registry = load_registry(case_dir / "registry.yml")
        caller_prog = SSAProgram(str(case_dir / "caller" / "db"))
        graph = XContractGraph.build(caller_prog, registry)
        findings = cross_auth_findings(graph)
        body = render_xcontract(graph.sites, graph.analyses, relative_to=case_dir)
        body += "\n\ncross-contract auth-domination findings:\n"
        body += render_findings(graph, findings, relative_to=case_dir)
        body += "\n\ncaller predicates with callee-summary feedback:\n"
        body += render_caller_feedback(graph, relative_to=case_dir)
        return body + "\n"

    if analysis == "xcontract_sec_guide":
        from tealtools.xcontract import XContractGraph, load_registry, render_xcontract
        from tealtools.detections.xcontract import (
            cross_detection_findings,
            render_findings as render_sg_findings,
        )

        registry = load_registry(case_dir / "registry.yml")
        caller_prog = SSAProgram(str(case_dir / "caller" / "db"))
        graph = XContractGraph.build(caller_prog, registry)
        findings = cross_detection_findings(graph)
        body = render_xcontract(graph.sites, graph.analyses, relative_to=case_dir)
        body += "\n\ncross-contract sec-guide findings:\n"
        body += render_sg_findings(graph, findings, relative_to=case_dir)
        return body + "\n"

    prog = SSAProgram(str(case_dir / "db"))

    if analysis == "auth_domination":
        from tealtools.auth_domination import AuthDominationDetector

        violations = AuthDominationDetector(prog).detect()
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis == "box_key":
        from tealtools.detections import NonUniqueBoxKeyDetector

        violations = NonUniqueBoxKeyDetector(prog).detect()
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis == "box_df":
        from tealtools.dataflow.box import (
            detect_correlated_flows,
            detect_into_box_flows,
            detect_out_of_box_flows,
        )
        from tealtools.dataflow.predicate_aware import filter_validated

        case_name = case_dir.name
        if case_name.startswith("key_correlated"):
            # CorrelatedViolation has a different shape; predicate-
            # aware filtering for chains is a future iteration.
            violations = detect_correlated_flows(prog)
            body = "\n".join(v.pretty() for v in violations) or "(no violations)"
            return body + "\n"
        if case_name.startswith("out_"):
            raw = detect_out_of_box_flows(prog)
        else:
            raw = detect_into_box_flows(prog)
        remaining, suppressed = filter_validated(raw, prog)
        parts: list[str] = []
        if remaining:
            parts.append("\n".join(v.pretty() for v in remaining))
        elif not suppressed:
            parts.append("(no violations)")
        if suppressed:
            parts.append(
                "suppressed:\n  "
                + "\n  ".join(s.pretty() for s in suppressed)
            )
        return "\n".join(parts) + "\n"

    if analysis == "itxn_report":
        from tealtools.inner_txn_report import InnerTxnReport

        return InnerTxnReport(prog).render() + "\n"

    if analysis.startswith("path_predicates"):
        from tealtools.path_predicates import PathPredicateAnalysis

        return PathPredicateAnalysis(prog).render() + "\n"

    if analysis == "group_shape":
        from tealtools.group_reasoning import analyze

        return analyze(prog).render() + "\n"

    if analysis == "cost":
        from tealtools.cost_analysis import render

        return render(prog) + "\n"

    if analysis == "cfg":
        from tealtools.cfg import CFG

        # Skeleton form: structural BB labels + edges only. Stable
        # under cosmetic opcode-label changes.
        return CFG.of(prog).to_dot(with_assignments=False) + "\n"

    if analysis == "sec_guide":
        # Detection name is the parent dir of the case dir, snake-case;
        # map back to the kebab-case keys in `detections.DETECTORS`.
        # Each fixture dir is named for the detection it exercises, so
        # the detector runs directly — no program-mode gating here.
        from tealtools.detections import DETECTORS

        detection = case_dir.parent.name.replace("_", "-")
        if detection not in DETECTORS:
            raise NotImplementedError(
                f"no detection registered for {detection!r}"
            )
        cls = DETECTORS[detection]
        violations = cls(prog).detect()
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis in SSA_SMOKE:
        return _ssa_summary(prog)

    raise NotImplementedError(f"no analysis dispatch for {analysis!r}")


@pytest.mark.parametrize("analysis,case_dir", list(_discover()))
def test_snapshot(analysis: str, case_dir: Path, scan_cache: Path) -> None:
    actual = _render(analysis, case_dir, scan_cache=scan_cache)
    expected_path = case_dir / "expected.txt"

    if UPDATE or not expected_path.exists():
        expected_path.write_text(actual)
        if not UPDATE:
            pytest.skip(f"created baseline at {expected_path.relative_to(PY_TESTS.parent.parent)}")
        return

    expected = expected_path.read_text()
    if actual == expected:
        return

    diff = "\n".join(
        difflib.unified_diff(
            expected.splitlines(),
            actual.splitlines(),
            fromfile=str(expected_path.name) + " (expected)",
            tofile="actual",
            lineterm="",
        )
    )
    pytest.fail(
        f"snapshot mismatch for {case_dir.relative_to(PY_TESTS)}:\n{diff}\n\n"
        "Re-run with UPDATE_SNAPSHOTS=1 to refresh."
    )
