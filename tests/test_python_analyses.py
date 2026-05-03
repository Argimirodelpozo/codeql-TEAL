"""Snapshot harness for the python-analysis detectors.

Discovers fixtures under ``tests/python/<analysis>/[<case>/]db/`` and
runs the matching analysis against each. Output is compared to a
checked-in ``expected.txt`` next to the fixture; mismatches fail the
test with a unified diff.

Regenerate snapshots with::

    UPDATE_SNAPSHOTS=1 pytest tests/test_python_analyses.py
"""
import difflib
import os
from collections import Counter
from pathlib import Path

import pytest

PY_TESTS = Path(__file__).resolve().parent / "python"
UPDATE = os.environ.get("UPDATE_SNAPSHOTS") == "1"

# Fixture dirs without a detector — exercised as SSA construction
# smoke tests (snapshot a structural summary).
SSA_SMOKE = {"loop_dig_deep", "loop_frame_dig", "stack_growing_loop"}


XC_ROOT = PY_TESTS / "xcontract"


def _discover():
    # xcontract cases own a multi-DB layout (caller/db, callee/db); the
    # case_dir is the parent of those, not the parent of any one db/.
    if XC_ROOT.exists():
        for case in sorted(p for p in XC_ROOT.iterdir() if p.is_dir()):
            yield pytest.param("xcontract", case, id=f"xcontract/{case.name}")
    for db_yml in sorted(PY_TESTS.rglob("codeql-database.yml")):
        case_dir = db_yml.parent.parent
        if XC_ROOT in case_dir.parents or case_dir == XC_ROOT:
            continue  # already collected as a single xcontract case
        rel = case_dir.relative_to(PY_TESTS)
        analysis = rel.parts[0]
        yield pytest.param(analysis, case_dir, id=str(rel))


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


def _render(analysis: str, case_dir: Path) -> str:
    from teal_ssa import SSAProgram

    if analysis == "xcontract":
        from teal_xcontract import (
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

    prog = SSAProgram(str(case_dir / "db"))

    if analysis == "auth_domination":
        from teal_auth_domination import AuthDominationDetector

        violations = AuthDominationDetector(prog).detect()
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis == "box_key":
        from teal_nonunique_box_key import NonUniqueBoxKeyDetector

        violations = NonUniqueBoxKeyDetector(prog).detect()
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis == "box_df":
        from teal_box_dataflow import (
            detect_correlated_flows,
            detect_into_box_flows,
            detect_out_of_box_flows,
        )

        case_name = case_dir.name
        if case_name.startswith("out_"):
            violations = detect_out_of_box_flows(prog)
        elif case_name.startswith("key_correlated"):
            violations = detect_correlated_flows(prog)
        else:
            violations = detect_into_box_flows(prog)
        body = "\n".join(v.pretty() for v in violations) or "(no violations)"
        return body + "\n"

    if analysis == "itxn_report":
        from teal_inner_txn_report import InnerTxnReport

        return InnerTxnReport(prog).render() + "\n"

    if analysis.startswith("path_predicates"):
        from teal_path_predicates import PathPredicateAnalysis

        return PathPredicateAnalysis(prog).render() + "\n"

    if analysis == "group_shape":
        from teal_group_reasoning import analyze

        return analyze(prog).render() + "\n"

    if analysis in SSA_SMOKE:
        return _ssa_summary(prog)

    raise NotImplementedError(f"no analysis dispatch for {analysis!r}")


@pytest.mark.parametrize("analysis,case_dir", list(_discover()))
def test_snapshot(analysis: str, case_dir: Path) -> None:
    if "CODEQL" not in os.environ:
        pytest.skip("CODEQL env var not set")

    actual = _render(analysis, case_dir)
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
