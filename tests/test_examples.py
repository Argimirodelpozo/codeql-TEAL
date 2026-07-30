"""The shipped examples must actually run.

``examples/algoplonk/run_rekey_demo.py`` sat broken in the repo for an unknown
stretch, calling ``SSAProgram(db_dir, verbose=False)`` and ``PySSA.build`` — a
CodeQL-era signature and a two-step reconstruction, both long gone. Nothing
executed it, so nothing noticed. Its committed reports still read as current
because they were generated before the rot.

An example nobody runs is worse than no example: it is documentation that lies.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DEMO = REPO / "examples" / "algoplonk" / "run_rekey_demo.py"


@pytest.fixture(scope="module")
def demo_run():
    """Run the demo in a subprocess, exactly as a user would."""
    if not DEMO.exists():
        pytest.skip("algoplonk example not present")
    r = subprocess.run([sys.executable, str(DEMO)],
                       capture_output=True, text=True, cwd=REPO, timeout=600)
    assert r.returncode == 0, f"the demo failed:\n{r.stdout}\n{r.stderr}"
    return r


def test_demo_runs_and_finds_the_rekey_bug(demo_run):
    """The whole point of the example: the pre-fix logicsig is vulnerable and
    the post-fix one is not. If that inverts, the example is teaching the
    opposite of what it claims."""
    assert "vuln=1" in demo_run.stdout, demo_run.stdout
    assert "fixed=0" in demo_run.stdout, demo_run.stdout
    assert "(OK)" in demo_run.stdout, demo_run.stdout


def test_demo_uses_no_removed_api():
    """The specific rot: a signature that no longer exists. Cheaper to pin than
    to rediscover.

    Checks CODE, not the raw text — the module docstring names both removed
    APIs while explaining why this test exists, and a substring scan flags its
    own explanation."""
    import ast

    tree = ast.parse(DEMO.read_text())
    if (tree.body and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)):
        tree.body.pop(0)                       # drop the module docstring
    code = ast.unparse(tree)
    for gone in ("verbose=", "PySSA"):
        assert gone not in code, f"{gone!r} is a removed API"


@pytest.mark.parametrize("kind,expected", [("vuln", 1), ("fixed", 0)])
def test_committed_reports_match_what_the_demo_now_produces(
        demo_run, kind, expected):
    """The reports are checked in, so a drifted one is a stale claim in the
    repo. The demo rewrites them, so after running they must agree."""
    rpt = REPO / "examples" / "algoplonk" / f"{kind}_rekey_report.txt"
    text = rpt.read_text()
    assert f"# Violations: {expected}" in text, text[:200]
    # and the header must name a real path, not the deleted CodeQL db/ dir
    assert "DB:" not in text, "report header still references the removed db/ layout"
