"""The detector / analysis path must import and run WITHOUT the puya package.

puya (the ``puyapy`` distribution) is an optional ``[lift]`` extra: it lowers
the pre-IR to genuine ``puya.ir.models``, which only decompilation needs. The
interprocedural lifted detectors run their taint on the puya-free pre-IR, so a
``pip install tealql`` with no puya must still give full detection.

These run in subprocesses with puya import blocked via a meta_path finder, so
the guarantee is tested even in an environment where puya IS installed.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("puya")  # if puya isn't here, the blocking test is moot


def _run_without_puya(body: str) -> subprocess.CompletedProcess:
    prelude = textwrap.dedent("""
        import sys
        class _Block:
            def find_spec(self, name, path=None, target=None):
                if name == "puya" or name.startswith("puya."):
                    raise ImportError(f"blocked: {name}")
                return None
        sys.meta_path.insert(0, _Block())
        try:
            import puya
            raise SystemExit("puya not actually blocked")
        except ImportError:
            pass
    """)
    return subprocess.run(
        [sys.executable, "-c", prelude + textwrap.dedent(body)],
        capture_output=True, text=True,
    )


def test_lift_package_imports_without_puya():
    r = _run_without_puya("""
        from tealql.tealtools.lift.lift import _Lifter
        import tealql.tealtools.lift
        print("OK")
    """)
    assert r.returncode == 0, r.stderr
    assert "OK" in r.stdout


def test_lifted_detectors_run_without_puya():
    r = _run_without_puya("""
        from tealql.tealtools.ssa import SSAProgram
        from tealql.security import DETECTORS
        prog = SSAProgram("tests/benchmark/tainted-fund-flow/vuln/unguarded_receiver.teal")
        n = len(DETECTORS["tainted-fund-flow"](prog).detect())
        print("FINDINGS", n)
    """)
    assert r.returncode == 0, r.stderr
    # The IR taint runs on the puya-free pre-IR, so the vuln is still caught.
    assert "FINDINGS 1" in r.stdout


def test_render_requires_puya_cleanly():
    # Accessing `render` triggers the lazy puya import; without puya that
    # must be a clean ImportError (raised at attribute access), not a crash.
    r = _run_without_puya("""
        try:
            from tealql.tealtools.lift import render
            print("NO-ERROR")
        except ImportError:
            print("CLEAN-IMPORTERROR")
    """)
    assert r.returncode == 0, r.stderr
    assert "CLEAN-IMPORTERROR" in r.stdout


def test_lifted_findings_identical_with_and_without_puya():
    probe = """
        from tealql.tealtools.ssa import SSAProgram
        from tealql.security import DETECTORS
        import glob
        for f in sorted(glob.glob("tests/benchmark/tainted-fund-flow/vuln/*.teal")):
            prog = SSAProgram(f)
            for d in ("tainted-fund-flow", "partial-tainted-fund-flow"):
                print(f.split("/")[-1], d, len(DETECTORS[d](prog).detect()))
    """
    with_puya = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(probe)],
        capture_output=True, text=True)
    without_puya = _run_without_puya(probe)
    assert with_puya.returncode == 0, with_puya.stderr
    assert without_puya.returncode == 0, without_puya.stderr
    assert with_puya.stdout == without_puya.stdout
    assert with_puya.stdout.strip()
