"""Smoke test: real mainnet contracts at least lift to real Puya IR.

The ``.teal`` under ``tests/experimental_IR_lift/explorer/`` were disassembled
from on-chain bytecode of randomly-sampled, actively-called mainnet apps (algod
``/v2/teal/disassemble``) -- a deliberately diverse set: many source compilers
and ``#pragma version`` 2..11, not just puya output. This is NOT a gating
correctness test (real-world TEAL hits known reconstruction limits, and very
large programs are slow in PySSA construction). It asserts the WIP lift handles
real input *robustly* -- a healthy majority lift to real Puya IR, and nothing
crashes or hangs the harness -- and prints the breakdown so the coverage is
visible. See ``project_puya_corpus_lift`` for the puya-corpus (248/248) result.

Each contract is lifted in its own subprocess with a hard timeout, so a program
that is merely slow to reconstruct (a known PySSA perf limit on 2000+ line
contracts) is recorded as ``slow``, never hanging pytest.
"""
from __future__ import annotations

import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
EXPLORER = REPO / "tests" / "experimental_IR_lift" / "explorer"
SRC = REPO / "src" / "analysis"
PER_CONTRACT_TIMEOUT = 90          # seconds; subprocess hard-killed past this

_CONTRACTS = sorted(EXPLORER.glob("app_*/")) if EXPLORER.exists() else []

# Lift one DB to real Puya IR (lower + Puya optimise) in a clean subprocess.
_LIFT = """
import sys, io, contextlib
sys.path.insert(0, {src!r})
from puya.log import configure_logging, LogLevel
configure_logging(min_log_level=LogLevel.critical)
from tealtools.ssa import SSAProgram
from tealtools.WIP_lift2puyaIR import to_puya_ir
p = SSAProgram({db!r}, verbose=False)
p.propagate_constants()
with contextlib.redirect_stdout(io.StringIO()):
    text = to_puya_ir.render(p, optimize_ir=True)
print("LIFTED", len(text.splitlines()))
"""


def _codeql() -> str | None:
    return os.environ.get("CODEQL") or __import__("shutil").which("codeql")


def _lift(db: Path) -> tuple[str, str]:
    """Return (status, detail). status in {ok, failed, slow, crash}."""
    try:
        r = subprocess.run(
            [sys.executable, "-c", _LIFT.format(src=str(SRC), db=str(db))],
            capture_output=True, text=True, timeout=PER_CONTRACT_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return "slow", f">{PER_CONTRACT_TIMEOUT}s (PySSA construction)"
    if r.returncode == 0 and "LIFTED" in r.stdout:
        return "ok", r.stdout.strip().split("\n")[-1]
    # a clean, expected reconstruction-limit failure (CodeError/InternalError/...)
    last = (r.stderr.strip().splitlines() or [""])[-1]
    if any(k in r.stderr for k in ("CodeError", "InternalError", "ValueError",
                                   "KeyError", "TypeError", "AssertionError")):
        return "failed", last[:120]
    return "crash", last[:200]


@pytest.mark.skipif(_codeql() is None, reason="codeql binary not available")
@pytest.mark.skipif(not _CONTRACTS, reason="no explorer contracts checked in")
def test_real_contracts_lift():
    from build_dbs import build_db

    results: dict[str, tuple[str, str]] = {}
    for d in _CONTRACTS:
        teal = next(d.glob("*.teal"))
        build_db(teal)                              # cached; builds if missing
        results[d.name] = _lift(d / "db")

    counts = Counter(s for s, _ in results.values())
    print(f"\n=== explorer lift: {len(results)} real mainnet contracts ===")
    for name, (status, detail) in sorted(results.items()):
        print(f"  {status:6} {name:18} {detail}")
    print(f"  -> {dict(counts)}")

    # Robustness: nothing may crash the harness with an unexpected error type.
    crashes = [n for n, (s, _) in results.items() if s == "crash"]
    assert not crashes, f"lift crashed (unexpected error) on: {crashes}"

    # Coverage: a healthy majority of the contracts that PySSA can reconstruct
    # in time must lift all the way to real Puya IR.
    completed = counts["ok"] + counts["failed"]
    assert completed, "no contract completed reconstruction"
    assert counts["ok"] / completed >= 0.5, (
        f"only {counts['ok']}/{completed} real contracts lifted "
        f"(< 50%): {dict(counts)}"
    )
