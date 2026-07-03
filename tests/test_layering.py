"""Architectural guard: the substrate must not import the analysis layer.

The per-program CFG + dominance in :mod:`tealql.tealtools.cfg` are substrate.
:class:`SuperCFG` / :mod:`super_auth` are cross-contract ANALYSES that
import :mod:`tealql.tealtools.xcontract` (which pulls auth_domination,
inner_txn_report). They live in the cfg/ folder but are re-exported
lazily, so importing the substrate CFG package must NOT drag the analysis
layer in. This test pins that — reintroducing an eager
``from .supercfg import …`` in ``cfg/__init__`` fails here.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap


def _fresh_import_probe(body: str) -> str:
    r = subprocess.run([sys.executable, "-c", textwrap.dedent(body)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout


def test_substrate_cfg_does_not_pull_supercfg():
    out = _fresh_import_probe("""
        import sys
        import tealql.tealtools.cfg   # substrate package
        from tealql.tealtools.cfg import CFG
        from tealql.tealtools.cfg.dominance import iterative_dominators
        pulled = [m for m in (
            "tealql.tealtools.cfg.supercfg", "tealql.tealtools.cfg.super_auth")
            if m in sys.modules]
        print(",".join(pulled) or "CLEAN")
    """)
    assert out.strip() == "CLEAN", f"substrate cfg eager-loaded: {out!r}"


def test_supercfg_still_importable_lazily():
    out = _fresh_import_probe("""
        from tealql.tealtools.cfg import SuperCFG, SuperBlock, SuperEdge
        print(SuperCFG.__name__)
    """)
    assert out.strip() == "SuperCFG"
