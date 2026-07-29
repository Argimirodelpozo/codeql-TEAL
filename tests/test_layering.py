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


# ---------------------------------------------------------------------------
# Package dependency direction
# ---------------------------------------------------------------------------


def test_tealtools_never_imports_security():
    """``security`` builds on ``tealtools``; the arrow never points back.

    ``tealtools`` is the reusable AVM substrate (parse, CFG, SSA, dataflow,
    lift) and ``security`` is one consumer of it. A single reverse import makes
    the substrate un-vendorable without dragging every detector along, and the
    cycle it creates is the kind that only shows up as an import-order bug
    months later.

    Checked by reading source, not by importing: a lazy ``import`` inside a
    function body is exactly as much of a cycle as a top-level one, and an
    import probe would never execute it."""
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "src"
    root = src / "tealql" / "tealtools"
    offenders = []
    for py in sorted(root.rglob("*.py")):
        # Dotted package path of the file's OWN package, so relative imports
        # can be resolved: src/tealql/tealtools/dataflow/x.py -> tealql.tealtools.dataflow
        pkg = py.relative_to(src).with_suffix("").parts
        pkg = pkg[:-1] if py.name == "__init__.py" else pkg[:-1]
        tree = ast.parse(py.read_text(), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                targets = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    # `from ...security import x` is level=3, module='security'
                    base = pkg[:len(pkg) - node.level + 1]
                    targets = [".".join((*base, node.module) if node.module else base)]
                else:
                    targets = [node.module or ""]
            else:
                continue
            for n in targets:
                if n == "tealql.security" or n.startswith("tealql.security."):
                    rel = py.relative_to(src)
                    offenders.append(f"{rel}:{node.lineno} imports {n}")

    assert not offenders, (
        "tealtools must not import security -- dependency direction is "
        "security -> tealtools, never the reverse:\n  "
        + "\n  ".join(offenders))
