"""Dump EVERY representation of a TEAL contract — a one-shot debugging view of
the whole pipeline.

:func:`dump_all` builds a labeled text report walking each layer
(source → graph → CFG → SSA → structure → control tree → path predicates →
inner-txn report → Puya IR) and, when ``out_dir`` is given, writes it to
``contract.txt`` plus the graph-shaped layers (graph / CFG / SSA / control-tree)
as ``.svg`` (or ``.dot`` if Graphviz's ``dot`` binary isn't on PATH).

Each layer is best-effort: a representation that fails to build (e.g. a contract
that doesn't lift) is reported as ``(unavailable: …)`` and the rest still dump.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..ssa import SSAProgram
from ..ssa import render as _ssa_render
from ..cfg import CFG
from ..graph import load_graph
from ..structure import analyze_structure
from ..control_tree import build_control_tree, pretty as _ct_pretty
from ..path_predicates import PathPredicateAnalysis
from ..inner_txn_report import InnerTxnReport
from .._utils.dot import render as _dot_render
from . import render as _viz


def dump_all(source, out_dir: Optional[str] = None, *, svg: bool = True) -> str:
    """Return a labeled text dump of every representation of ``source`` (a
    ``.teal`` file, a directory of them, or an in-memory ``{name: text}`` map).
    When ``out_dir`` is given, also write ``contract.txt`` + the graph-shaped
    layers as ``.svg``/``.dot`` there."""
    prog = SSAProgram(source, verbose=False)
    prog.propagate_constants()

    parts: list[str] = []

    def add(title, fn):
        try:
            body = fn() or "(empty)"
        except Exception as e:                    # best-effort per layer
            body = f"(unavailable: {type(e).__name__}: {e})"
        parts.append(_section(title, body))

    add("SOURCE (normalized TEAL)", lambda: _source_text(source))
    add("GRAPH (AST nodes + edges)", lambda: _graph_text(source))
    add("CFG (basic blocks)", lambda: _cfg_text(prog))
    add("SSA (functional, by block)", lambda: _ssa_render.functional_by_block(prog))
    add("STRUCTURE (subs / routing / handlers)", lambda: analyze_structure(prog).render())
    add("CONTROL TREE (region tree)", lambda: _ct_pretty(build_control_tree(prog)))
    add("PATH PREDICATES", lambda: PathPredicateAnalysis(prog).render())
    add("INNER-TXN REPORT", lambda: InnerTxnReport(prog).render())
    add("PUYA IR (lift)", lambda: _ir_text(source))

    text = "\n\n".join(parts) + "\n"
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "contract.txt").write_text(text)
        _write_graphs(out, prog, source, svg=svg)
    return text


# --- text sections ------------------------------------------------------


def _section(title: str, body: str) -> str:
    bar = "=" * 72
    return f"{bar}\n=== {title}\n{bar}\n{body}"


def _source_text(source) -> str:
    if isinstance(source, dict):
        return "\n\n".join(f"# {n}\n{t}" for n, t in source.items())
    p = Path(source)
    if p.is_file():
        return p.read_text()
    if p.is_dir():
        return "\n\n".join(f"# {f.name}\n{f.read_text()}"
                           for f in sorted(p.glob("*.teal")))
    return str(source)


def _graph_text(source) -> str:
    g = load_graph(source, verbose=False)
    nodes = sorted(g.nodes, key=lambda n: (getattr(n, "file", ""), getattr(n, "line", 0)))
    head = f"{g.number_of_nodes()} nodes, {g.number_of_edges()} edges\n"
    return head + "\n".join(repr(n) for n in nodes)


def _cfg_text(prog: SSAProgram) -> str:
    cfg = CFG.of(prog)
    lines = []
    for bb in cfg.blocks:
        succs = ", ".join(f"L{s.first_line}" for s in bb.successors) or "-"
        lines.append(f"BB L{bb.first_line}-L{bb.last_line}  ->  [{succs}]")
    return "\n".join(lines)


def _ir_text(source) -> str:
    from ..WIP_lift2puyaIR.lift import _Lifter
    lifter = _Lifter(SSAProgram(source, verbose=False))   # fresh prog (lift mutates)
    lifter.build()
    return "\n\n".join(s.render() for s in lifter.subs)


# --- graphviz files -----------------------------------------------------


def _write_graphs(out: Path, prog: SSAProgram, source, *, svg: bool) -> None:
    def emit(name: str, dot: str) -> None:
        if svg:
            try:
                (out / f"{name}.svg").write_bytes(bytes(_dot_render(dot)))
                return
            except Exception:
                pass                              # no `dot` on PATH -> .dot fallback
        (out / f"{name}.dot").write_text(dot)

    for name, build in (
        ("graph", lambda: _viz.to_dot(load_graph(source, verbose=False))),
        ("cfg", lambda: CFG.of(prog).to_dot()),
        ("ssa", lambda: _ssa_render.to_dot(prog)),
        ("control_tree", lambda: _viz.region_to_dot(build_control_tree(prog))),
    ):
        try:
            emit(name, build())
        except Exception:
            pass                                  # layer failed -> skip its file
