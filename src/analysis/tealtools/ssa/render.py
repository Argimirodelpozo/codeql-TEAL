"""Rendering / view-construction for SSAProgram.

The textual functional dump (:func:`functional` / :func:`functional_by_block`),
the data-dependency and CFG view graphs (:func:`data_graph` / :func:`cfg`),
and the Graphviz DOT emitter (:func:`to_dot`) for a reconstructed program.

Bridged from the same-named ``SSAProgram`` methods so ``prog.functional()``
etc. keep working unchanged; ``draw`` / ``print_functional`` stay on the class
as thin composers over these.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

import networkx as nx

from ..dot import escape
from .models import BasicBlock, Const

if TYPE_CHECKING:
    from .program import SSAProgram


def functional(
    prog: "SSAProgram",
    *,
    file: Optional[str] = None,
    line_range: Optional[tuple[int, int]] = None,
    resolve_consts: bool = True,
    propagate_consts: bool = True,
    show_ranges: bool = False,
) -> str:
    # Merge labels and assignments by (file, line). Labels carry no SSA effect,
    # so the kind tiebreaker (0 label, 1 assignment) sorts labels above
    # assignments at the same line — matching the source layout.
    items: list[tuple] = []
    for lbl_file, lbl_line, lbl_code in prog.labels:
        if file is not None and lbl_file != file:
            continue
        if line_range is not None and not (line_range[0] <= lbl_line <= line_range[1]):
            continue
        items.append((lbl_file, lbl_line, 0, lbl_code))
    for a in prog.assignments_in(file=file, line_range=line_range):
        items.append((a.location.file, a.location.line, 1, a))
    items.sort(key=lambda x: (x[0], x[1], x[2]))

    lines = []
    for _, line, kind, obj in items:
        if kind == 0:  # Label
            lines.append(f"L{line:>4}: {obj}")
        else:
            lines.append(
                f"L{line:>4}: "
                f"{obj.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
            )
    return "\n".join(lines)


def functional_by_block(
    prog: "SSAProgram",
    *,
    file: Optional[str] = None,
    resolve_consts: bool = True,
    propagate_consts: bool = True,
    show_ranges: bool = False,
) -> str:
    """Same as :func:`functional` but groups assignments by BB with a header
    line and predecessor/successor summary per block."""
    blocks = sorted(
        (bb for bb in prog.blocks.values() if file is None or bb.file == file),
        key=lambda bb: (bb.file, bb.first_line),
    )
    out = []
    for bb in blocks:
        preds = ", ".join(f"L{p.first_line}" for p in bb.predecessors) or "-"
        succs = ", ".join(f"L{s.first_line}" for s in bb.successors) or "-"
        out.append(f"# {bb}  preds=[{preds}] succs=[{succs}]")
        for p in bb.phis:
            out.append(f"  {p.kind[0]}_{p.stack_index} = {p!r}")
        for a in bb.assignments:
            out.append(
                f"  L{a.location.line:>4}: "
                f"{a.functional(resolve_consts=resolve_consts, propagate_consts=propagate_consts, show_ranges=show_ranges)}"
            )
        out.append("")
    return "\n".join(out)


def data_graph(prog: "SSAProgram") -> nx.MultiDiGraph:
    """Data-dependency graph over SSA objects (Assignment / SSAVar / Phi)
    with def / use / phi_in edges."""
    h = nx.MultiDiGraph()
    for a in prog.assignments:
        h.add_node(a)
        for v in a.outputs:
            h.add_node(v)
            h.add_edge(a, v, kind="def")
        for inp in a.inputs:
            if isinstance(inp, Const):
                continue
            h.add_node(inp)
            h.add_edge(inp, a, kind="use")
    for p in prog.phis.values():
        h.add_node(p)
        for arg in p.args:
            if isinstance(arg, Const):
                continue
            h.add_node(arg)
            h.add_edge(arg, p, kind="phi_in")
    return h


def cfg(prog: "SSAProgram") -> nx.MultiDiGraph:
    """Basic-block CFG: nodes are BasicBlock, edges are pred → succ."""
    h = nx.MultiDiGraph()
    for bb in prog.blocks.values():
        h.add_node(bb)
    for bb in prog.blocks.values():
        for succ in bb.successors:
            h.add_edge(bb, succ)
    return h


def to_dot(
    prog: "SSAProgram",
    *,
    file: Optional[str] = None,
    resolve_consts: bool = True,
    rankdir: str = "TB",
    max_lines_per_bb: int = 80,
) -> str:
    """Emit Graphviz DOT: one rounded box per BB, labeled with entry phis +
    functional assignments; edges are pred → succ."""

    def _bb_id(bb: BasicBlock) -> str:
        return f'"BB_{bb.file}_{bb.first_line}_{bb.last_line}"'

    def _bb_label(bb: BasicBlock) -> str:
        header = f"BB L{bb.first_line}-L{bb.last_line}"
        lines_out = [header]
        for phi in bb.phis:
            lines_out.append(f"  φ_{phi.stack_index}[{phi.kind[0]}] = {repr(phi)}")
        for a in bb.assignments:
            lines_out.append(f"  L{a.location.line:>4}: {a.functional(resolve_consts=resolve_consts)}")
        if len(lines_out) > max_lines_per_bb:
            elided = len(lines_out) - (max_lines_per_bb - 1)
            lines_out = lines_out[: max_lines_per_bb - 1] + [f"  ... (+{elided} more)"]
        return "\\l".join(lines_out) + "\\l"

    blocks = [
        bb for bb in prog.blocks.values()
        if file is None or bb.file == file
    ]
    blocks.sort(key=lambda bb: (bb.file, bb.first_line))

    out = [
        "digraph TEAL_SSA {",
        f"  rankdir={rankdir};",
        "  overlap=false;",
        "  splines=true;",
        '  node [shape=box, fontname="Monospace", fontsize=9];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    node_set = set(blocks)
    for bb in blocks:
        attrs = (
            f'label="{escape(_bb_label(bb))}", '
            'style="rounded,filled", fillcolor="#f4f4f8"'
        )
        out.append(f"  {_bb_id(bb)} [{attrs}];")
    seen = set()
    for bb in blocks:
        for succ in bb.successors:
            if succ not in node_set:
                continue
            pair = (bb, succ)
            if pair in seen:
                continue
            seen.add(pair)
            out.append(f"  {_bb_id(bb)} -> {_bb_id(succ)};")
    out.append("}")
    return "\n".join(out)
