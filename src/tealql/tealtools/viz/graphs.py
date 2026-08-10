"""Shared DOT renderers for analysis products that are graph-shaped.

The representation-specific graph classes keep their own renderers. This
module supplies the adapters the analysis catalog needs repeatedly:

* annotate the canonical basic-block CFG with facts or verdicts; and
* render arbitrary composite analysis graphs; and
* render the retained construction SSA / mutable pre-IR control graphs.

Keeping those adapters here prevents every analysis from inventing subtly
different node identities, escaping, and successor handling merely to make a
debugging picture.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .._utils.dot import escape


def _lines(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return value.splitlines()
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return [str(value)]


def annotated_cfg_dot(
    prog,
    annotations: Mapping[object, object] | None = None,
    *,
    title: str = "TEAL analysis",
    rankdir: str = "TB",
) -> str:
    """Render the program CFG with analysis evidence inside each block.

    ``annotations`` is keyed by the actual ``BasicBlock`` object.  Values may
    be one string or an iterable of lines.  Empty blocks remain visible: an
    absence of evidence must not look like an analysis that skipped the block.
    """
    annotations = annotations or {}
    blocks = sorted(prog.blocks.values(), key=lambda b: (b.file, b.first_line))

    def node_id(bb) -> str:
        return '"' + escape(f"BB:{bb.file}:{bb.first_line}-{bb.last_line}") + '"'

    out = [
        "digraph TEAL_ANALYSIS {",
        f"  rankdir={rankdir};",
        f'  label="{escape(title)}"; labelloc=t; fontsize=18;',
        "  overlap=false; splines=true;",
        '  node [shape=box, style="rounded,filled", fillcolor="#f6f6f8", '
        'fontname="Monospace", fontsize=9];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    shown = set(blocks)
    for bb in blocks:
        body = [f"BB L{bb.first_line}-L{bb.last_line}", *_lines(annotations.get(bb))]
        label = "\\l".join(escape(line) for line in body) + "\\l"
        attrs = []
        if annotations.get(bb):
            attrs.extend(['fillcolor="#fff4cc"', 'color="#b7791f"'])
        extra = f", {', '.join(attrs)}" if attrs else ""
        out.append(f"  {node_id(bb)} [label=\"{label}\"{extra}];")
    for bb in blocks:
        for successor in bb.successors:
            if successor in shown:
                out.append(f"  {node_id(bb)} -> {node_id(successor)};")
    out.append("}")
    return "\n".join(out)


def networkx_to_dot(graph, *, title: str, rankdir: str = "LR") -> str:
    """Render an arbitrary analysis graph with stable ``repr`` node labels."""
    nodes = sorted(graph.nodes, key=repr)

    def node_id(node) -> str:
        return '"' + escape(f"node:{repr(node)}") + '"'

    out = [
        "digraph ANALYSIS_GRAPH {",
        f"  rankdir={rankdir};",
        f'  label="{escape(title)}"; labelloc=t; fontsize=18;',
        '  node [shape=box, style="rounded,filled", fillcolor="#f6f6f8", '
        'fontname="Monospace", fontsize=9];',
        '  edge [fontname="Monospace", fontsize=8];',
    ]
    for node in nodes:
        out.append(f'  {node_id(node)} [label="{escape(repr(node))}"];')
    for source, target, data in graph.edges(data=True):
        kinds = data.get("kinds", ())
        label = ",".join(sorted(map(str, kinds))) if kinds else ""
        out.append(
            f'  {node_id(source)} -> {node_id(target)} [label="{escape(label)}"];'
        )
    out.append("}")
    return "\n".join(out)


def pyssa_to_dot(pyssa, *, rankdir: str = "TB") -> str:
    """Render the retained construction-time ``PySSA`` block graph."""

    def node_id(block) -> str:
        file, first, last = block.key
        return '"' + escape(f"PYSSA:{file}:{first}-{last}") + '"'

    def operand(value) -> str:
        if value is None:
            return "?"
        if hasattr(value, "slot") and hasattr(value, "bb_key"):
            return f"phi[{value.slot}]@L{value.bb_key[1]}"
        if hasattr(value, "idx") and hasattr(value, "line"):
            return f"v{value.idx}@L{value.line}"
        return repr(value)

    out = [
        "digraph PYSSA {",
        f"  rankdir={rankdir};",
        '  label="construction SSA (PySSA)"; labelloc=t; fontsize=18;',
        '  node [shape=box, style="rounded,filled", fillcolor="#edf7ed", '
        'fontname="Monospace", fontsize=9];',
    ]
    shown = set(pyssa.blocks)
    for block in pyssa.blocks:
        lines = [f"BB L{block.key[1]}-L{block.key[2]}"]
        for phi in sorted(block.entry_phis, key=lambda item: item.slot):
            lines.append(
                f"phi[{phi.slot}] = " + ", ".join(operand(arg) for arg in phi.args)
            )
        for op in block.ops:
            lhs = ", ".join(operand(value) for value in op.outputs)
            rhs = " ".join(x for x in (op.op, op.immediates) if x)
            args = ", ".join(operand(value) for value in op.inputs)
            lines.append(f"L{op.line}: {lhs + ' = ' if lhs else ''}{rhs}({args})")
        label = "\\l".join(escape(line) for line in lines) + "\\l"
        out.append(f'  {node_id(block)} [label="{label}"];')
    for block in pyssa.blocks:
        for successor in block.succs:
            if successor in shown:
                out.append(f"  {node_id(block)} -> {node_id(successor)};")
    out.append("}")
    return "\n".join(out)


def pre_ir_to_dot(program, *, title: str = "pre-IR", rankdir: str = "TB") -> str:
    """Render a :mod:`tealtools.lift.pre_ir` program without lowering it.

    Block ids are globally unique in this representation, but subroutine
    clusters preserve ownership and make cross-subroutine edges conspicuous.
    """
    from ..lift import pre_ir

    def node_id(sub, block) -> str:
        return '"' + escape(f"IR:{sub.id}:{block.id}") + '"'

    subroutines = [program.main, *program.subroutines]
    owner = {block.id: sub for sub in subroutines for block in sub.body}
    by_id = {block.id: block for sub in subroutines for block in sub.body}
    out = [
        "digraph PRE_IR {",
        f"  rankdir={rankdir};",
        f'  label="{escape(title)}"; labelloc=t; fontsize=18;',
        "  compound=true; overlap=false; splines=true;",
        '  node [shape=box, style="rounded,filled", fillcolor="#eef3ff", '
        'fontname="Monospace", fontsize=9];',
    ]
    for index, sub in enumerate(subroutines):
        out.append(f"  subgraph cluster_{index} {{")
        out.append(f'    label="{escape(sub.id)}"; color="#718096";')
        for block in sub.body:
            lines = [f"block@{block.id}"]
            if block.comment:
                lines.append(f"// {block.comment}")
            lines.extend(phi.render() for phi in block.phis)
            lines.extend(op.render() for op in block.ops)
            if block.terminator is not None:
                lines.append(block.terminator.render())
            label = "\\l".join(escape(line) for line in lines) + "\\l"
            out.append(f'    {node_id(sub, block)} [label="{label}"];')
        out.append("  }")
    for sub in subroutines:
        for block in sub.body:
            for successor_id in pre_ir.succ_ids(block.terminator):
                successor = by_id.get(successor_id)
                successor_sub = owner.get(successor_id)
                if successor is not None and successor_sub is not None:
                    out.append(
                        f"  {node_id(sub, block)} -> {node_id(successor_sub, successor)};"
                    )
    out.append("}")
    return "\n".join(out)


def structure_to_dot(structure, *, rankdir: str = "TB") -> str:
    """Render routing/handler/subroutine ownership over the real CFG."""
    annotations: dict[Any, list[str]] = {}
    for block in structure.routing:
        annotations.setdefault(block, []).append(
            "role: dispatch" if block in structure.dispatch else "role: routing"
        )
    for block in structure.handlers:
        annotations.setdefault(block, []).append("role: handler")
    for subroutine in structure.subroutines:
        name = subroutine.name or f"sub@L{subroutine.entry_bb.first_line}"
        for block in subroutine.body:
            annotations.setdefault(block, []).append(f"role: subroutine {name}")
    for call in structure.call_sites:
        target = call.target_name or "?"
        annotations.setdefault(call.callsub_bb, []).append(
            f"call L{call.line} -> {target}"
        )
    return annotated_cfg_dot(
        structure.prog,
        annotations,
        title="program structure: routing, handlers, subroutines",
        rankdir=rankdir,
    )
