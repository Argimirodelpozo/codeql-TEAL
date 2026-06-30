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


def dump_all(source, out_dir: Optional[str] = None, *, svg: bool = True,
             registry=None) -> str:
    """Return a labeled text dump of every representation of ``source`` (a
    ``.teal`` file, a directory of them, or an in-memory ``{name: text}`` map).
    When ``out_dir`` is given, also write ``contract.txt`` + the graph-shaped
    layers as ``.svg``/``.dot`` there. ``registry`` (an ``{app_id: path}`` dict
    or a yaml path) adds the cross-contract super-CFG when the contract makes
    resolvable appcalls."""
    prog = SSAProgram(source, verbose=False)
    prog.propagate_constants()
    # Additive analytical passes (no materialize/DCE), so the SSA section can
    # show IntRange overlays while the pre-materialized sections still work.
    for _p in ("propagate_ranges", "propagate_range_arithmetic",
               "propagate_assert_ranges", "propagate_byte_lengths",
               "propagate_bytemath_ranges"):
        try:
            getattr(prog, _p)()
        except Exception:
            pass

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
    add("SSA (functional + IntRange/byte-length overlay)",
        lambda: _ssa_overlay(prog))
    add("USER-INPUT TAINT (sources -> sensitive sinks)", lambda: _taint_text(prog))
    add("STRUCTURE (subs / routing / handlers)", lambda: analyze_structure(prog).render())
    add("CONTROL TREE (region tree)", lambda: _ct_pretty(build_control_tree(prog)))
    add("PATH PREDICATES", lambda: PathPredicateAnalysis(prog).render())
    add("INNER-TXN REPORT", lambda: InnerTxnReport(prog).render())
    add("PUYA IR (lift)", lambda: _ir_text(source))
    add("GUESSED ABI ENCODINGS (speculative side-channel)",
        lambda: _guessed_encodings_text(source))
    if registry is not None:
        add("SUPER-CFG (cross-contract)", lambda: _supercfg_text(prog, registry))

    text = "\n\n".join(parts) + "\n"
    if out_dir is not None:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "contract.txt").write_text(text)
        _write_graphs(out, prog, source, registry=registry, svg=svg)
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
    """The genuine ``puya.ir`` (via Puya's own text emitter), un-optimised so
    every register shows with its recovered type -- incl. the langspec
    refinements (``bool`` / ``biguint`` / ``account`` / ``bytes[N]``) and the
    CONFIDENT ARC4 encoded types (``arc4.UInt64`` / ``arc4.Bool`` / static
    ``arc4.Tuple`` / ...) that only exist in the real Puya IR, not the lift's
    pre-IR intermediate."""
    from ..lift import to_puya_ir
    return to_puya_ir.render(SSAProgram(source, verbose=False), optimize_ir=False)


def _guessed_encodings_text(source) -> str:
    """The SPECULATIVE ARC4 encoded-type recovery side-channel
    (:func:`to_puya_ir._guess_encoded_types`) -- best-effort guesses (currently
    strict-proof ``arc4.String`` literals) that are deliberately NOT in the IR's
    ``ir_type``, so a wrong guess can't affect lowering. Shown here so a consumer
    (e.g. structure-aware fuzzing) can see what's available; for a string guess the
    decoded text is included."""
    import puya.ir.models as M
    from ..lift import to_puya_ir
    main, subs = to_puya_ir.to_puya(SSAProgram(source, verbose=False))
    guesses = to_puya_ir._guess_encoded_types(main, subs)
    if not guesses:
        return "(no speculative ABI-structure guesses)"
    name_of, const_of = {}, {}
    for sub in [main, *subs]:
        for bb in sub.body:
            for o in bb.ops:
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        name_of[id(t)] = f"{t.name}#{t.version}"
                        if isinstance(o.source, M.BytesConstant):
                            const_of[id(t)] = o.source.value
    lines = [f"{len(guesses)} guess(es) — best-effort, side-channel only "
             "(never in the IR's ir_type):"]
    for rid, et in sorted(guesses.items(), key=lambda kv: name_of.get(kv[0], "")):
        extra = ""
        if rid in const_of and "utf8" in str(et):
            try:
                extra = f"  = {const_of[rid][2:].decode('utf-8')!r}"
            except (UnicodeDecodeError, IndexError):
                pass
        lines.append(f"  {name_of.get(rid, '?')}: {et}{extra}")
    return "\n".join(lines)


def _ssa_overlay(prog: SSAProgram) -> str:
    """SSA functional dump with BOTH overlays: ``/*[V<=hi]*/`` IntRange (the
    substrate renderer) and ``/*len=N*/`` / ``/*val=…*/`` byte-length/value
    (a post-pass over the text, since the renderer only does IntRange)."""
    out = _ssa_render.functional_by_block(prog, show_ranges=True)
    try:
        from ..render_annotated import annotate_bytes_inline
        out = annotate_bytes_inline(prog, out)
    except Exception:
        pass
    return out


def _taint_text(prog: SSAProgram) -> str:
    """User-input → sensitive-sink reachability over the TaintGraph (which now
    carries the interprocedural frame edges, so param-fed flows are seen)."""
    import networkx as nx
    from ..dataflow.taint_graph import TaintGraph
    from ..opsets import (
        SENSITIVE_ITXN_FIELDS, STATE_WRITE_OPS, TXN_SOURCE_OPS, LSIG_ARG_OPS,
    )
    tg = TaintGraph.of(prog)
    sources = [
        n for n in tg.nodes()
        if (tg.op_of(n) in TXN_SOURCE_OPS and "ApplicationArgs" in (tg.immediates_of(n) or ""))
        or tg.op_of(n) in LSIG_ARG_OPS
    ]
    sinks: list[tuple] = []
    for n in tg.nodes():
        op, imm = tg.op_of(n), tg.immediates_of(n)
        if op == "itxn_field" and imm in SENSITIVE_ITXN_FIELDS:
            sinks.append((n, f"itxn_field {imm}"))
        elif op in STATE_WRITE_OPS:
            sinks.append((n, op))
    flows = []
    for s in sources:
        reach = set(nx.descendants(tg.g, s)) | {s}
        for sink, name in sinks:
            if sink in reach:
                flows.append(f"  {s!r}  ->  {name}@{sink!r}")
    head = f"{len(sources)} user-input source(s), {len(sinks)} sensitive sink(s)\n"
    return head + ("\n".join(sorted(flows)) if flows
                   else "(no user-input -> sensitive-sink flow)")


def _supercfg(prog: SSAProgram, registry):
    """Build the SuperCFG for ``prog`` + ``registry`` (dict or yaml path), or
    ``None`` if there are no resolvable appcall sites."""
    from ..cfg import SuperCFG
    from ..xcontract import find_appcall_sites, load_registry
    reg = registry if isinstance(registry, dict) else load_registry(registry)
    if not find_appcall_sites(prog, reg):
        return None
    return SuperCFG.build(prog, reg)


def _supercfg_text(prog: SSAProgram, registry) -> str:
    sc = _supercfg(prog, registry)
    if sc is None:
        return "(no resolvable appcall sites — nothing to splice)"
    contracts = sorted({sb.app_id for sb in sc.blocks()},
                       key=lambda x: (x is not None, x))
    scope = ["root" if c is None else f"app{c}" for c in contracts]
    lines = [f"{len(contracts)} contracts: {scope}",
             f"{len(sc.inter_edges)} inter-contract edge(s):"]
    for e in sc.inter_edges:
        lines.append(f"  {e.kind:6}  {e.src!r}  ->  {e.dst!r}")
    return "\n".join(lines)


# --- graphviz files -----------------------------------------------------


def _write_graphs(out: Path, prog: SSAProgram, source, *, registry=None,
                  svg: bool) -> None:
    def emit(name: str, dot: str) -> None:
        if svg:
            try:
                (out / f"{name}.svg").write_bytes(bytes(_dot_render(dot)))
                return
            except Exception:
                pass                              # no `dot` on PATH -> .dot fallback
        (out / f"{name}.dot").write_text(dot)

    builders = [
        ("graph", lambda: _viz.to_dot(load_graph(source, verbose=False))),
        ("cfg", lambda: CFG.of(prog).to_dot()),
        ("ssa", lambda: _ssa_render.to_dot(prog)),
        ("control_tree", lambda: _viz.region_to_dot(build_control_tree(prog))),
    ]
    if registry is not None:
        def _sc_dot():
            sc = _supercfg(prog, registry)
            if sc is None:
                raise ValueError("no appcall sites")
            return sc.to_dot()
        builders.append(("supercfg", _sc_dot))

    for name, build in builders:
        try:
            emit(name, build())
        except Exception:
            pass                                  # layer failed -> skip its file
