"""Dump EVERY representation of a TEAL contract — a one-shot debugging view of the
whole pipeline (source → graph → CFG → SSA → structure → control tree → path
predicates → inner-txn report → Puya IR).

Each layer is best-effort: one that fails to build is reported as
``(unavailable: …)`` and the rest still dump.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ..ssa import SSAProgram
from ..ssa import render as _ssa_render
from ..cfg import CFG
from ..graph import load_graph
from ..structure import analyze_structure
from ..path_predicates import PathPredicateAnalysis
from ..inner_txn_report import InnerTxnReport
from ..analysis import DerivedProfile, derived_program
from .._utils.dot import render as _dot_render
from . import render as _viz


def dump_all(source, out_dir: Optional[str] = None, *, svg: bool = True,
             registry=None) -> str:
    """Labeled text dump of every representation of ``source`` (a ``.teal`` file, a
    directory of them, or an in-memory ``{name: text}`` map); with ``out_dir`` also
    writes ``contract.txt`` + the graph-shaped layers as ``.svg`` / ``.dot``, and
    ``registry`` adds the cross-contract super-CFG."""
    prog = SSAProgram(source)

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
        lambda: _ssa_overlay(derived_program(prog, DerivedProfile.GUARDED)))
    add("USER-INPUT TAINT (sources -> sensitive sinks)", lambda: _taint_text(prog))
    add("STRUCTURE (subs / routing / handlers)", lambda: analyze_structure(prog).render())
    add("PATH PREDICATES", lambda: PathPredicateAnalysis(prog).render())
    add("INNER-TXN REPORT", lambda: InnerTxnReport(prog).render())
    add("PUYA IR (lift)", lambda: _ir_text(source))
    add("GUESSED ABI ENCODINGS (speculative side-channel)",
        lambda: _guessed_encodings_text(source))
    add("ABI TYPE-DRIVEN SECURITY LEADS (recovered arc4.Address at fund sinks)",
        lambda: _abi_security_leads_text(source))
    add("STORAGE SCHEMA (recovered global / local / box keys + maps)",
        lambda: _box_schema_text(source))
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
    g = load_graph(source)
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
    """The genuine ``puya.ir`` via Puya's own text emitter, un-optimised so every
    register shows with its recovered type."""
    from ..lift import to_puya_ir
    return to_puya_ir.render(SSAProgram(source), optimize_ir=False)


def _guessed_encodings_text(source) -> str:
    """The SPECULATIVE ARC4 encoded-type recovery side-channel — best-effort
    guesses that are deliberately NOT in the IR's ``ir_type``, so a wrong guess
    cannot affect lowering."""
    import puya.ir.models as M
    from ..lift import to_puya_ir
    main, subs = to_puya_ir.to_puya(SSAProgram(source))
    guesses, confident = to_puya_ir.guess_encoded_types_scored(main, subs)
    if not guesses:
        return "(no speculative ABI-structure guesses)"
    name_of, const_of = {}, {}
    for sub in [main, *subs]:
        for bb in sub.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if isinstance(src, M.Intrinsic):
                    # Inline constant args carry their own guess entries.
                    for a in src.args:
                        if isinstance(a, M.BytesConstant):
                            name_of[id(a)] = f"const[{a.value[:16].hex()}…]" \
                                if len(a.value) > 16 else f"const[{a.value.hex()}]"
                            const_of[id(a)] = a.value
                if isinstance(o, M.Assignment):
                    for t in o.targets:
                        name_of[id(t)] = f"{t.name}#{t.version}"
                        if isinstance(o.source, M.BytesConstant):
                            const_of[id(t)] = o.source.value
    n_sure = sum(1 for v in confident.values() if v)
    lines = [f"{len(guesses)} guess(es) — best-effort, side-channel only "
             f"(never in the IR's ir_type); {n_sure} fully confident, "
             f"{len(guesses) - n_sure} somewhat:"]
    # fully-confident first, then by name, so the reliable ones read at the top.
    for rid, et in sorted(guesses.items(),
                          key=lambda kv: (not confident.get(kv[0]),
                                          name_of.get(kv[0], ""))):
        extra = ""
        if rid in const_of and "utf8" in str(et):
            try:
                extra = f"  = {const_of[rid][2:].decode('utf-8')!r}"
            except (UnicodeDecodeError, IndexError):
                pass
        tag = "confident" if confident.get(rid) else "somewhat "
        lines.append(f"  [{tag}] {name_of.get(rid, '?')}: {et}{extra}")
    return "\n".join(lines)


def _abi_security_leads_text(source) -> str:
    """Fund/asset-transfer sinks paying out to a value recovered as ``arc4.Address``,
    flagging the arbitrary-recipient shape (caller-supplied and UNGUARDED)."""
    from ..lift import to_puya_ir
    main, subs = to_puya_ir.to_puya(SSAProgram(source))
    leads = to_puya_ir.abi_address_fund_flows(main, subs)
    if not leads:
        return "(no arc4.Address values reach a fund/asset sink)"
    danger = [x for x in leads if x["caller_supplied"] and not x["guarded"]]
    lines = [f"{len(leads)} address→sink flow(s); "
             f"{len(danger)} caller-supplied & UNGUARDED (arbitrary-recipient):"]
    for x in sorted(leads, key=lambda d: (not (d["caller_supplied"] and not d["guarded"]),
                                          d["subroutine"], d["field"])):
        tag = "  ⚠ CALLER-SUPPLIED, UNGUARDED" if x["caller_supplied"] and not x["guarded"] \
            else ("  caller-supplied, guarded" if x["caller_supplied"]
                  else "  (not directly caller-supplied)")
        lines.append(f"  itxn_field {x['field']} (sub {x['subroutine']}) "
                     f"<- {x['encoding']}{tag}")
    return "\n".join(lines)


def _box_schema_text(source) -> str:
    """Reconstructed STORAGE SCHEMA — the global / local / box keys and maps
    recovered from the storage opcodes, typed via the ABI type recovery."""
    from ..lift import to_puya_ir
    from ..lift.box_recovery import recover_storage_schema
    main, subs = to_puya_ir.to_puya(SSAProgram(source))
    schema = recover_storage_schema(main, subs)
    if not schema:
        return "(no app storage)"
    return "\n".join("  " + s.render() for s in schema)


def _ssa_overlay(prog: SSAProgram) -> str:
    """SSA functional dump with BOTH overlays: ``/*[V<=hi]*/`` IntRange from the
    substrate renderer, ``/*len=N*/`` / ``/*val=…*/`` from the text post-pass."""
    out = _ssa_render.functional_by_block(prog, show_ranges=True)
    try:
        from ..render_annotated import annotate_bytes_inline
        out = annotate_bytes_inline(prog, out)
    except Exception:
        pass
    return out


def _taint_text(prog: SSAProgram) -> str:
    """User-input → sensitive-sink reachability over the TaintGraph."""
    import networkx as nx
    from ..dataflow.taint_graph import TaintGraph
    from ..avm import (
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
    """Build the SuperCFG for ``prog`` + ``registry`` (dict or yaml path), or ``None``
    if there are no resolvable appcall sites."""
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
        ("graph", lambda: _viz.to_dot(load_graph(source))),
        ("cfg", lambda: CFG.of(prog).to_dot()),
        ("ssa", lambda: _ssa_render.to_dot(prog)),
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
