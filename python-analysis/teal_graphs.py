"""TEAL graph layer.

Build a NetworkX MultiDiGraph from a TEAL CodeQL database, with CFG and
dataflow edges as separate edge kinds. Aimed at Jupyter / REPL exploration.

Quick start
-----------
    >>> from teal_graphs import load_graph, cfg_view, dataflow_view
    >>> from teal_ast import Opcode, IntegerAddOpcode
    >>> g = load_graph("test-dbs/xgov-db")
    >>> g.number_of_nodes(), g.number_of_edges()
    >>> # Typed node filtering:
    >>> [n for n in g if isinstance(n, IntegerAddOpcode)]

Nodes come in two flavours:

- :class:`teal_ast.AstNode` (typed subclass per ``qlClass``), hashed by
  ``(file, line)``.
- :class:`PhiNode` — SSA phi definitions (``DirectPhi``/``IndirectPhi``).
  Not ``AstNode`` instances; hashed by ``(file, line, kind, stack_index)``
  since multiple phis may share a ``(file, line)`` with each other and
  with the BB's first opcode.

Each edge has a ``kind`` attribute ("cfg" or "dataflow"); CFG edges
additionally carry ``successor``. Phi edges are folded into the ``"cfg"``
kind with successor labels ``"PhiIn"`` / ``"PhiOut"``.

The first call against a database compiles + runs five queries (~10-30s);
subsequent calls hit a per-db CSV cache invalidated by db mtime + query mtime.
"""
from __future__ import annotations

import csv
import hashlib
import os
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Iterable

import networkx as nx

from teal_ast import AstNode, Location, ast_node_from_row

QUERIES_DIR = Path(__file__).resolve().parent / "queries"
# Root of the teal-all QL library. Queries depend on predicates defined
# here, so changes to these files must invalidate the cache even when
# queries/*.ql themselves haven't been touched.
TEAL_LIB_DIR = Path(__file__).resolve().parent.parent / "teal" / "ql" / "lib" / "codeql" / "teal"
DEFAULT_CACHE = Path(
    os.environ.get("TEAL_GRAPHS_CACHE", Path.home() / ".cache" / "teal-graphs")
)
QUERY_NAMES = (
    "nodes",
    "cfgEdges",
    "dataflowEdges",
    "phiNodes",
    "phiEdges",
    "basicBlocks",
    "ssaOutputs",
    "ssaInputs",
    "phiArgs",
    "constValues",
    "mustValues",
    "scratchInfluence",
    "valueIdentitySteps",
    "stackHeights",
)


class PhiNode:
    """An SSA phi node (``DirectPhi`` or ``IndirectPhi``) in the CFG graph.

    Phis are not ``AstNode``s and can share ``(file, line)`` with the BB's
    first opcode, so identity is ``(file, line, kind, stack_index)``.
    ``kind`` is ``"DirectPhi"`` or ``"IndirectPhi"``.
    """

    __slots__ = ("location", "kind", "stack_index", "args")

    def __init__(self, location: Location, kind: str, stack_index: int):
        self.location = location
        self.kind = kind
        self.stack_index = stack_index
        # Populated by phiArgs.ql at load time. Elements are SSAVar for
        # DirectPhi and a single PhiNode (the root DirectPhi) for
        # IndirectPhi — see phi_label() for recursive rendering.
        self.args: list = []

    @property
    def ql_class(self) -> str:
        return self.kind

    @property
    def code(self) -> str:
        return f"φ_{self.stack_index}"

    def _key(self) -> tuple:
        return (self.location.file, self.location.start_line, self.kind, self.stack_index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        if not isinstance(other, PhiNode):
            return NotImplemented
        return self._key() == other._key()

    def __repr__(self) -> str:
        return f"{self.kind}({self.location.file}:{self.location.start_line}#{self.stack_index})"


class SSAVar:
    """A stack variable produced by an opcode.

    Mirrors CodeQL's ``SSAVar`` — identity is
    ``(file, declaring_line, output_index)`` where ``output_index`` is
    1-based (matching ``getInternalOutputIndex``). The textual form
    matches ``SSAVar.getIdentifier()`` in QL: ``V#{idx}@L{line}``.
    """

    __slots__ = ("file", "line", "output_index")

    def __init__(self, file: str, line: int, output_index: int):
        self.file = file
        self.line = line
        self.output_index = output_index

    @property
    def identifier(self) -> str:
        return f"V#{self.output_index}@L{self.line}"

    def _key(self) -> tuple:
        return (self.file, self.line, self.output_index)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        if not isinstance(other, SSAVar):
            return NotImplemented
        return self._key() == other._key()

    def __repr__(self) -> str:
        return self.identifier


class BasicBlockNode:
    """A basic block collapsed into a single graph node.

    Identity is ``(file, first_line, last_line)``. Carries the ordered list
    of AST nodes inside the block (``ast_nodes``) and any SSA phis attached
    at the block's entry (``phis``) — available for consumers that want to
    render phis as a header inside the BB rather than as side-nodes.
    """

    __slots__ = ("file", "first_line", "last_line", "ast_nodes", "phis")

    def __init__(self, file: str, first_line: int, last_line: int):
        self.file = file
        self.first_line = first_line
        self.last_line = last_line
        self.ast_nodes: list[AstNode] = []
        self.phis: list[PhiNode] = []

    @property
    def location(self) -> Location:
        # For compatibility with code paths that filter by `.location.file`.
        return Location(self.file, self.first_line, 0, self.last_line, 0)

    def _key(self) -> tuple:
        return (self.file, self.first_line, self.last_line)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other) -> bool:
        if not isinstance(other, BasicBlockNode):
            return NotImplemented
        return self._key() == other._key()

    def __repr__(self) -> str:
        return f"BB({self.file}:{self.first_line}-{self.last_line})"


def _codeql() -> str:
    return os.environ.get("CODEQL", "codeql")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(res.stdout)
        sys.stderr.write(res.stderr)
        raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
    return res


def _ensure_pack_installed() -> None:
    if (QUERIES_DIR / ".codeql" / "pack").exists():
        return
    _run([_codeql(), "pack", "install", str(QUERIES_DIR)])


def _run_csv_query(db: Path, query: Path, out_dir: Path) -> None:
    qname = query.stem
    bqrs = out_dir / f"{qname}.bqrs"
    csv_out = out_dir / f"{qname}.csv"
    _run([_codeql(), "query", "run",
          "--database", str(db),
          "--output", str(bqrs),
          str(query)])
    _run([_codeql(), "bqrs", "decode",
          "--format=csv",
          "--output", str(csv_out),
          str(bqrs)])


def _cache_dir_for(db: Path) -> Path:
    sig_parts = [str(db.resolve()), str(db.stat().st_mtime_ns)]
    for q in sorted(QUERIES_DIR.glob("*.ql")):
        sig_parts.append(f"{q.name}:{q.stat().st_mtime_ns}")
    # Include teal-all library sources so edits to the QL library
    # (predicates the queries rely on) invalidate the cache too.
    # Skip the on-disk pack cache under .codeql/ — those are generated
    # build artifacts that change independently.
    if TEAL_LIB_DIR.exists():
        for q in sorted(TEAL_LIB_DIR.rglob("*.qll")):
            if ".codeql" in q.parts:
                continue
            rel = q.relative_to(TEAL_LIB_DIR)
            sig_parts.append(f"lib/{rel}:{q.stat().st_mtime_ns}")
    h = hashlib.sha256("|".join(sig_parts).encode()).hexdigest()[:16]
    out = DEFAULT_CACHE / h
    out.mkdir(parents=True, exist_ok=True)
    return out


def _read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        return list(reader)


def _load_source_lines(db: Path) -> dict[str, list[str]]:
    """Map relative file path -> 1-indexed list of lines from ``db/src.zip``."""
    src_zip = db / "src.zip"
    if not src_zip.exists():
        return {}
    sources: dict[str, list[str]] = {}
    with zipfile.ZipFile(src_zip) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            with zf.open(info) as f:
                try:
                    text = f.read().decode("utf-8")
                except UnicodeDecodeError:
                    continue
            lines = text.splitlines()
            sources[info.filename] = lines
            sources[Path(info.filename).name] = lines
    return sources


def _slice_source(sources: dict[str, list[str]], loc: Location) -> str:
    """Extract the source text covered by a :class:`Location`.

    CodeQL columns are 1-based, inclusive at both ends. TEAL opcodes are
    always single-line; for multi-line spans (e.g. the program-root
    ``Source`` node) we return ``""`` since the covered region isn't a
    single statement.
    """
    lines = sources.get(loc.file) or sources.get(Path(loc.file).name)
    if lines is None:
        return ""
    if loc.start_line != loc.end_line:
        return ""
    if loc.start_line < 1 or loc.start_line > len(lines):
        return ""
    return lines[loc.start_line - 1][loc.start_column - 1 : loc.end_column]


def load_graph(
    db_path: str | Path,
    *,
    refresh: bool = False,
    verbose: bool = True,
) -> nx.MultiDiGraph:
    """Build a MultiDiGraph from a TEAL CodeQL database.

    Parameters
    ----------
    db_path:
        Path to a CodeQL database directory (the one containing ``db-teal/``
        and ``codeql-database.yml``).
    refresh:
        If True, re-run all queries even if cached results exist.
    verbose:
        Print one-line progress to stderr.
    """
    db = Path(db_path).resolve()
    if not db.exists():
        raise FileNotFoundError(db)

    _ensure_pack_installed()
    cache = _cache_dir_for(db)
    if refresh:
        for f in list(cache.glob("*.csv")) + list(cache.glob("*.bqrs")):
            f.unlink()

    g = nx.MultiDiGraph()
    g.graph["db_path"] = str(db)
    sources = _load_source_lines(db)

    # (file, start_line) -> AstNode instance, for edge-endpoint lookup.
    by_loc: dict[tuple[str, int], AstNode] = {}
    # (file, line, kind, stackIdx) -> PhiNode instance.
    by_phi: dict[tuple[str, int, str, int], PhiNode] = {}
    # (file, line, output_index) -> SSAVar instance.
    by_var: dict[tuple[str, int, int], SSAVar] = {}

    def _resolve_var(file: str, line: int, output_index: int) -> SSAVar:
        key = (file, line, output_index)
        v = by_var.get(key)
        if v is None:
            v = SSAVar(file, line, output_index)
            by_var[key] = v
        return v

    def _resolve(file: str, line: int) -> AstNode:
        key = (file, line)
        node = by_loc.get(key)
        if node is None:
            # Edge endpoint not reported by nodes.ql — stash a bare AstNode
            # so the edge still lands in the graph.
            node = ast_node_from_row(Location(file, line, 0, line, 0), "", "AstNode")
            by_loc[key] = node
            g.add_node(node)
        return node

    def _resolve_phi(file: str, line: int, kind: str, stack_idx: int) -> PhiNode:
        key = (file, line, kind, stack_idx)
        node = by_phi.get(key)
        if node is None:
            node = PhiNode(Location(file, line, 0, line, 0), kind, stack_idx)
            by_phi[key] = node
            g.add_node(node)
        return node

    def _resolve_endpoint(file: str, line: int, stack_idx: int, kind: str):
        if kind == "ast":
            return _resolve(file, line)
        return _resolve_phi(file, line, kind, stack_idx)

    for q in QUERY_NAMES:
        csv_out = cache / f"{q}.csv"
        if not csv_out.exists():
            if verbose:
                print(f"[teal_graphs] running {q}.ql ...", file=sys.stderr)
            _run_csv_query(db, QUERIES_DIR / f"{q}.ql", cache)
        rows = _read_csv(csv_out)

        if q == "nodes":
            for file, sl, sc, el, ec, ql_class in rows:
                loc = Location(file, int(sl), int(sc), int(el), int(ec))
                code = _slice_source(sources, loc).strip()
                node = ast_node_from_row(loc, code, ql_class)
                by_loc[(file, loc.start_line)] = node
                g.add_node(node)
        elif q == "cfgEdges":
            for sf, sl, df, dl, t in rows:
                u = _resolve(sf, int(sl))
                v = _resolve(df, int(dl))
                g.add_edge(u, v, kind="cfg", successor=t)
        elif q == "dataflowEdges":
            for sf, sl, df, dl in rows:
                u = _resolve(sf, int(sl))
                v = _resolve(df, int(dl))
                g.add_edge(u, v, kind="dataflow")
        elif q == "phiNodes":
            for file, line, stack_idx, kind in rows:
                _resolve_phi(file, int(line), kind, int(stack_idx))
        elif q == "phiEdges":
            for (
                sf, sl, ssi, sk,
                df, dl, dsi, dk,
                label,
            ) in rows:
                u = _resolve_endpoint(sf, int(sl), int(ssi), sk)
                v = _resolve_endpoint(df, int(dl), int(dsi), dk)
                g.add_edge(u, v, kind="cfg", successor=label)
        elif q == "basicBlocks":
            # Annotate each AstNode with its BB id = (file, firstLine, lastLine).
            for ast_file, ast_line, bb_first, bb_last in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                g.nodes[node]["bb"] = (ast_file, int(bb_first), int(bb_last))
        elif q == "ssaOutputs":
            # Per-op list of produced SSAVars, ordered by output_index (1-based).
            for ast_file, ast_line, out_idx in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                v = _resolve_var(ast_file, int(ast_line), int(out_idx))
                outs = g.nodes[node].setdefault("stack_outputs", [])
                outs.append(v)
            # Finalize ordering by output_index.
            for n in g.nodes:
                outs = g.nodes[n].get("stack_outputs")
                if outs:
                    outs.sort(key=lambda x: x.output_index)
        elif q == "constValues":
            # Literal-only resolved constants per (op, outputIdx). Sound.
            # Per-output schema: ``g.nodes[op]["const_outputs"]`` is
            # ``{outIdx: (kind, value)}``. Single-value back-compat field
            # ``g.nodes[op]["const_value"]`` is set when only one output.
            for ast_file, ast_line, out_idx, kind, value in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                outs = g.nodes[node].setdefault("const_outputs", {})
                outs[int(out_idx)] = (kind, value)
                if int(out_idx) == 1 and len(outs) == 1:
                    g.nodes[node]["const_value"] = (kind, value)
                elif "const_value" in g.nodes[node] and len(outs) > 1:
                    g.nodes[node].pop("const_value", None)
        elif q == "mustValues":
            # Dataflow-extended must-be-constant resolutions per
            # (op, outputIdx). Sound (uses ``LocalFlow::valueIdentityFlow``
            # under the hood — strict value-equality flow, not the broad
            # taint pass-through). Covers arithmetic folds, scratch reads,
            # callsub bridges, phi convergence, and identity-preserving
            # stack manipulations.
            for ast_file, ast_line, out_idx, kind, value in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                must = g.nodes[node].setdefault("must_outputs", {})
                must[int(out_idx)] = (kind, value)
        elif q == "valueIdentitySteps":
            # One row per ``valueIdentityFlowStep(src, sink)``: src and
            # sink defs hold the same runtime value (stack passthrough,
            # single-source phi, callsub bridge, scratch bridge).
            # Stored on the graph as ``g.graph['identity_steps']``: a list
            # of ``(src_key, sink_key)`` where each key is one of:
            #   ("var",  file, line, idx)            for an SSAVar def
            #   ("phi",  file, line, kind, stack_idx) for a DirectPhi/IndirectPhi
            # Python's `propagate_constants` iterates these to fixed point
            # so a value resolved at a multi-arg phi can flow through to
            # downstream SSAVars.
            steps = g.graph.setdefault("identity_steps", [])
            for row in rows:
                (sf, sl, si, sk, df, dl, di, dk) = row
                src = (("var", sf, int(sl), int(si)) if sk == "SSAVar"
                       else ("phi", sf, int(sl), sk, int(si)))
                snk = (("var", df, int(dl), int(di)) if dk == "SSAVar"
                       else ("phi", df, int(dl), dk, int(di)))
                steps.append((src, snk))
        elif q == "stackHeights":
            # Per AST node × possible stack height before it executes.
            # Stored on the node as ``g.nodes[n]["stack_heights"]`` =
            # set[int]. Multiple values denote inconsistent depth (paths
            # disagree); single-value sets are the common case. The
            # stack simulator uses ``min(...)`` to bound BB-entry phi
            # lists so the model's [1..1000] IndirectPhi explosion at
            # recursive subroutines doesn't leak into per-line views.
            for row in rows:
                (sh_file, sh_line, depth) = row
                node = by_loc.get((sh_file, int(sh_line)))
                if node is None:
                    continue
                heights = g.nodes[node].setdefault("stack_heights", set())
                heights.add(int(depth))
        elif q == "scratchInfluence":
            # Per `load N` op, list every may-influencing `store N` plus
            # the SSAVar key (file, line, outputIdx) of the value the
            # store writes. Python's scratch-prop pass uses this to
            # decide if every influencing store wrote the same constant.
            #
            # Storage on the LOAD node:
            #   g.nodes[load]["scratch_stores"] = [(store_value_key, ...), ...]
            # where store_value_key = (file, line, outputIdx).
            for row in rows:
                (load_file, load_line, _store_file, _store_line,
                 sv_file, sv_line, sv_idx) = row
                load_node = by_loc.get((load_file, int(load_line)))
                if load_node is None:
                    continue
                stores_list = g.nodes[load_node].setdefault("scratch_stores", [])
                stores_list.append((sv_file, int(sv_line), int(sv_idx)))
        elif q == "phiArgs":
            # Attach each phi's expansion arguments. DirectPhi -> SSAVars;
            # IndirectPhi -> the root DirectPhi (a PhiNode).
            for row in rows:
                (phi_file, phi_line, phi_idx, phi_kind,
                 arg_file, arg_line, arg_idx, arg_kind) = row
                phi = by_phi.get(
                    (phi_file, int(phi_line), phi_kind, int(phi_idx))
                )
                if phi is None:
                    continue
                if arg_kind == "SSAVar":
                    arg = _resolve_var(arg_file, int(arg_line), int(arg_idx))
                elif arg_kind == "DirectPhi":
                    arg = _resolve_phi(
                        arg_file, int(arg_line), "DirectPhi", int(arg_idx)
                    )
                else:
                    continue
                phi.args.append(arg)
            # Finalize ordering: SSAVar args by (line, output_index); phi
            # args (single root for IndirectPhi) don't need sorting.
            for p in by_phi.values():
                p.args.sort(key=lambda a: (
                    (a.line, a.output_index) if isinstance(a, SSAVar)
                    else (a.location.start_line, a.stack_index)
                ))
        elif q == "ssaInputs":
            # Per-op list of consumed Definitions, ordered by getStackInputByOrder `ord` (1-based).
            # Each entry is either an SSAVar, a DirectPhi PhiNode, or an IndirectPhi PhiNode.
            #
            # When DirectPhi + IndirectPhi co-exist at the same ``(bb, slot)``
            # they appear as two rows at the same ``ord`` (parallel views of
            # the same stack position). Dedupe by (node, ord) for display —
            # prefer DirectPhi as canonical so the args render via the local-
            # origin tree. Both phis still exist in the graph for dataflow
            # purposes (Dataflow.qll uses getConsumedValues directly).
            pending: dict = {}
            for row in rows:
                ast_file, ast_line, ord_, def_kind, def_file, def_line, def_idx = row
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                if def_kind == "SSAWriteDef":
                    d = _resolve_var(def_file, int(def_line), int(def_idx))
                else:
                    d = _resolve_phi(def_file, int(def_line), def_kind, int(def_idx))
                pending.setdefault(node, []).append((int(ord_), def_kind, d))
            # Stash the (ord, kind, d) entries as a node attribute; the
            # final dedupe + arg-merge happens post-loop after phiArgs has
            # populated phi.args.
            for node, items in pending.items():
                items.sort(key=lambda x: (x[0], 0 if x[1] == "DirectPhi" else 1))
                g.nodes[node]["_stack_inputs_raw"] = items

    # Post-pass: dedupe stack_inputs by ord, merging args of DirectPhi +
    # IndirectPhi pairs at the same slot so the IndirectPhi's propagated
    # chain remains visible in the displayed phi(...) expansion. Runs
    # AFTER phiArgs has populated phi.args.
    for node in list(g.nodes):
        items = g.nodes[node].pop("_stack_inputs_raw", None)
        if items is None:
            continue
        seen: dict = {}
        deduped = []
        for ord_, kind, d in items:
            if ord_ not in seen:
                seen[ord_] = d
                deduped.append((ord_, kind, d))
                continue
            canonical = seen[ord_]
            if isinstance(canonical, PhiNode) and isinstance(d, PhiNode):
                existing = set(canonical.args)
                for arg in d.args:
                    if arg not in existing:
                        canonical.args.append(arg)
                        existing.add(arg)
        g.nodes[node]["stack_inputs"] = [d for _, _, d in deduped]

    if verbose:
        print(
            f"[teal_graphs] loaded {g.number_of_nodes()} nodes, "
            f"{g.number_of_edges()} edges from {db.name}",
            file=sys.stderr,
        )
    return g


def _edges_of_kind(g: nx.MultiDiGraph, kind: str) -> Iterable[tuple]:
    for u, v, k, d in g.edges(keys=True, data=True):
        if d.get("kind") == kind:
            yield u, v, k


def cfg_view(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Read-only edge-subgraph containing only CFG edges and their endpoints."""
    return g.edge_subgraph(_edges_of_kind(g, "cfg"))


def dataflow_view(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Read-only edge-subgraph containing only dataflow edges and their endpoints."""
    return g.edge_subgraph(_edges_of_kind(g, "dataflow"))


# -- Graphviz rendering -------------------------------------------------------

_CFG_EDGE_STYLES = {
    "NormalSuccessor":           "",
    "BooleanSuccessor(true)":    'color="#2a8f3c", fontcolor="#2a8f3c", label="T"',
    "BooleanSuccessor(false)":   'color="#c0392b", fontcolor="#c0392b", label="F"',
    "ConditionalJumpCompletion(true)":  'color="#2a8f3c", fontcolor="#2a8f3c", label="T"',
    "ConditionalJumpCompletion(false)": 'color="#c0392b", fontcolor="#c0392b", label="F"',
    "UnconditionalJumpCompletion":      'style=bold, label="jmp"',
    "RetsubCompletion":          'style=dashed, label="retsub"',
    "MultilabelJumpCompletion":  'style=dotted',
    "PhiIn":                     'style=dashed, color="#7f5ab6", arrowhead=onormal, constraint=false',
    "PhiOut":                    'style=dashed, color="#7f5ab6", arrowhead=normal, constraint=false',
}


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _dot_id(n) -> str:
    if isinstance(n, PhiNode):
        suffix = f"#{n.kind}#{n.stack_index}"
    else:
        suffix = ""
    return '"' + _dot_escape(f"{n.location.file}:{n.location.start_line}{suffix}") + '"'


def _edge_attrs(data: dict) -> str:
    kind = data.get("kind")
    if kind == "cfg":
        succ = data.get("successor", "")
        style = _CFG_EDGE_STYLES.get(succ)
        if style is not None:
            return style
        return f'label="{_dot_escape(succ)}"'
    if kind == "dataflow":
        return 'style=dotted, color="#2980b9", constraint=false'
    return ""


def to_dot(
    g: nx.MultiDiGraph,
    *,
    kinds: tuple[str, ...] = ("cfg",),
    file: str | None = None,
    rankdir: str = "TB",
) -> str:
    """Emit a Graphviz DOT source for ``g``.

    ``kinds`` picks which edge types to include; ``file`` optionally restricts
    to nodes from one source file. Nodes labeled ``<line>: <opcode>``.
    """
    nodes = [n for n in g.nodes if file is None or n.location.file == file]
    node_set = set(nodes)

    lines = [
        "digraph TEAL {",
        f"  rankdir={rankdir};",
        "  overlap=false;",
        "  splines=true;",
        '  node [shape=box, fontname="Monospace", fontsize=10];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    def _node_sort_key(x):
        phi_bit = 1 if isinstance(x, PhiNode) else 0
        phi_idx = x.stack_index if isinstance(x, PhiNode) else -1
        return (x.location.file, x.location.start_line, phi_bit, phi_idx)

    for n in sorted(nodes, key=_node_sort_key):
        if isinstance(n, PhiNode):
            label = phi_label(n)
            attrs = f'label="{_dot_escape(label)}", shape=ellipse, style=dashed, color="#7f5ab6", fontcolor="#7f5ab6"'
        else:
            body = n.code or n.ql_class
            label = f"{n.location.start_line}: {body}"
            attrs = f'label="{_dot_escape(label)}"'
        lines.append(f'  {_dot_id(n)} [{attrs}];')

    for u, v, _, data in g.edges(keys=True, data=True):
        if data.get("kind") not in kinds:
            continue
        if u not in node_set or v not in node_set:
            continue
        attrs = _edge_attrs(data)
        sep = " " if attrs else ""
        lines.append(f"  {_dot_id(u)} -> {_dot_id(v)}{sep}[{attrs}];")

    lines.append("}")
    return "\n".join(lines)


class _SvgResult:
    def __init__(self, svg: bytes):
        self.svg = svg

    def _repr_svg_(self) -> str:
        return self.svg.decode("utf-8")

    def __bytes__(self) -> bytes:
        return self.svg

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(self.svg)
        return p


def _render_dot(dot_source: str, *, format: str = "svg", engine: str = "dot"):
    res = subprocess.run(
        [engine, f"-T{format}"],
        input=dot_source.encode("utf-8"),
        capture_output=True,
    )
    if res.returncode != 0:
        sys.stderr.write(res.stderr.decode("utf-8", errors="replace"))
        raise RuntimeError(f"{engine} failed (exit {res.returncode})")
    if format == "svg":
        return _SvgResult(res.stdout)
    return res.stdout


def draw_cfg(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render CFG edges as a layered DOT graph. Returns a Jupyter-renderable SVG."""
    return _render_dot(
        to_dot(g, kinds=("cfg",), file=file, rankdir=rankdir),
        format=format, engine=engine,
    )


def draw_dataflow(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render dataflow edges.

    Use ``engine='dot'`` (default) for layered layouts, or ``'fdp'`` / ``'sfdp'``
    / ``'neato'`` for a force-directed ("physical") layout — often clearer for
    dataflow slices since there's no inherent top-to-bottom structure.
    """
    return _render_dot(
        to_dot(g, kinds=("dataflow",), file=file, rankdir=rankdir),
        format=format, engine=engine,
    )


def draw(
    g: nx.MultiDiGraph,
    *,
    kinds: tuple[str, ...] = ("cfg", "dataflow"),
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render both edge kinds overlaid: solid CFG edges + dotted dataflow edges."""
    return _render_dot(
        to_dot(g, kinds=kinds, file=file, rankdir=rankdir),
        format=format, engine=engine,
    )


# -- SSA stack inspection -----------------------------------------------------


def stack_inputs(g: nx.MultiDiGraph, op: AstNode) -> list:
    """Definitions consumed by ``op``, in stack-input order (1-based ord → index 0).

    Each element is an :class:`SSAVar` or :class:`PhiNode`. Returns an empty
    list when the op consumes nothing (or when ``ssaInputs.ql`` produced no
    row for it, e.g. dead code or a non-stack AST node).
    """
    return list(g.nodes[op].get("stack_inputs", []))


def stack_outputs(g: nx.MultiDiGraph, op: AstNode) -> list[SSAVar]:
    """SSAVars produced by ``op``, in output-index order (1-based)."""
    return list(g.nodes[op].get("stack_outputs", []))


def phi_label(p: "PhiNode") -> str:
    """Render a phi as ``phi(arg1, arg2, ...)`` with args expanded.

    DirectPhi expands to ``phi(V#i@Lx, V#j@Ly)`` — one arg per originating
    input SSAVar. IndirectPhi nests its root DirectPhi: ``phi(phi(...))``.
    Falls back to the compact form ``φ_k@L{line}`` when the phi has no
    args attached (e.g. a DB loaded with an older cache).
    """
    if not p.args:
        tag = "φ" if p.kind == "DirectPhi" else "φᵢ"
        return f"{tag}_{p.stack_index}@L{p.location.start_line}"
    inner = ", ".join(_def_label(a) for a in p.args)
    return f"phi({inner})"


def _def_label(d) -> str:
    if isinstance(d, SSAVar):
        return d.identifier
    if isinstance(d, PhiNode):
        return phi_label(d)
    return repr(d)


def stack_summary(g: nx.MultiDiGraph, op: AstNode) -> str:
    """One-line ``L{line}: {op}   in=[…]  out=[…]`` summary for an opcode."""
    ins = stack_inputs(g, op)
    outs = stack_outputs(g, op)
    body = op.code or op.ql_class
    in_str = "[" + ", ".join(_def_label(d) for d in ins) + "]"
    out_str = "[" + ", ".join(_def_label(v) for v in outs) + "]"
    return f"L{op.location.start_line:>4}: {body:<36}  in={in_str:<42}  out={out_str}"


def _is_const_block_ref(op: AstNode) -> bool:
    """True if ``op`` is an ``intc_*`` / ``intc`` / ``bytec_*`` / ``bytec`` —
    i.e. one of the opcodes whose source form references a constblock
    entry by index rather than carrying the literal inline."""
    from teal_ast import (
        Intc0Opcode, Intc1Opcode, Intc2Opcode, Intc3Opcode, IntcOpcode,
        Bytec0Opcode, Bytec1Opcode, Bytec2Opcode, Bytec3Opcode, BytecOpcode,
    )
    return isinstance(op, (
        Intc0Opcode, Intc1Opcode, Intc2Opcode, Intc3Opcode, IntcOpcode,
        Bytec0Opcode, Bytec1Opcode, Bytec2Opcode, Bytec3Opcode, BytecOpcode,
    ))


def ssa_functional(g: nx.MultiDiGraph, op: AstNode, *, resolve_consts: bool = True) -> str:
    """**Experimental.** Render an opcode in SSA functional form:

        ``out1, out2 = opcode immediates (in1, in2)``

    Outputs are comma-separated (no parens, no commas for a single
    output); inputs are always parenthesised. If the op has no outputs
    the ``… =`` prefix is omitted; if it has no inputs the RHS ends
    with ``()``. Phi labels in ``in*`` are expanded via
    :func:`phi_label`.

    When ``resolve_consts=True`` (default), every ``intc_*`` / ``intc N``
    / ``bytec_*`` / ``bytec N`` is replaced by the literal value read
    from the nearest dominating ``intcblock``/``bytecblock`` — so an
    ``intc_2`` under ``intcblock 0 1 10 3`` renders as ``10``, and a
    ``bytec_0`` under ``bytecblock 0x48 …`` renders as ``0x48``.
    """
    outs = stack_outputs(g, op)
    out_str = ", ".join(_def_label(v) for v in outs)

    # Const-block substitution: replace the whole RHS with the literal.
    if resolve_consts and _is_const_block_ref(op):
        cv = g.nodes[op].get("const_value")
        if cv is not None:
            _, value = cv
            return f"{out_str} = {value}" if outs else value

    ins = stack_inputs(g, op)
    code = op.code or op.ql_class
    opname, _, imms = code.partition(" ")
    in_str = "(" + ", ".join(_def_label(d) for d in ins) + ")"
    rhs = f"{opname} {imms} {in_str}" if imms else f"{opname} {in_str}"
    if outs:
        return f"{out_str} = {rhs}"
    return rhs


def print_ssa_functional(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    line_range: tuple[int, int] | None = None,
    resolve_consts: bool = True,
) -> None:
    """**Experimental.** Walk opcodes in source order, emitting :func:`ssa_functional`.

    Same file/line-range filtering semantics as :func:`print_ssa_trace`.
    Non-opcode AST nodes (labels, pragmas, source header) are skipped.
    Set ``resolve_consts=False`` to keep ``intc_*`` / ``bytec_*`` as-is
    instead of inlining their ``intcblock``/``bytecblock`` values.
    """
    from teal_ast import Opcode

    nodes = [
        n for n in g.nodes
        if isinstance(n, Opcode)
        and (file is None or n.location.file == file)
        and (line_range is None or line_range[0] <= n.location.start_line <= line_range[1])
    ]
    nodes.sort(key=lambda n: (n.location.file, n.location.start_line))
    for n in nodes:
        print(f"L{n.location.start_line:>4}: {ssa_functional(g, n, resolve_consts=resolve_consts)}")


def print_ssa_trace(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    line_range: tuple[int, int] | None = None,
    stack_active_only: bool = False,
) -> None:
    """Print a per-opcode in/out stack summary, walking ops in source order.

    By default every :class:`Opcode` is shown, even if it neither consumes
    nor produces stack values (``proto``, ``err``, unconditional branches,
    labels-via-ret, …). Non-opcode AST nodes (labels, pragmas, source
    header, …) are always skipped.

    ``file`` restricts to a single source file. ``line_range`` is an
    inclusive ``(lo, hi)`` window on start line. Set
    ``stack_active_only=True`` to hide opcodes with empty in/out.
    """
    from teal_ast import Opcode

    nodes = [
        n for n in g.nodes
        if isinstance(n, Opcode)
        and (file is None or n.location.file == file)
        and (line_range is None or line_range[0] <= n.location.start_line <= line_range[1])
    ]
    if stack_active_only:
        nodes = [
            n for n in nodes
            if g.nodes[n].get("stack_inputs") or g.nodes[n].get("stack_outputs")
        ]
    nodes.sort(key=lambda n: (n.location.file, n.location.start_line))
    for n in nodes:
        print(stack_summary(g, n))


# -- Basic-block view ---------------------------------------------------------


def cfg_bb_graph(g: nx.MultiDiGraph) -> nx.MultiDiGraph:
    """Return a CFG graph with every basic block collapsed into one node.

    Output nodes are :class:`BasicBlockNode` instances (carrying the ordered
    list of AST nodes inside) plus any :class:`PhiNode`s (preserved as side
    nodes at the block's entry, per the ``PhiIn``/``PhiOut`` header model).

    Edges:

    - Inter-BB CFG edges are kept with their original ``successor`` label.
    - ``PhiIn`` edges from an AST node are rewritten to originate from that
      node's host BB. ``PhiIn`` edges from another phi are kept as-is.
    - ``PhiOut`` edges go from the phi to its host BB (the consumer lives
      inside that BB in the op-level graph).
    - Dataflow edges are skipped (not meaningful at BB granularity).

    Requires that ``load_graph`` has annotated every AST node with a ``bb``
    attribute, which it does by default.
    """
    bb_cache: dict[tuple, BasicBlockNode] = {}

    def _bb_for_ast(n: AstNode) -> BasicBlockNode | None:
        bb_id = g.nodes[n].get("bb")
        if bb_id is None:
            return None
        bb = bb_cache.get(bb_id)
        if bb is None:
            bb = BasicBlockNode(*bb_id)
            bb_cache[bb_id] = bb
        return bb

    # First pass: materialize BB nodes and populate their ast_nodes list.
    for n in g.nodes:
        if isinstance(n, AstNode):
            bb = _bb_for_ast(n)
            if bb is not None:
                bb.ast_nodes.append(n)
    for bb in bb_cache.values():
        bb.ast_nodes.sort(key=lambda x: x.location.start_line)

    # Index BB-by-first-line for O(1) phi lookup.
    bb_by_first: dict[tuple[str, int], BasicBlockNode] = {
        (bb.file, bb.first_line): bb for bb in bb_cache.values()
    }

    # Second pass: attach phis to their host BB.
    phi_host: dict[PhiNode, BasicBlockNode] = {}
    for n in g.nodes:
        if isinstance(n, PhiNode):
            bb = bb_by_first.get((n.location.file, n.location.start_line))
            if bb is not None:
                bb.phis.append(n)
                phi_host[n] = bb
    for bb in bb_cache.values():
        bb.phis.sort(key=lambda p: (p.kind, p.stack_index))

    def _endpoint(n):
        if isinstance(n, BasicBlockNode):
            return n
        if isinstance(n, PhiNode):
            return n
        return _bb_for_ast(n)

    h = nx.MultiDiGraph()
    h.graph.update(g.graph)
    for bb in bb_cache.values():
        h.add_node(bb)
    for p in phi_host:
        h.add_node(p)

    for u, v, data in g.edges(data=True):
        if data.get("kind") != "cfg":
            continue
        succ = data.get("successor")
        u2 = _endpoint(u)
        v2 = _endpoint(v)
        if u2 is None or v2 is None:
            continue
        # Collapse intra-BB straight-line edges.
        if u2 is v2 and succ not in ("PhiIn", "PhiOut"):
            continue
        # Phi -> consumer edge: consumer sits inside the phi's host BB, so
        # this is always phi -> host BB at BB granularity.
        h.add_edge(u2, v2, kind="cfg", successor=succ)

    return h


def _bb_label(bb: BasicBlockNode, *, max_lines: int = 20) -> str:
    header = f"BB L{bb.first_line}-L{bb.last_line}"
    body_lines = [
        f"{n.location.start_line}: {n.code or n.ql_class}"
        for n in bb.ast_nodes
    ]
    if len(body_lines) > max_lines:
        elided = len(body_lines) - (max_lines - 1)
        body_lines = body_lines[: max_lines - 1] + [f"... (+{elided} more)"]
    return "\\l".join([header, ""] + body_lines) + "\\l"


def _bb_dot_id(n) -> str:
    if isinstance(n, BasicBlockNode):
        suffix = f"#{n.first_line}-{n.last_line}"
        return '"' + _dot_escape(f"BB:{n.file}{suffix}") + '"'
    return _dot_id(n)


def to_bb_dot(
    h: nx.MultiDiGraph,
    *,
    file: str | None = None,
    rankdir: str = "TB",
) -> str:
    """Emit DOT source for a BB-collapsed CFG graph (from :func:`cfg_bb_graph`)."""
    def _file_of(n) -> str:
        if isinstance(n, BasicBlockNode):
            return n.file
        return n.location.file

    nodes = [n for n in h.nodes if file is None or _file_of(n) == file]
    node_set = set(nodes)

    lines = [
        "digraph TEAL_BB {",
        f"  rankdir={rankdir};",
        "  overlap=false;",
        "  splines=true;",
        '  node [shape=box, fontname="Monospace", fontsize=9];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]

    def _sort_key(n):
        if isinstance(n, BasicBlockNode):
            return (n.file, n.first_line, 0, 0, 0)
        if isinstance(n, PhiNode):
            return (n.location.file, n.location.start_line, 1, n.kind, n.stack_index)
        return (n.location.file, n.location.start_line, 2, "", 0)

    for n in sorted(nodes, key=_sort_key):
        if isinstance(n, BasicBlockNode):
            attrs = (
                f'label="{_dot_escape(_bb_label(n))}", '
                'shape=box, style="rounded,filled", fillcolor="#f4f4f8"'
            )
        elif isinstance(n, PhiNode):
            label = phi_label(n)
            attrs = (
                f'label="{_dot_escape(label)}", shape=ellipse, style=dashed, '
                'color="#7f5ab6", fontcolor="#7f5ab6"'
            )
        else:
            body = n.code or n.ql_class
            label = f"{n.location.start_line}: {body}"
            attrs = f'label="{_dot_escape(label)}"'
        lines.append(f"  {_bb_dot_id(n)} [{attrs}];")

    for u, v, data in h.edges(data=True):
        if u not in node_set or v not in node_set:
            continue
        if data.get("kind") != "cfg":
            continue
        attrs = _edge_attrs(data)
        sep = " " if attrs else ""
        lines.append(f"  {_bb_dot_id(u)} -> {_bb_dot_id(v)}{sep}[{attrs}];")

    lines.append("}")
    return "\n".join(lines)


def draw_cfg_bb(
    g: nx.MultiDiGraph,
    *,
    file: str | None = None,
    format: str = "svg",
    engine: str = "dot",
    rankdir: str = "TB",
):
    """Render the CFG at basic-block granularity.

    Each BB becomes one labeled box listing its opcodes; phis hang off the
    block's entry as purple ellipses. Accepts either the full op-level
    graph (the BB collapse is done internally) or a pre-built BB graph
    from :func:`cfg_bb_graph`.
    """
    # Detect whether we got an op-level graph or an already-collapsed one.
    if any(isinstance(n, BasicBlockNode) for n in g.nodes):
        h = g
    else:
        h = cfg_bb_graph(g)
    return _render_dot(
        to_bb_dot(h, file=file, rankdir=rankdir),
        format=format, engine=engine,
    )
