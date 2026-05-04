"""TEAL graph layer.

Build a NetworkX MultiDiGraph from a TEAL CodeQL database, with CFG and
dataflow edges as separate edge kinds. Aimed at Jupyter / REPL exploration.

Quick start
-----------
    >>> from teal_graphs import load_graph, cfg_view, dataflow_view
    >>> g = load_graph("test-dbs/xgov-db")
    >>> g.number_of_nodes(), g.number_of_edges()
    >>> # All CFG successors of a given opcode:
    >>> list(cfg_view(g).successors(("source.teal", 42)))

Each node is keyed by ``(file, line)`` and carries ``qlClass`` + ``text``
attributes. Each edge has a ``kind`` attribute ("cfg" or "dataflow"); CFG
edges additionally carry ``successor`` (the ``SuccessorType`` string).

The first call against a database compiles + runs three queries (~10-30s);
subsequent calls hit a per-db CSV cache invalidated by db mtime + query mtime.
"""
from __future__ import annotations

import csv
import hashlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

import networkx as nx

QUERIES_DIR = Path(__file__).resolve().parent / "queries"
DEFAULT_CACHE = Path(
    os.environ.get("TEAL_GRAPHS_CACHE", Path.home() / ".cache" / "teal-graphs")
)
QUERY_NAMES = ("nodes", "cfgEdges", "dataflowEdges")


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
    h = hashlib.sha256("|".join(sig_parts).encode()).hexdigest()[:16]
    out = DEFAULT_CACHE / h
    out.mkdir(parents=True, exist_ok=True)
    return out


def _read_csv(path: Path) -> list[list[str]]:
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)  # header
        return list(reader)


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

    for q in QUERY_NAMES:
        csv_out = cache / f"{q}.csv"
        if not csv_out.exists():
            if verbose:
                print(f"[teal_graphs] running {q}.ql ...", file=sys.stderr)
            _run_csv_query(db, QUERIES_DIR / f"{q}.ql", cache)
        rows = _read_csv(csv_out)

        if q == "nodes":
            for file, line, ql_class, text in rows:
                g.add_node((file, int(line)), qlClass=ql_class, text=text)
        elif q == "cfgEdges":
            for sf, sl, df, dl, t in rows:
                g.add_edge((sf, int(sl)), (df, int(dl)),
                           kind="cfg", successor=t)
        elif q == "dataflowEdges":
            for sf, sl, df, dl in rows:
                g.add_edge((sf, int(sl)), (df, int(dl)), kind="dataflow")

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
}


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _dot_id(n: tuple) -> str:
    return '"' + _dot_escape(f"{n[0]}:{n[1]}") + '"'


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
    to nodes from one source file. Nodes labeled ``L<line>: <opcode>``.
    """
    nodes = [(n, d) for n, d in g.nodes(data=True) if file is None or n[0] == file]
    node_set = {n for n, _ in nodes}

    lines = [
        "digraph TEAL {",
        f"  rankdir={rankdir};",
        '  node [shape=box, fontname="Monospace", fontsize=10];',
        '  edge [fontname="Monospace", fontsize=9];',
    ]
    for n, d in sorted(nodes, key=lambda t: (t[0][0], t[0][1])):
        label = f"L{n[1]}: {d.get('qlClass', '')}"
        lines.append(f'  {_dot_id(n)} [label="{_dot_escape(label)}"];')

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
    """Render dataflow edges as a DOT graph (dot engine; for force-directed use engine='fdp')."""
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
