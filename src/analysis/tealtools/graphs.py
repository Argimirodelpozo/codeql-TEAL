"""TEAL graph layer.

Build a NetworkX MultiDiGraph from a TEAL CodeQL database: typed
:class:`tealtools.ast.AstNode` nodes (one per opcode, hashed by
``(file, line)``) connected by ``kind="cfg"`` edges carrying a ``successor``
label. Only the extractor floor (``nodes`` / ``cfgEdges`` / ``basicBlocks``,
see ``QUERY_NAMES``) is loaded from CodeQL; SSA / phis / const values are
reconstructed in Python downstream (``tealtools.ssa``).

Quick start
-----------
    >>> from tealtools.graphs import load_graph
    >>> from .ast import Opcode, IntegerAddOpcode
    >>> g = load_graph("tests/dbs/xgov-db")
    >>> [n for n in g if isinstance(n, IntegerAddOpcode)]

Graphviz rendering of the loaded graph lives in :mod:`tealtools.viz`
(``to_dot`` / ``draw_cfg`` / ``cfg_bb_graph`` / ``draw_cfg_bb``).

The first call against a database runs the queries (~10s); subsequent calls
hit a per-db CSV cache invalidated by db mtime + query mtime.
"""
from __future__ import annotations

import csv
import hashlib
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import networkx as nx

from .ast import AstNode, Location, ast_node_from_row

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
    "basicBlocks",
)
# ``ssaOutputs`` / ``ssaInputs`` are no longer called: per-op stack
# arities now come from :func:`tealtools.opcode_sigs.op_arity`, and PySSA
# reconstructs the operand wiring + phis from those counts + the CFG
# (basicBlocks + cfgEdges). Only the extractor floor (nodes / cfgEdges /
# basicBlocks) is still loaded from CodeQL.
# ``dataflowEdges`` is no longer called: it was visualization-only; a
# def->use overlay is derivable from the reconstructed operand wiring if a
# renderer ever needs it again.
# ``constValues`` is no longer called: literal constants are computed in
# Python by :func:`tealtools.const_values.compute_const_values` (the
# post-load population near the end of ``load_graph``). The port keeps the
# real value in two cases QL drops — uint64 literals outside CodeQL's
# 32-bit ``.toInt()`` range, and ``intc`` in code the dominance predicate
# excludes (e.g. dead code). The ``elif q == "constValues"`` branch below
# is dead (kept, like the other dropped-query branches, as a re-enable hook).
# ``stackHeights`` is no longer called: its only reader was
# ``stacksim.py`` (since removed), and PySSA computes its own per-op
# heights in ``_phase5_heights``.
# ``valueIdentitySteps``, ``scratchInfluence``, ``innerTxnFields``
# are no longer called: PySSA's :func:`_apply_pyssa_to` populates
# the same annotations directly from the in-memory CFG.
#  - ``identity_steps``: shuffle-output identity (via
#    ``_shuffle_mapping``), single-source phi convergence, and
#    scratch-load↔store edges.
#  - ``scratch_stores``: per ``load N``, the set of ``store N``
#    value-keys that may reach it via the CFG (reaching-defs with
#    kill analysis in :func:`_compute_scratch_influence`).
# Same shape consumers (``propagate_constants``,
# ``propagate_scratch_constants``, taint engine step 2c, detectors)
# expect, so they keep working unchanged.
# ``mustValues`` is no longer called: PySSA's
# :meth:`SSAProgram.propagate_constants` + ``const_fold.py`` cover
# what it produced (literal pushes, identity flow, phi unification,
# arithmetic on resolved values, and now ``global ZeroAddress``
# field-narrowing via ``_fold_global_field``). The bytes-equality
# dominator narrowing in ``BytesPropagation.qll`` isn't ported yet
# but no fixture in the current test suite exercises it.
# ``phiNodes`` / ``phiEdges`` / ``phiArgs`` are intentionally NOT run
# at load time: :meth:`SSAProgram.__init__` now routes SSA
# construction through :class:`tealtools.ssa.PySSA` after the QL
# pre-pass, so the QL phi queries (in particular the
# ``[1..1000]``-bounded ``phiArgs.ql``) are dead weight. The ``.ql``
# files still live in ``queries/`` — they're not called from
# ``load_graph`` anymore, that's all.


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
    # ``codeql pack install`` resolves dependencies into the global
    # ``~/.codeql/packages`` cache; it doesn't create anything under
    # ``QUERIES_DIR/.codeql/pack`` (the old check looked there), so
    # without our own sentinel we'd pay ~5s of JVM startup per
    # ``load_graph`` call just to learn "Nothing to install". Track
    # install state with a marker file, invalidated when the pack
    # manifest or lockfile changes (those are the inputs to
    # dependency resolution).
    manifest = QUERIES_DIR / "qlpack.yml"
    lockfile = QUERIES_DIR / "codeql-pack.lock.yml"
    sentinel = QUERIES_DIR / ".pack_installed_sig"
    sig_parts: list[str] = []
    for p in (manifest, lockfile):
        if p.exists():
            sig_parts.append(f"{p.name}:{p.stat().st_mtime_ns}")
    sig = "|".join(sig_parts)
    if sentinel.exists() and sentinel.read_text() == sig:
        return
    _run([_codeql(), "pack", "install", str(QUERIES_DIR)])
    sentinel.write_text(sig)


def _run_csv_query(db: Path, query: Path, out_dir: Path) -> None:
    """Run one query and decode its result to CSV. Kept for the rare
    case where only one query is missing — but the common path is
    :func:`_run_queries_batch` which amortises JVM startup across all
    missing queries."""
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


# Pack identity for ``codeql database run-queries`` BQRS output paths.
# Must match ``QUERIES_DIR/qlpack.yml`` ``name:`` field.
_QL_PACK_NAME = "argimirodelpozo/tealtools"


def _run_queries_batch(
    db: Path, queries: list[Path], out_dir: Path, *, verbose: bool = True,
) -> None:
    """Run ``queries`` in a single ``codeql database run-queries``
    invocation (one JVM startup, parallel evaluation across cores)
    and decode all BQRS results into ``out_dir/<query>.csv``.

    The per-query alternative (one ``codeql query run`` subprocess
    each) pays ~7s JVM startup × N queries; batching collapses that
    to one startup."""
    if not queries:
        return
    if verbose:
        names = ", ".join(q.stem for q in queries)
        print(f"[tealtools.graphs] batch-running {len(queries)} "
              f"queries ({names}) ...", file=sys.stderr)
    _run([_codeql(), "database", "run-queries", "-j", "0", "--", str(db),
          *(str(q) for q in queries)])
    # ``codeql bqrs decode`` is one-file-per-invocation; running them
    # serially pays JVM startup N times. Parallelise the decodes — N
    # independent files, embarrassingly parallel, bounded by cores.
    from concurrent.futures import ThreadPoolExecutor
    import os as _os
    results_root = db / "results" / _QL_PACK_NAME
    decode_jobs: list[tuple[Path, Path]] = []
    for q in queries:
        bqrs = results_root / f"{q.stem}.bqrs"
        if not bqrs.exists():
            raise FileNotFoundError(
                f"codeql database run-queries did not produce {bqrs}; "
                f"check that ``{q}`` lives in the {_QL_PACK_NAME!r} pack."
            )
        decode_jobs.append((bqrs, out_dir / f"{q.stem}.csv"))

    def _decode_one(job: tuple[Path, Path]) -> None:
        bqrs, csv_out = job
        _run([_codeql(), "bqrs", "decode",
              "--format=csv",
              "--output", str(csv_out),
              str(bqrs)])

    # Cap workers to (cores, len(jobs)) — more than that wastes
    # context-switch overhead without speeding up.
    n_workers = min(len(decode_jobs), _os.cpu_count() or 4)
    with ThreadPoolExecutor(max_workers=n_workers) as ex:
        # Materialise the iterator so any raised exception in a worker
        # propagates here (otherwise it gets swallowed by the executor).
        list(ex.map(_decode_one, decode_jobs))


def _cache_dir_for(db: Path) -> Path:
    # Use ``codeql-database.yml`` mtime rather than the DB dir's own
    # mtime: ``codeql database run-queries`` writes to ``<db>/results/``
    # which bumps the dir's mtime and would otherwise invalidate the
    # cache on every run. The YAML manifest is stable across query
    # execution.
    manifest = db / "codeql-database.yml"
    manifest_mtime = (
        manifest.stat().st_mtime_ns if manifest.exists()
        else db.stat().st_mtime_ns
    )
    sig_parts = [str(db.resolve()), str(manifest_mtime)]
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

    # Batch-run any missing queries in a single ``codeql database
    # run-queries`` invocation — amortises ~7s JVM startup across the
    # set instead of paying it per query.
    missing = [QUERIES_DIR / f"{q}.ql"
               for q in QUERY_NAMES
               if not (cache / f"{q}.csv").exists()]
    if missing:
        _run_queries_batch(db, missing, cache, verbose=verbose)

    for q in QUERY_NAMES:
        csv_out = cache / f"{q}.csv"
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
        elif q == "basicBlocks":
            # Annotate each AstNode with its BB id = (file, firstLine, lastLine).
            for ast_file, ast_line, bb_first, bb_last in rows:
                node = by_loc.get((ast_file, int(ast_line)))
                if node is None:
                    continue
                g.nodes[node]["bb"] = (ast_file, int(bb_first), int(bb_last))

    # constValues port: resolved literal constants per output, computed in
    # Python (replaces ``constValues.ql``). Populates ``const_outputs``
    # ``{out_idx: (kind, value)}`` and the single-output back-compat scalar
    # ``const_value`` — the same shape the QL handler produced.
    from .const_values import compute_const_values
    for cf, cl, coi, ckind, cval in compute_const_values(g):
        node = by_loc.get((cf, int(cl)))
        if node is None:
            continue
        g.nodes[node].setdefault("const_outputs", {})[int(coi)] = (ckind, cval)
    for node in list(g.nodes):
        outs = g.nodes[node].get("const_outputs")
        if outs and len(outs) == 1 and 1 in outs:
            g.nodes[node]["const_value"] = outs[1]

    if verbose:
        print(
            f"[tealtools.graphs] loaded {g.number_of_nodes()} nodes, "
            f"{g.number_of_edges()} edges from {db.name}",
            file=sys.stderr,
        )
    return g


