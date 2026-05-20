"""``tealql`` — unified CLI for the TealQL static-analysis toolkit.

Each subcommand takes a single ``<target>`` and runs one analysis or
report against it. A target is one of:

* an existing CodeQL DB directory (contains ``codeql-database.yml``),
* a ``.teal`` file, or
* a directory tree containing one or more ``.teal`` files.

When the target is raw source, a DB is built on the fly and cached
under ``~/.cache/tealql/dbs/`` (override via ``$TEALQL_DB_CACHE``).
Subsequent runs on the same inputs are no-ops in the DB layer.

Common flags accepted by every analysis subcommand:

  ``--json``           emit JSON instead of text
  ``--db-cache DIR``   alternative cache root for auto-built DBs
  ``--force-rebuild``  rebuild the DB even if a cached one exists
  ``-v / --verbose``   show DB-build progress on stderr

A ``debug`` namespace exposes raw CodeQL operations (``debug query``,
``debug db``, ``debug cache``) for power-user troubleshooting and for
running custom QL packs against the same target abstraction.
"""
from __future__ import annotations

import argparse
import json as _json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Iterable

from .targets import (
    DEFAULT_CACHE, build_db_for_dir, is_codeql_db, resolve_target,
)


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _add_target_args(sp: argparse.ArgumentParser, *, dest: str = "target") -> None:
    """Add the universal ``<target>`` positional and common flags."""
    sp.add_argument(
        dest,
        help="path to a .teal file, a directory of .teal files, "
             "or an existing CodeQL DB",
    )
    sp.add_argument("--json", action="store_true",
                    dest="json_out",
                    help="emit JSON instead of text")
    sp.add_argument("--db-cache", default=None,
                    help=f"DB cache root (default: {DEFAULT_CACHE})")
    sp.add_argument("--force-rebuild", action="store_true",
                    help="rebuild the DB even if already cached")
    sp.add_argument("-v", "--verbose", action="store_true",
                    help="print DB-build progress to stderr")


def _resolve(args) -> Path:
    """Run :func:`resolve_target` with the args namespace's flags."""
    return resolve_target(
        args.target,
        cache_root=Path(args.db_cache) if args.db_cache else DEFAULT_CACHE,
        force_rebuild=args.force_rebuild,
        verbose=args.verbose,
    )


def _load(args):
    """Resolve target → DB → :class:`SSAProgram`."""
    from .ssa import SSAProgram
    return SSAProgram(str(_resolve(args)))


def _emit_findings(findings: Iterable, *, json_out: bool) -> int:
    """Standard renderer for finding-style output (auth, box-key, etc.).

    Returns 1 if any findings were emitted (non-zero exit signals
    "violations found"), 0 otherwise — convenient for CI usage.
    """
    findings = list(findings)
    if json_out:
        from .serialize import finding_to_dict
        print(_json.dumps([finding_to_dict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("(no violations)")
        else:
            for v in findings:
                print(v.pretty())
    return 1 if findings else 0


def _emit_dict(payload: dict, *, json_out: bool, text: str) -> int:
    """Standard renderer for report-style output. Caller pre-computes
    both the dict (used under --json) and the text (used otherwise)."""
    print(_json.dumps(payload, indent=2) if json_out else text)
    return 0


# ---------------------------------------------------------------------------
# Analysis subcommands
# ---------------------------------------------------------------------------


def _cmd_auth(args) -> int:
    from .auth_domination import AuthDominationDetector
    return _emit_findings(
        AuthDominationDetector(_load(args)).detect(),
        json_out=args.json_out,
    )


def _cmd_box_df(args) -> int:
    from .dataflow.box import (
        detect_into_box_flows,
        detect_out_of_box_flows,
        detect_correlated_flows,
    )
    prog = _load(args)
    fn = {
        "into": detect_into_box_flows,
        "out": detect_out_of_box_flows,
        "correlated": detect_correlated_flows,
    }[args.flavour]
    return _emit_findings(fn(prog), json_out=args.json_out)


def _cmd_itxn_report(args) -> int:
    from .inner_txn_report import InnerTxnReport
    r = InnerTxnReport(_load(args))
    return _emit_dict(r.to_dict(), json_out=args.json_out, text=r.render())


def _cmd_group_shape(args) -> int:
    from .group_reasoning import analyze
    s = analyze(_load(args))
    return _emit_dict(s.to_dict(), json_out=args.json_out, text=s.render())


def _cmd_cost(args) -> int:
    from . import cost_analysis
    prog = _load(args)
    return _emit_dict(
        cost_analysis.to_dict(prog),
        json_out=args.json_out,
        text=cost_analysis.render(prog),
    )


def _cmd_functional(args) -> int:
    """Run the canonical SSA pipeline and print the functional dump.

    ``--show-ranges`` adds inline ``/*[V<=hi]*/`` IntRange comments on
    uint64 SSAVars (the substrate's existing renderer flag).
    ``--show-bytes`` adds inline ``/*len=N*/`` / ``/*val=...*/``
    annotations on bytes-typed SSAVars (post-process via
    :mod:`tealtools.render_annotated`). ``--by-block`` groups
    assignments per basic block with predecessor/successor headers.
    """
    from .passes import functional_dump
    prog = _load(args)
    line_range = None
    if args.line_range:
        try:
            lo, hi = (int(x) for x in args.line_range.split("-", 1))
            line_range = (lo, hi)
        except ValueError:
            print(f"error: --line-range expects 'LO-HI', got {args.line_range!r}",
                  file=sys.stderr)
            return 2
    out = functional_dump(
        prog,
        file=args.file,
        line_range=line_range,
        by_block=args.by_block,
        show_ranges=args.show_ranges,
        show_bytes=args.show_bytes,
    )
    print(out)
    return 0


def _cmd_path_predicates(args) -> int:
    from .path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(_load(args))
    return _emit_dict(pp.to_dict(), json_out=args.json_out, text=pp.render())


def _cmd_cfg(args) -> int:
    from .cfg import CFG
    cfg = CFG.of(_load(args))
    dot = cfg.to_dot(file=args.file, with_assignments=not args.skeleton)
    if args.json_out:
        print(_json.dumps({"format": "dot", "dot": dot}, indent=2))
    else:
        print(dot)
    return 0


def _cmd_xcontract(args) -> int:
    from .xcontract import (
        XContractGraph,
        cross_auth_findings,
        load_registry,
        render_xcontract,
        render_findings,
    )
    registry = load_registry(args.registry)
    caller = _load(args)
    graph = XContractGraph.build(caller, registry)
    findings = cross_auth_findings(graph)
    if args.json_out:
        from .serialize import finding_to_dict
        payload = {
            "sites": [s.to_dict() for s in graph.sites],
            "cross_auth_findings": [finding_to_dict(f) for f in findings],
        }
        print(_json.dumps(payload, indent=2))
    else:
        print(render_xcontract(graph.sites, graph.analyses))
        if findings:
            print("\ncross-contract auth-domination findings:")
            print(render_findings(graph, findings))
    return 1 if findings else 0


def _resolve_mode(args) -> "str | None":
    """Determine the declared detection mode (``"app"`` / ``"logicsig"``
    / ``None``) for the target. ``--mode`` wins outright; otherwise a
    ``--config`` file is consulted by matching the *target string*
    against its globs. ``None`` means "unfiltered — run every
    detector"; no opcode inference happens."""
    if args.mode:
        return args.mode
    if args.config:
        from .detections.config import DetectionConfig
        cfg = DetectionConfig.from_path(Path(args.config))
        return cfg.mode_for(str(args.target))
    return None


def _cmd_detections(args) -> int:
    from .detections import DETECTORS

    if args.list:
        for name in sorted(DETECTORS):
            print(name)
        return 0

    mode = _resolve_mode(args)
    prog = _load(args)
    names = list(DETECTORS) if args.all else [args.detector]
    # Mode filtering applies to --all only; an explicit --detector is an
    # explicit request and runs regardless of declared mode.
    if mode is not None and args.all:
        names = [
            n for n in names
            if mode in getattr(DETECTORS[n], "applies_to",
                               frozenset({"app", "logicsig"}))
        ]
    if args.json_out:
        from .serialize import finding_to_dict
        out: dict[str, list] = {}
        for name in names:
            cls = DETECTORS[name]
            out[name] = [finding_to_dict(v) for v in cls(prog).detect()]
        print(_json.dumps(out, indent=2))
        any_findings = any(v for v in out.values())
    else:
        any_findings = False
        for name in names:
            cls = DETECTORS[name]
            violations = cls(prog).detect()
            if args.all:
                print(f"=== sec-guide/{name} ===")
            if violations:
                any_findings = True
                for v in violations:
                    print(v.pretty())
            elif args.all:
                print("(no findings)")
            if args.all:
                print()
        if not args.all and not any_findings:
            print("(no findings)")
    return 1 if any_findings else 0


def _cmd_detections_scan(args) -> int:
    from .detections.scan import (
        DEFAULT_CACHE as SCAN_CACHE,
        ScanConfig, render_json, render_text, scan,
    )
    from .detections.config import DetectionConfig

    config = ScanConfig.from_path(Path(args.config)) if args.config else ScanConfig.empty()
    detection_config = (
        DetectionConfig.from_path(Path(args.mode_config))
        if args.mode_config else None
    )
    cache = Path(args.cache) if args.cache else SCAN_CACHE
    findings = scan(
        Path(args.root),
        config=config,
        cache_root=cache,
        verbose=args.verbose,
        detection_config=detection_config,
    )
    print(render_json(findings) if args.json_out else render_text(findings))
    return 1 if findings else 0


def _cmd_all(args) -> int:
    from .detector import run_all, run_all_dict
    prog = _load(args)
    if args.json_out:
        print(_json.dumps(run_all_dict(prog), indent=2))
    else:
        print(run_all(prog), end="")
    return 0


# ---------------------------------------------------------------------------
# debug namespace (CodeQL passthrough + cache inspection)
# ---------------------------------------------------------------------------


def _cmd_debug_query(args) -> int:
    """Run a ``.ql`` file against the resolved target using the local
    ``codeql`` binary. Output goes to stdout; pass ``--output`` to
    persist the BQRS. Equivalent to ``codeql query run <ql>
    --database <db>`` plus optional decode."""
    db = _resolve(args)
    codeql = shutil.which("codeql")
    if codeql is None:
        print("error: codeql binary not found on PATH", file=sys.stderr)
        return 2
    cmd = [codeql, "query", "run", str(Path(args.ql).resolve()),
           "--database", str(db)]
    if args.output:
        cmd += ["--output", args.output]
    cmd += list(args.extra)
    return subprocess.run(cmd).returncode


def _cmd_debug_db(args) -> int:
    """Resolve target → DB path. Useful for plumbing a DB into other
    tools without going through any analysis."""
    db = _resolve(args)
    if args.json_out:
        print(_json.dumps({"db": str(db)}, indent=2))
    else:
        print(db)
    return 0


def _cmd_debug_cache(args) -> int:
    """Inspect or clear the auto-built-DB cache."""
    cache = Path(args.db_cache) if args.db_cache else DEFAULT_CACHE
    if args.action == "info":
        if not cache.exists():
            payload = {"path": str(cache), "exists": False, "entries": 0}
        else:
            entries = [p for p in cache.iterdir() if p.is_dir()]
            payload = {
                "path": str(cache), "exists": True,
                "entries": len(entries),
                "ids": sorted(p.name for p in entries),
            }
        if args.json_out:
            print(_json.dumps(payload, indent=2))
        else:
            print(f"cache: {payload['path']}")
            if not payload["exists"]:
                print("  (empty, will be created on first build)")
            else:
                print(f"  {payload['entries']} cached DB(s)")
        return 0
    if args.action == "clear":
        if cache.exists():
            shutil.rmtree(cache)
            print(f"removed {cache}")
        else:
            print(f"(nothing to remove at {cache})")
        return 0
    raise AssertionError(f"unknown action {args.action!r}")


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tealql",
        description="TEAL static-analysis toolkit. Each subcommand "
                    "runs one analysis or report against a target "
                    "(.teal file/dir or a pre-built CodeQL DB).",
    )
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")

    def add(name: str, help_: str, handler: Callable) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        _add_target_args(sp)
        sp.set_defaults(handler=handler)
        return sp

    add("auth", "auth-domination detector", _cmd_auth)

    box_df = add("box-df", "box dataflow (into / out / correlated)", _cmd_box_df)
    box_df.add_argument(
        "--flavour", required=True, choices=["into", "out", "correlated"],
        help="which box-dataflow analysis to run",
    )

    add("itxn-report", "inner-transaction report", _cmd_itxn_report)
    add("group-shape", "forced group shape", _cmd_group_shape)
    add("cost", "per-line opcode cost", _cmd_cost)
    add("path-predicates", "per-BB path predicates", _cmd_path_predicates)
    add("all", "run every detector + report", _cmd_all)

    func_p = add(
        "functional",
        "SSA functional dump after the canonical pipeline "
        "(constants, ranges, byte_lengths, bytemath, …)",
        _cmd_functional,
    )
    func_p.add_argument("--file", default=None,
                        help="restrict to a single source file (e.g. prog.teal)")
    func_p.add_argument("--line-range", default=None,
                        help="restrict to a LO-HI source-line range")
    func_p.add_argument("--show-ranges", action="store_true",
                        help="inline /*[V<=hi]*/ IntRange annotations on uint64 vars")
    func_p.add_argument("--show-bytes", action="store_true",
                        help="inline /*len=N val=...*/ annotations on bytes vars")
    func_p.add_argument("--by-block", action="store_true",
                        help="group assignments per basic block with pred/succ headers")

    cfg_p = add("cfg", "dump basic-block CFG as Graphviz DOT", _cmd_cfg)
    cfg_p.add_argument("--file", default=None,
                       help="restrict to a single source file (e.g. prog.teal)")
    cfg_p.add_argument("--skeleton", action="store_true",
                       help="omit assignments; show only BB labels + edges")

    xc = add("xcontract", "cross-contract appcall analysis", _cmd_xcontract)
    xc.add_argument("--registry", required=True,
                    help="yaml mapping AppID → callee DB path")

    from .detections import DETECTORS as _DETECTORS
    det = sub.add_parser(
        "detections",
        help="run one (or every) Algorand-security-guide detection",
    )
    det.set_defaults(handler=_cmd_detections)
    # Target is optional here because ``--list`` doesn't need one.
    det.add_argument(
        "target", nargs="?", default=None,
        help="path to a .teal file, a directory of .teal files, "
             "or an existing CodeQL DB (omit when using --list)",
    )
    det.add_argument("--json", action="store_true", dest="json_out",
                     help="emit JSON instead of text")
    det.add_argument("--db-cache", default=None,
                     help=f"DB cache root (default: {DEFAULT_CACHE})")
    det.add_argument("--force-rebuild", action="store_true",
                     help="rebuild the DB even if already cached")
    det.add_argument("-v", "--verbose", action="store_true",
                     help="print DB-build progress to stderr")
    det.add_argument("--mode", choices=["app", "logicsig"], default=None,
                     help="declare the target's mode; with --all, skips "
                          "detectors that don't apply to that mode")
    det.add_argument("--config", default=None,
                     help="detection-mode config (yaml/json); the target "
                          "path is matched against its globs to pick a mode")
    group = det.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--detector", choices=sorted(_DETECTORS.keys()),
        help="detector short name (e.g. fee-validation)",
    )
    group.add_argument("--all", action="store_true",
                       help="run every detection")
    group.add_argument("--list", action="store_true",
                       help="list available detector short names and exit")

    # detections-scan is structurally different: it walks a directory of
    # .teal files and builds one DB per parent dir, so it bypasses
    # ``resolve_target``. Keep its flag shape intact, but route --json /
    # --verbose through the same shared flags.
    sgs = sub.add_parser(
        "detections-scan",
        help="recursively scan a directory of .teal files; build "
             "per-dir DBs and run detections on each program",
    )
    sgs.add_argument("root", help="directory to walk for .teal files")
    sgs.add_argument("--config", default=None,
                     help="yaml/json with `rules:` for per-file detector selection")
    sgs.add_argument("--mode-config", default=None,
                     help="yaml/json with `modes:` declaring each file's "
                          "app/logicsig mode; detectors that don't apply to "
                          "a file's mode are skipped")
    sgs.add_argument("--cache", default=None,
                     help="DB cache root (default: ~/.cache/tealql/sec-guide-scan/)")
    sgs.add_argument("--json", action="store_true", dest="json_out",
                     help="emit JSON findings instead of text")
    sgs.add_argument("-v", "--verbose", action="store_true",
                     help="print DB-build progress to stderr")
    sgs.set_defaults(handler=_cmd_detections_scan)

    # --- debug namespace ---------------------------------------------
    dbg = sub.add_parser(
        "debug",
        help="CodeQL passthrough + cache inspection (power-user)",
    )
    dbg_sub = dbg.add_subparsers(dest="debug_cmd", required=True, metavar="<subcommand>")

    q = dbg_sub.add_parser("query", help="run a .ql file against a target")
    q.add_argument("ql", help="path to a .ql query file")
    _add_target_args(q)
    q.add_argument("--output", default=None,
                   help="optional .bqrs output path (passed through to codeql)")
    q.add_argument("extra", nargs=argparse.REMAINDER,
                   help="extra args forwarded to `codeql query run` "
                        "(prefix with --)")
    q.set_defaults(handler=_cmd_debug_query)

    d = dbg_sub.add_parser("db", help="resolve target → DB path (build if needed)")
    _add_target_args(d)
    d.set_defaults(handler=_cmd_debug_db)

    c = dbg_sub.add_parser("cache", help="inspect or clear the DB cache")
    c.add_argument("action", choices=["info", "clear"])
    c.add_argument("--db-cache", default=None, help="alternative cache root")
    c.add_argument("--json", action="store_true", dest="json_out")
    c.set_defaults(handler=_cmd_debug_cache)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as e:
        print(f"error: codeql exited with code {e.returncode}", file=sys.stderr)
        return e.returncode


if __name__ == "__main__":
    sys.exit(main())
