"""CLI entry point for tealtools.

Each subcommand loads a CodeQL DB and runs one analysis, printing a
plain-text rendering. Use ``python -m tealtools --help`` to list
available subcommands.

The DB path is the same path you'd pass to ``SSAProgram(...)`` —
typically a directory created via ``codeql database create``.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable


def _load(db_path: str):
    from .ssa import SSAProgram
    return SSAProgram(db_path)


def _cmd_auth(args) -> int:
    from .auth_domination import AuthDominationDetector
    prog = _load(args.db)
    violations = AuthDominationDetector(prog).detect()
    if not violations:
        print("(no violations)")
    else:
        for v in violations:
            print(v.pretty())
    return 0


def _cmd_box_key(args) -> int:
    from .dataflow.nonunique_box_key import NonUniqueBoxKeyDetector
    prog = _load(args.db)
    violations = NonUniqueBoxKeyDetector(prog).detect()
    if not violations:
        print("(no violations)")
    else:
        for v in violations:
            print(v.pretty())
    return 0


def _cmd_box_df(args) -> int:
    from .dataflow.box import (
        detect_into_box_flows,
        detect_out_of_box_flows,
        detect_correlated_flows,
    )
    prog = _load(args.db)
    if args.flavour == "into":
        violations = detect_into_box_flows(prog)
    elif args.flavour == "out":
        violations = detect_out_of_box_flows(prog)
    else:
        violations = detect_correlated_flows(prog)
    if not violations:
        print("(no violations)")
    else:
        for v in violations:
            print(v.pretty())
    return 0


def _cmd_itxn_report(args) -> int:
    from .inner_txn_report import InnerTxnReport
    prog = _load(args.db)
    print(InnerTxnReport(prog).render())
    return 0


def _cmd_group_shape(args) -> int:
    from .group_reasoning import analyze
    prog = _load(args.db)
    print(analyze(prog).render())
    return 0


def _cmd_cost(args) -> int:
    from .cost_analysis import render
    prog = _load(args.db)
    print(render(prog))
    return 0


def _cmd_path_predicates(args) -> int:
    from .path_predicates import PathPredicateAnalysis
    prog = _load(args.db)
    print(PathPredicateAnalysis(prog).render())
    return 0


def _cmd_all(args) -> int:
    from .detector import run_all
    print(run_all(_load(args.db)), end="")
    return 0


def _cmd_cfg(args) -> int:
    from .cfg import CFG
    prog = _load(args.db)
    cfg = CFG.of(prog)
    print(cfg.to_dot(file=args.file, with_assignments=not args.skeleton))
    return 0


def _cmd_sec_guide(args) -> int:
    from .sec_guide import DETECTORS

    prog = _load(args.db)
    names = list(DETECTORS) if args.detector == "all" else [args.detector]
    any_findings = False
    for name in names:
        cls = DETECTORS[name]
        violations = cls(prog).detect()
        if args.detector == "all":
            print(f"=== sec-guide/{name} ===")
        if violations:
            any_findings = True
            for v in violations:
                print(v.pretty())
        elif args.detector == "all":
            print("(no findings)")
        if args.detector == "all":
            print()
    if args.detector != "all" and not any_findings:
        print("(no findings)")
    return 0


def _cmd_sec_guide_scan(args) -> int:
    from pathlib import Path
    from .sec_guide.scan import (
        DEFAULT_CACHE, ScanConfig, render_json, render_text, scan,
    )

    config = ScanConfig.from_path(Path(args.config)) if args.config else ScanConfig.empty()
    cache = Path(args.cache) if args.cache else DEFAULT_CACHE
    findings = scan(
        Path(args.root),
        config=config,
        cache_root=cache,
        verbose=args.verbose,
    )
    print(render_json(findings) if args.json else render_text(findings))
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
    caller = _load(args.caller_db)
    graph = XContractGraph.build(caller, registry)
    print(render_xcontract(graph.sites, graph.analyses))
    findings = cross_auth_findings(graph)
    if findings:
        print("\ncross-contract auth-domination findings:")
        print(render_findings(graph, findings))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m tealtools",
        description="TEAL static-analysis toolkit. "
                    "Each subcommand runs one analysis against a CodeQL DB.",
    )
    sub = p.add_subparsers(dest="cmd", required=True, metavar="<command>")

    def add_db(sp: argparse.ArgumentParser, fn: Callable):
        sp.add_argument("db", help="path to the CodeQL DB")
        sp.set_defaults(handler=fn)

    add_db(sub.add_parser("auth", help="auth-domination detector"), _cmd_auth)
    add_db(sub.add_parser("box-key", help="non-unique box-key detector"),
           _cmd_box_key)

    box_df = sub.add_parser("box-df", help="box dataflow (into / out / correlated)")
    box_df.add_argument("flavour", choices=["into", "out", "correlated"])
    add_db(box_df, _cmd_box_df)

    add_db(sub.add_parser("itxn-report", help="inner-transaction report"),
           _cmd_itxn_report)
    add_db(sub.add_parser("group-shape", help="forced group shape"),
           _cmd_group_shape)
    add_db(sub.add_parser("cost", help="per-line opcode cost"),
           _cmd_cost)
    add_db(sub.add_parser("path-predicates", help="per-BB path predicates"),
           _cmd_path_predicates)

    add_db(sub.add_parser("all", help="run every detector + report"),
           _cmd_all)

    cfg_p = sub.add_parser("cfg", help="dump basic-block CFG as Graphviz DOT")
    cfg_p.add_argument("db", help="path to the CodeQL DB")
    cfg_p.add_argument("--file", default=None,
                       help="restrict to a single source file (e.g. prog.teal)")
    cfg_p.add_argument("--skeleton", action="store_true",
                       help="omit assignments; show only BB labels + edges")
    cfg_p.set_defaults(handler=_cmd_cfg)

    xc = sub.add_parser("xcontract", help="cross-contract appcall analysis")
    xc.add_argument("caller_db", help="caller CodeQL DB")
    xc.add_argument("--registry", required=True,
                    help="yaml mapping AppID → callee DB path")
    xc.set_defaults(handler=_cmd_xcontract)

    from .sec_guide import DETECTORS as _SG
    sg = sub.add_parser(
        "sec-guide",
        help="run a security-guide detector (or all of them)",
    )
    sg.add_argument(
        "detector",
        choices=["all", *sorted(_SG.keys())],
        help="detector short name, or 'all' for the full sec-guide suite",
    )
    sg.add_argument("db", help="path to the CodeQL DB")
    sg.set_defaults(handler=_cmd_sec_guide)

    sgs = sub.add_parser(
        "sec-guide-scan",
        help="recursively scan a directory of .teal files; build per-dir DBs"
             " and run the configured sec-guide detectors on each program",
    )
    sgs.add_argument("root", help="directory to walk for .teal files")
    sgs.add_argument(
        "--config", default=None,
        help="optional yaml/json with `rules:` (match-glob → only/exclude detectors)",
    )
    sgs.add_argument(
        "--cache", default=None,
        help="DB cache root (default: ~/.cache/teal-sec-guide-scan/)",
    )
    sgs.add_argument(
        "--json", action="store_true",
        help="emit JSON findings instead of one-line-per-finding text",
    )
    sgs.add_argument(
        "-v", "--verbose", action="store_true",
        help="print DB-build progress to stderr",
    )
    sgs.set_defaults(handler=_cmd_sec_guide_scan)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
