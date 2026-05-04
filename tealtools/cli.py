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
    from .nonunique_box_key import NonUniqueBoxKeyDetector
    prog = _load(args.db)
    violations = NonUniqueBoxKeyDetector(prog).detect()
    if not violations:
        print("(no violations)")
    else:
        for v in violations:
            print(v.pretty())
    return 0


def _cmd_box_df(args) -> int:
    from .box_dataflow import (
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

    xc = sub.add_parser("xcontract", help="cross-contract appcall analysis")
    xc.add_argument("caller_db", help="caller CodeQL DB")
    xc.add_argument("--registry", required=True,
                    help="yaml mapping AppID → callee DB path")
    xc.set_defaults(handler=_cmd_xcontract)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
