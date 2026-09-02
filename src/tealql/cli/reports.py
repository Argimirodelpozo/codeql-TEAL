"""Report-style subcommands: auth, box-df, itxn-report, group-shape,
group-layout, functional, path-predicates, cfg, dump."""
from __future__ import annotations

import json as _json
import sys

from tealql.tealtools.diagnostics.errors import TealQLError

from ._common import (
    _emit_dict,
    _emit_findings,
    _load,
    _resolve,
)


def _cmd_auth(args) -> int:
    from tealql.tealtools.analysis.auth import AuthDominationDetector
    return _emit_findings(
        AuthDominationDetector(_load(args)).detect(),
        json_out=args.json_out,
    )


def _cmd_box_df(args) -> int:
    from tealql.tealtools.dataflow.box import (
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
    from tealql.tealtools.reporting.inner_transactions import InnerTxnReport
    r = InnerTxnReport(_load(args))
    return _emit_dict(r.to_dict(), json_out=args.json_out, text=r.render())


def _cmd_group_shape(args) -> int:
    from tealql.tealtools.cfg.group import analyze, analyze_per_exit
    prog = _load(args)
    if getattr(args, "per_exit", False):
        # DISTINCT shapes per approving exit, not their intersection — the common
        # summary drops any shape not shared by every exit.
        s = analyze_per_exit(prog)
    else:
        s = analyze(prog)
    return _emit_dict(s.to_dict(), json_out=args.json_out, text=s.render())


def _cmd_group_layout(args) -> int:
    from tealql.tealtools.cfg.group import analyze_layout
    layout = analyze_layout(_load(args))
    return _emit_dict(layout.to_dict(), json_out=args.json_out, text=layout.render())


def _cmd_functional(args) -> int:
    """Run the canonical SSA pipeline and print the functional dump."""
    from tealql.tealtools.analysis import functional_dump
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
    # `--json` is a common flag: honour it (a caller parsing stdout as JSON
    # must never get the text dump) — the dump has no structured form, so the
    # payload wraps it.
    print(_json.dumps({"text": out}, indent=2) if args.json_out else out)
    return 0


def _cmd_path_predicates(args) -> int:
    from tealql.tealtools.cfg.path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(_load(args))
    return _emit_dict(pp.to_dict(), json_out=args.json_out, text=pp.render())


def _cmd_cfg(args) -> int:
    from tealql.tealtools.cfg import CFG
    cfg = CFG.of(_load(args))
    dot = cfg.to_dot(file=args.file, with_assignments=not args.skeleton)
    if args.json_out:
        print(_json.dumps({"format": "dot", "dot": dot}, indent=2))
    else:
        print(dot)
    return 0


def _cmd_dump(args) -> int:
    import sys as _sys
    from tealql.tealtools.viz import CATALOG, CATALOG_BY_KEY, dump_all
    if args.list_views:
        if args.json_out:
            print(_json.dumps([
                {"key": view.key, "kind": view.kind.value,
                 "graph": "dot" if view.has_graph else "text", "title": view.title}
                for view in CATALOG], indent=2))
            return 0
        for view in CATALOG:
            graph = "dot" if view.has_graph else "text"
            print(f"{view.key:42} {view.kind.value:14} {graph:4}  {view.title}")
        return 0
    unknown = [key for key in args.views or () if key not in CATALOG_BY_KEY]
    if unknown:
        raise TealQLError(
            "unknown visualization view(s): " + ", ".join(unknown)
            + "; use 'tealql dump --list-views'"
        )
    source = str(_resolve(args))
    text = dump_all(
        source,
        args.out_dir,
        svg=not args.no_svg,
        registry=args.registry,
        group_members=args.group_members,
        views=args.views,
    )
    if args.out_dir:
        _sys.stderr.write(
            f"wrote full dump to {args.out_dir}/ "
            f"(contract.txt + one graph per applicable catalog view)\n")
        if args.json_out:
            print(_json.dumps({"out_dir": args.out_dir, "text": text}, indent=2))
    elif args.json_out:
        print(_json.dumps({"text": text}, indent=2))
    else:
        print(text, end="")
    return 0


def register(sub, add) -> None:
    add("auth", "auth-domination detector", _cmd_auth)

    box_df = add("box-df", "box dataflow (into / out / correlated)", _cmd_box_df)
    box_df.add_argument(
        "--flavour", required=True, choices=["into", "out", "correlated"],
        help="which box-dataflow analysis to run",
    )

    add("itxn-report", "inner-transaction report", _cmd_itxn_report)

    group_shape_p = add("group-shape", "forced group shape", _cmd_group_shape)
    group_shape_p.add_argument(
        "--per-exit", action="store_true",
        help="enumerate the DISTINCT group shapes per approving exit (ABI-labelled) "
             "instead of only the common shape across all exits")
    add("group-layout", "forced group size + per-position layout", _cmd_group_layout)

    add("path-predicates", "per-BB path predicates", _cmd_path_predicates)

    dump_p = add(
        "dump",
        "visualize every representation, analysis, and pass (debug)",
        _cmd_dump,
        optional_target=True,
    )
    dump_p.add_argument("-o", "--out-dir", default=None,
                        help="write contract.txt + every applicable graph into "
                             "this directory (else annotated text to stdout)")
    dump_p.add_argument("--no-svg", action="store_true",
                        help="write .dot instead of rendering .svg (no Graphviz needed)")
    dump_p.add_argument("--registry", default=None,
                        help="yaml AppID->.teal registry; adds the cross-contract super-CFG")
    dump_p.add_argument(
        "--group-member",
        dest="group_members",
        action="append",
        default=None,
        metavar="TEAL",
        help="ordered atomic-group member for analysis.group_taint; repeat in "
             "exact group order (the main target is not inserted implicitly)",
    )
    dump_p.add_argument(
        "--view",
        dest="views",
        action="append",
        default=None,
        metavar="KEY",
        help="render only this catalog key; repeat to select several",
    )
    dump_p.add_argument(
        "--list-views",
        action="store_true",
        help="list every maintained view key and exit",
    )

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
