"""``tealql`` — unified CLI for the TealQL static-analysis toolkit.

Each subcommand takes a single ``<target>`` and runs one analysis or
report against it. A target is one of:

* a ``.teal`` file, or
* a directory tree containing one or more ``.teal`` files.

The pipeline reconstructs everything (graph → SSA → analysis) straight
from that source — there is nothing to build, cache, or read.

Common flags accepted by every analysis subcommand:

  ``--json``           emit JSON instead of text
  ``-v`` / ``-vv``     progress logging to stderr (``-v`` = INFO
                       milestones, ``-vv`` = DEBUG per-pass timings)
  ``--strict``         refuse to analyze a partially-parsed program
                       (unparseable TEAL spans normally WARN and continue)

Exit codes (uniform across subcommands):

  ``0``  clean — analysis ran, no findings
  ``1``  findings — at least one detector reported something
  ``2``  error — bad target, unparseable source under ``--strict``,
         or any other expected failure (clean message on stderr)
"""
from __future__ import annotations

import argparse
import json as _json
import logging
import sys
from pathlib import Path
from typing import Callable, Iterable

from tealtools._utils.targets import resolve_target
from tealtools.errors import TealParseError, TealQLError

logger = logging.getLogger("tealtools.cli")


def _configure_logging(verbosity: int) -> None:
    """Wire the ``tealtools`` AND ``security`` logger hierarchies to stderr
    at a level set by the ``-v`` count: 0 → warnings only (quiet), 1
    (``-v``) → INFO progress milestones, 2+ (``-vv``) → DEBUG (per-pass
    timings, finer detail). Library modules emit through these hierarchies;
    the CLI is the only place a handler gets attached. (The ``security``
    package logs under its own root — e.g. ``security.scan`` progress —
    so both hierarchies need the handler or ``-v`` shows only half the
    pipeline.)"""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    for hierarchy in ("tealtools", "security"):
        root = logging.getLogger(hierarchy)
        root.setLevel(level)
        root.addHandler(handler)


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _add_target_args(sp: argparse.ArgumentParser, *, dest: str = "target") -> None:
    """Add the universal ``<target>`` positional and common flags."""
    sp.add_argument(
        dest,
        help="path to a .teal file or a directory of .teal files",
    )
    sp.add_argument("--json", action="store_true",
                    dest="json_out",
                    help="emit JSON instead of text")
    sp.add_argument("-v", "--verbose", action="count", default=0,
                    help="progress logging to stderr; repeat (-vv) for "
                         "per-pass timings")
    sp.add_argument("--strict", action="store_true",
                    help="exit 2 if any TEAL failed to parse instead of "
                         "analyzing the partial program with a warning")


def _resolve(args) -> Path:
    """Validate the target path (raises if it isn't TEAL source)."""
    return resolve_target(args.target)


def _check_parse_health(prog, args) -> None:
    """Surface unparseable-TEAL spans: the parser DROPS them, so analysis
    covers only part of the source. Default: loud warning (a partially-
    parsed contract must never read as silently clean). ``--strict``:
    raise, which the top level turns into exit code 2."""
    diags = getattr(prog, "parse_diagnostics", ())
    if not diags:
        return
    if getattr(args, "strict", False):
        raise TealParseError(diags)
    logger.warning(
        "%d TEAL span(s) failed to parse and were EXCLUDED from analysis — "
        "results may be incomplete (first: %s). Use --strict to make this "
        "fatal.", len(diags), diags[0],
    )


def _load(args):
    """Resolve target → :class:`SSAProgram`."""
    from tealtools.ssa import SSAProgram
    source = _resolve(args)
    logger.info("building SSA program from %s", source)
    prog = SSAProgram(str(source))
    logger.info("SSA program ready (%d assignments)", len(prog.assignments))
    _check_parse_health(prog, args)
    return prog


def _load_programs(args) -> "list[tuple]":
    """Resolve target → ``[(SSAProgram, file_filter), …]``, ONE program per
    ``.teal`` file. A directory of N contracts becomes N single-contract
    programs — not one merged program — because the AVM runs each program
    independently and strict-dominance / path-predicate detectors give wrong
    answers when several programs' entries and exits are pooled into one
    (the same reason ``security.scan`` builds per-file). ``file_filter`` is
    the basename for a multi-file target (so detectors scope to it) or
    ``None`` for a single file."""
    from tealtools._utils.targets import _discover_teal_files
    from tealtools.ssa import SSAProgram
    source = _resolve(args)
    teal_files = _discover_teal_files(Path(source))
    single = len(teal_files) == 1
    progs: list[tuple] = []
    for teal in teal_files:
        logger.info("building SSA program from %s", teal)
        prog = SSAProgram(str(teal))
        _check_parse_health(prog, args)
        progs.append((prog, None if single else teal.name))
    return progs


def _emit_findings(findings: Iterable, *, json_out: bool) -> int:
    """Standard renderer for finding-style output (auth, box-key, etc.).

    Returns 1 if any findings were emitted (non-zero exit signals
    "violations found"), 0 otherwise — convenient for CI usage.
    """
    findings = list(findings)
    if json_out:
        from tealtools._utils.serialize import finding_to_dict
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
    from tealtools.auth_domination import AuthDominationDetector
    return _emit_findings(
        AuthDominationDetector(_load(args)).detect(),
        json_out=args.json_out,
    )


def _cmd_box_df(args) -> int:
    from tealtools.dataflow.box import (
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
    from tealtools.inner_txn_report import InnerTxnReport
    r = InnerTxnReport(_load(args))
    return _emit_dict(r.to_dict(), json_out=args.json_out, text=r.render())


def _cmd_group_shape(args) -> int:
    from tealtools.group_reasoning import analyze
    s = analyze(_load(args))
    return _emit_dict(s.to_dict(), json_out=args.json_out, text=s.render())


def _cmd_group_layout(args) -> int:
    from tealtools.group_reasoning import analyze_layout
    layout = analyze_layout(_load(args))
    return _emit_dict(layout.to_dict(), json_out=args.json_out, text=layout.render())


def _cmd_cost(args) -> int:
    from tealtools import cost_analysis
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
    from tealtools.passes import functional_dump
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
    from tealtools.path_predicates import PathPredicateAnalysis
    pp = PathPredicateAnalysis(_load(args))
    return _emit_dict(pp.to_dict(), json_out=args.json_out, text=pp.render())


def _cmd_cfg(args) -> int:
    from tealtools.cfg import CFG
    cfg = CFG.of(_load(args))
    dot = cfg.to_dot(file=args.file, with_assignments=not args.skeleton)
    if args.json_out:
        print(_json.dumps({"format": "dot", "dot": dot}, indent=2))
    else:
        print(dot)
    return 0


def _cmd_xcontract(args) -> int:
    from tealtools.xcontract import (
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
        from tealtools._utils.serialize import finding_to_dict
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
        from security.config import DetectionConfig
        cfg = DetectionConfig.from_path(Path(args.config))
        return cfg.mode_for(str(args.target))
    return None


def _cmd_detections(args) -> int:
    from security import DETECTORS

    if args.list:
        for name in sorted(DETECTORS):
            print(name)
        return 0

    mode = _resolve_mode(args)
    programs = _load_programs(args)
    names = list(DETECTORS) if args.all else [args.detector]
    # Mode filtering applies to --all only; an explicit --detector is an
    # explicit request and runs regardless of declared mode.
    if mode is not None and args.all:
        names = [
            n for n in names
            if mode in getattr(DETECTORS[n], "applies_to",
                               frozenset({"app", "logicsig"}))
        ]
    if args.all:
        # Supersession dedup, AFTER mode filtering: a superseded detector is
        # skipped only when its superseder survived the filter and will run
        # (the superseder falls back to it internally on lift failure); an
        # explicit --detector request always runs as asked.
        from security.scan import default_detection_names
        names = default_detection_names(names)
    logger.info("running %d detection(s) on %d program(s) (mode=%s)",
                len(names), len(programs), mode or "unfiltered")

    def _run(name):
        # A detector's findings across every per-file program (one entry
        # unless the target was a multi-file directory).
        cls = DETECTORS[name]
        found = []
        for prog, file in programs:
            found.extend(cls(prog, file=file).detect())
        logger.info("  %s: %d finding(s)", name, len(found))
        return found

    if args.json_out:
        from tealtools._utils.serialize import finding_to_dict
        out = {name: [finding_to_dict(v) for v in _run(name)] for name in names}
        print(_json.dumps(out, indent=2))
        any_findings = any(v for v in out.values())
    else:
        any_findings = False
        for name in names:
            violations = _run(name)
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
    from security.scan import (
        DetectionOptions, ScanConfig, failures, render_json, render_text, scan,
    )
    from security.config import ConfigError, DetectionConfig

    options = None
    if args.options:
        if args.config or args.mode_config:
            raise ConfigError(
                "--options is the unified config (selection + modes + "
                "severity + fail_on); pass it INSTEAD of --config/--mode-config")
        options = DetectionOptions.from_path(Path(args.options))
    config = ScanConfig.from_path(Path(args.config)) if args.config else ScanConfig.empty()
    detection_config = (
        DetectionConfig.from_path(Path(args.mode_config))
        if args.mode_config else None
    )
    findings = scan(
        Path(args.root),
        config=config,
        detection_config=detection_config,
        options=options,
        strict=getattr(args, "strict", False),
    )
    print(render_json(findings) if args.json_out else render_text(findings))
    # Exit 1 only on FAILURES: with --options, findings below fail_on
    # (informational is-deletable style) are reported but don't fail CI.
    return 1 if failures(findings, options) else 0


def _cmd_all(args) -> int:
    from security.run import run_all_dict, run_all_findings
    prog = _load(args)
    if args.json_out:
        payload = run_all_dict(prog)
        print(_json.dumps(payload, indent=2))
        n_findings = sum(len(v) for v in payload["detectors"].values())
    else:
        text, n_findings = run_all_findings(prog)
        print(text, end="")
    return 1 if n_findings else 0


def _cmd_dump(args) -> int:
    import sys as _sys
    from tealtools.viz import dump_all
    source = str(_resolve(args))
    text = dump_all(source, args.out_dir, svg=not args.no_svg, registry=args.registry)
    if args.out_dir:
        _sys.stderr.write(
            f"wrote full dump to {args.out_dir}/ "
            f"(contract.txt + graph/cfg/ssa/control_tree)\n")
    else:
        print(text, end="")
    return 0


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tealql",
        description="TEAL static-analysis toolkit. Each subcommand "
                    "runs one analysis or report against a target "
                    "(.teal file or directory of .teal files).",
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
    add("group-layout", "forced group size + per-position layout", _cmd_group_layout)
    add("cost", "per-line opcode cost", _cmd_cost)
    add("path-predicates", "per-BB path predicates", _cmd_path_predicates)
    add("all", "run every detector + report", _cmd_all)

    dump_p = add("dump", "dump EVERY representation of a contract (debug)", _cmd_dump)
    dump_p.add_argument("-o", "--out-dir", default=None,
                        help="also write contract.txt + graph/cfg/ssa/control_tree "
                             ".svg files into this dir (else text to stdout)")
    dump_p.add_argument("--no-svg", action="store_true",
                        help="write .dot instead of rendering .svg (no Graphviz needed)")
    dump_p.add_argument("--registry", default=None,
                        help="yaml AppID->.teal registry; adds the cross-contract super-CFG")

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
                    help="yaml mapping AppID → callee .teal path")

    from security import DETECTORS as _DETECTORS
    det = sub.add_parser(
        "detections",
        help="run one (or every) Algorand-security-guide detection",
    )
    det.set_defaults(handler=_cmd_detections)
    # Target is optional here because ``--list`` doesn't need one.
    det.add_argument(
        "target", nargs="?", default=None,
        help="path to a .teal file or a directory of .teal files "
             "(omit when using --list)",
    )
    det.add_argument("--json", action="store_true", dest="json_out",
                     help="emit JSON instead of text")
    det.add_argument("-v", "--verbose", action="count", default=0,
                     help="progress logging to stderr; repeat (-vv) for "
                          "per-pass timings")
    det.add_argument("--strict", action="store_true",
                     help="exit 2 if any TEAL failed to parse instead of "
                          "analyzing the partial program with a warning")
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
                       help="run every detection (skipping ones superseded "
                            "by a successor that also runs)")
    group.add_argument("--list", action="store_true",
                       help="list available detector short names and exit")

    # detections-scan is structurally different: it walks a directory of
    # .teal files and reconstructs each parent dir's SSA, so it bypasses
    # ``resolve_target``. Route --json / --verbose through the same flags.
    sgs = sub.add_parser(
        "detections-scan",
        help="recursively scan a directory of .teal files; reconstruct "
             "each dir and run detections on every program",
    )
    sgs.add_argument("root", help="directory to walk for .teal files")
    sgs.add_argument("--options", default=None,
                     help="ONE yaml/json with everything: `detectors:` "
                          "selection rules, `modes:` app/logicsig scoping, "
                          "per-detector `severity:` overrides, `fail_on:` "
                          "exit-code threshold, `auto_mode:`. Replaces "
                          "--config/--mode-config")
    sgs.add_argument("--config", default=None,
                     help="yaml/json with `rules:` for per-file detector selection")
    sgs.add_argument("--mode-config", default=None,
                     help="yaml/json with `modes:` declaring each file's "
                          "app/logicsig mode; detectors that don't apply to "
                          "a file's mode are skipped")
    sgs.add_argument("--json", action="store_true", dest="json_out",
                     help="emit JSON findings instead of text")
    sgs.add_argument("-v", "--verbose", action="count", default=0,
                     help="progress logging to stderr; repeat (-vv) for "
                          "per-pass timings")
    sgs.add_argument("--strict", action="store_true",
                     help="exit 2 if any scanned file fails to parse or "
                          "reconstruct instead of skipping it with a warning")
    sgs.set_defaults(handler=_cmd_detections_scan)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))
    try:
        return args.handler(args)
    except (TealQLError, FileNotFoundError) as e:
        # Every EXPECTED failure (bad target, --strict parse refusal, …)
        # exits 2 with a clean message; genuine bugs still traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
