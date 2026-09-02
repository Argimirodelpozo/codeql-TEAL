"""Security subcommands: taint-query, all, xcontract, audit,
group-taint, detections, detections-scan."""
from __future__ import annotations

import json as _json
import sys
from pathlib import Path

from tealql.tealtools.diagnostics.errors import TealQLError

from ._common import (
    _check_parse_health,
    _add_common_flags,
    _load,
    _load_programs,
    logger,
)


def _cmd_audit(args) -> int:
    """Fetch deployed app ``<ID>`` and its callees from chain, run every app-mode
    detector, and print a consolidated report; exit 2 if the app can't be fetched.

    NETWORK-touching: the mainnet API for program bytes plus a local algod on
    :4001 for disassembly (both env-overridable), cached under ``--cache-dir``."""
    from tealql.tealtools._utils.chain import fetch_approval
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.intercontract.analysis import _DEFAULT_CALLEE_CACHE, XContractGraph
    from tealql.security import DETECTORS
    from tealql.security.scan import default_detection_names

    app_id = args.app_id
    cache = Path(args.cache_dir) if args.cache_dir else _DEFAULT_CALLEE_CACHE
    cache.mkdir(parents=True, exist_ok=True)
    teal_path = cache / f"app_{app_id}.teal"
    if not teal_path.exists():
        try:
            teal, _bc = fetch_approval(app_id)
        except Exception as e:
            print(f"error: could not fetch app {app_id} from chain ({e}). "
                  "The program bytes come from the mainnet API and disassembly "
                  "needs a local algod (:4001) — see TEAL_ALGOD_* env vars.",
                  file=sys.stderr)
            return 2
        teal_path.write_text(teal)
    caller = SSAProgram(str(teal_path), strict=False)
    # The same preparation `_load` does; see its comments for why both are needed.
    caller.propagate_constants()
    _check_parse_health(caller, args)

    # App-mode detectors, supersession-deduped, each guarded so one crash
    # doesn't sink the run.
    app_names = default_detection_names(
        [n for n, c in DETECTORS.items()
         if "app" in getattr(c, "applies_to", frozenset({"app", "logicsig"}))])
    own: "dict[str, list]" = {}
    for name in app_names:
        try:
            vs = DETECTORS[name](caller, file=teal_path.name).detect()
        except Exception as e:                       # a detector fault ≠ audit fault
            logger.warning("detector %s failed on app %s: %s", name, app_id, e)
            continue
        if vs:
            own[name] = vs

    # Cross-contract callees, with caller context (pinned args + seeded
    # predicates). Best-effort: a fetch outage degrades to app-only.
    graph = None
    cross: list = []
    try:
        graph = XContractGraph.from_chain(caller, cache_dir=str(cache))
        from tealql.security.xcontract import cross_detection_findings
        cross = cross_detection_findings(graph, detector_names=default_detection_names())
    except Exception as e:
        logger.warning("cross-contract analysis unavailable for app %s: %s", app_id, e)

    # ABI method table (empty on raw/non-ABI bytecode). An audit report enumerates
    # ATTACK SURFACE, so drop the table entries that are not entry points — logged
    # ARC-28 events and the selectors of methods this app calls on OTHER apps. Only
    # when the router is recognised at all; otherwise keep the whole table, since an
    # unmodelled dispatch means "undetermined", not "serves nothing".
    methods = []
    try:
        from tealql.tealtools.metadata.abi import extract_method_table, method_line_ranges
        _text = teal_path.read_text()
        served = {m.selector for _, _, m in method_line_ranges(_text)}
        methods = [m for m in extract_method_table(_text).values()
                   if not served or m.selector in served]
    except Exception as exc:
        # Degrade VISIBLY, matching the neighbouring sections: silently
        # dropping the ABI-methods table hid e.g. an undecodable cached .teal.
        logger.warning("method table unavailable for %s: %s", teal_path, exc)

    callees = sorted(graph.callees) if graph is not None else []
    n_own = sum(len(v) for v in own.values())

    # Order by SEVERITY (worst first), then name. A group's severity is the MAX
    # of its findings' own `.severity` (the IR sink family carries per-finding
    # levels), falling back to the detector default.
    from tealql.security import severity_of
    from tealql.security.scan import SEVERITY_ORDER

    def _rank(level: str) -> int:
        return SEVERITY_ORDER.index(level) if level in SEVERITY_ORDER else -1

    def _group_severity(name: str, vs: list) -> str:
        levels = [(getattr(v, "severity", "") or "").lower() or severity_of(name)
                  for v in vs]
        return max(levels, key=_rank, default=severity_of(name))

    group_sev = {name: _group_severity(name, vs) for name, vs in own.items()}
    ordered = sorted(own, key=lambda n: (-_rank(group_sev[n]), n))
    sev_counts: "dict[str, int]" = {}
    for name, vs in own.items():
        sev_counts[group_sev[name]] = sev_counts.get(group_sev[name], 0) + len(vs)

    if args.json_out:
        from tealql.tealtools._utils.serialize import finding_to_dict
        print(_json.dumps({
            "app_id": app_id,
            "approval_program": str(teal_path),
            "callees": callees,
            "methods": [{"selector": m.selector_hex, "name": m.name,
                         "signature": m.signature} for m in methods],
            "summary": {s: sev_counts[s]                    # counts by severity
                        for s in reversed(SEVERITY_ORDER) if s in sev_counts},
            "findings": {name: {"severity": group_sev[name],
                                "findings": [finding_to_dict(v) for v in own[name]]}
                         for name in ordered},               # severity-ordered
            "cross_contract_findings": [
                {"app_id": f.app_id, "detector": f.detector_name,
                 "message": f.violation.pretty()} for f in cross],
        }, indent=2))
        return 1 if (n_own or cross) else 0

    print(f"═══ tealql audit — app {app_id} ═══")
    print(f"  approval program : {teal_path}")
    if callees:
        print(f"  cross-contract   : {', '.join('app' + str(a) for a in callees)}")
    if methods:
        print(f"  ABI methods ({len(methods)}):")
        for m in methods[:25]:
            print(f"    {m.selector_hex}  {m.signature}")
        if len(methods) > 25:
            print(f"    … (+{len(methods) - 25} more)")

    summary = "  ".join(f"{s}:{sev_counts[s]}"
                        for s in reversed(SEVERITY_ORDER) if s in sev_counts)
    print(f"\n── findings on app {app_id} — {n_own} ──"
          + (f"   [{summary}]" if summary else ""))
    if not own:
        print("  (none)")
    for name in ordered:
        print(f"  ▸ [{group_sev[name].upper():13}] {name}  ({len(own[name])})")
        for v in own[name]:
            print(f"      {v.pretty()}")

    print(f"\n── cross-contract findings — {len(cross)} ──")
    if not cross:
        print("  (none)")
    else:
        from tealql.security.xcontract import render_findings as _render_sg
        print(_render_sg(graph, cross))
    return 1 if (n_own or cross) else 0


def _cmd_xcontract(args) -> int:
    from tealql.tealtools.intercontract.analysis import (
        XContractGraph,
        cross_auth_findings,
        load_registry,
        render_xcontract,
        render_findings,
    )
    caller = _load(args)
    if args.from_chain:
        # Registry discovered by transitive BFS from chain (cached). A fetch
        # outage or unregistered callee is logged and skipped, never invented.
        graph = XContractGraph.from_chain(caller, cache_dir=args.cache_dir)
    else:
        graph = XContractGraph.build(caller, load_registry(args.registry))
    auth = cross_auth_findings(graph)

    # --detections/--detector also runs the detector suite against each callee
    # across the boundary with caller context (trusted_args pins + seeded
    # predicates); supersession-deduped unless one detector was named.
    sg_findings = []
    if args.detections or args.detector:
        from tealql.security.xcontract import (
            cross_detection_findings,
            render_findings as render_sg,
        )
        if args.detector:
            from tealql.security import DETECTORS
            if args.detector not in DETECTORS:
                raise TealQLError(
                    f"unknown detector {args.detector!r}; run "
                    "`tealql detections --list` for the available names")
            names = [args.detector]
        else:
            from tealql.security.scan import default_detection_names
            names = default_detection_names()
        sg_findings = cross_detection_findings(graph, detector_names=names)

    if args.json_out:
        from tealql.tealtools._utils.serialize import finding_to_dict
        payload = {
            "sites": [s.to_dict() for s in graph.sites],
            "cross_auth_findings": [finding_to_dict(f) for f in auth],
        }
        if args.detections or args.detector:
            payload["cross_detection_findings"] = [
                {"app_id": f.app_id, "detector": f.detector_name,
                 "message": f.violation.pretty()}
                for f in sg_findings
            ]
        print(_json.dumps(payload, indent=2))
    else:
        print(render_xcontract(graph.sites, graph.analyses))
        if auth:
            print("\ncross-contract auth-domination findings:")
            print(render_findings(graph, auth))
        if args.detections or args.detector:
            print("\ncross-contract security findings:")
            print(render_sg(graph, sg_findings, relative_to=Path.cwd()))
    return 1 if (auth or sg_findings) else 0


def _cmd_group_taint(args) -> int:
    """Cross-member taint over ONE atomic group — an attacker input in an earlier
    member reaching a sink in a later one via shared scratch or the log channel.

    HAZARD: ``args.members`` must be in GROUP ORDER (``members[i]`` is group txn
    ``i``); the graph enforces the AVM ``i < k`` rule off those positions, so a
    mis-ordered command line silently analyses a different group."""
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.dataflow.group_taint_graph import (
        GroupTaintGraph, group_taint_findings, render_group_taint,
    )
    progs = []
    for member in args.members:
        prog = SSAProgram(str(member), strict=False)
        prog.propagate_constants()
        _check_parse_health(prog, args)
        progs.append(prog)
    findings = group_taint_findings(GroupTaintGraph.build(progs))
    if args.json_out:
        print(_json.dumps({"findings": [f.to_dict() for f in findings]}, indent=2))
    else:
        print(render_group_taint(findings))
    return 1 if findings else 0


def _cmd_taint_query(args) -> int:
    """Open taint-reachability queries over the coarse taint graph — the free-form
    counterpart to the fixed detectors.

    HAZARD: reachability OVER-approximates (a reachable sink may be perfectly
    validated), so this is a triage lens, NOT a verdict — ``--verify`` is what
    chains a sink to its guard-aware detector. Exit is always 0."""
    from tealql.tealtools.dataflow.taint_query import TaintQuery
    prog = _load(args)
    precise = getattr(args, "precise", False)

    if getattr(args, "verify", False):
        from tealql.security.sink_verdict import verify_sinks
        verdicts = verify_sinks(prog, precise=precise)
        if args.json_out:
            print(_json.dumps([v.to_dict() for v in verdicts], indent=2))
        elif not verdicts:
            print("(no dangerous sinks reachable from attacker input)")
        else:
            for v in verdicts:
                print(v.render())
        return 0

    q = TaintQuery(prog)

    def _emit_hits(hits):
        if args.json_out:
            print(_json.dumps([h.to_dict() for h in hits], indent=2))
        elif not hits:
            print("(no dangerous sinks)")
        else:
            for h in hits:
                print(h.render())

    def _emit_nodes(nodes, empty):
        if args.json_out:
            print(_json.dumps([{"file": n.file, "line": n.line,
                                "node_class": n.node_class} for n in nodes], indent=2))
        elif not nodes:
            print(empty)
        else:
            for n in nodes:
                print(f"  {n.file}:{n.line}  {n.node_class}")

    if args.from_line is not None:
        _emit_hits(q.sinks_from(line=args.from_line))
    elif args.from_src is not None:
        sf, _, sl = args.from_src.rpartition(":")
        if not sl.isdigit():
            print("error: --from-src expects [FILE:]LINE", file=sys.stderr)
            return 2
        _emit_hits(q.sinks_from(source_file=sf or None, source_line=int(sl)))
    elif args.to_line is not None:
        _emit_nodes(q.sources_of(line=args.to_line), "(no attacker source reaches it)")
    elif args.list_sinks:
        _emit_hits(q.all_sinks())
    elif args.list_sources:
        _emit_nodes(q.all_sources(), "(no attacker-input sources)")
    else:
        _emit_hits(q.tainted_sinks(precise=precise))   # default: whole attack surface
    return 0


def _resolve_mode(args) -> "str | None":
    """The DECLARED detection mode: ``--mode``, else a ``--config`` glob match on
    the target string, else ``None`` meaning unfiltered — never inferred from
    opcodes."""
    if args.mode:
        return args.mode
    if args.config:
        from tealql.security.config import DetectionConfig
        cfg = DetectionConfig.from_path(Path(args.config))
        return cfg.mode_for(str(args.target))
    return None


def _cmd_detections(args) -> int:
    from tealql.security import DETECTORS

    if args.list:
        if args.json_out:
            print(_json.dumps(sorted(DETECTORS), indent=2))
        else:
            for name in sorted(DETECTORS):
                print(name)
        return 0

    if args.detector is not None and args.detector not in DETECTORS:
        raise TealQLError(
            f"unknown detector {args.detector!r}; run "
            "`tealql detections --list` for the available names")

    if not getattr(args, "target", None):
        print("error: a target (.teal file or directory) is required "
              "unless --list is given", file=sys.stderr)
        return 2

    mode = _resolve_mode(args)
    programs = _load_programs(args)
    names = list(DETECTORS) if args.all else [args.detector]
    # Mode filtering is for --all only; an explicit --detector runs as asked.
    if mode is not None and args.all:
        names = [
            n for n in names
            if mode in getattr(DETECTORS[n], "applies_to",
                               frozenset({"app", "logicsig"}))
        ]
    logger.info("running %d detection(s) on %d program(s) (mode=%s)",
                len(names), len(programs), mode or "unfiltered")

    def _run(name):
        # One detector's findings across every per-file program.
        cls = DETECTORS[name]
        found = []
        for prog, file in programs:
            found.extend(cls(prog, file=file).detect())
        logger.info("  %s: %d finding(s)", name, len(found))
        return found

    if args.json_out:
        from tealql.tealtools._utils.serialize import finding_to_dict
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
    from tealql.security.scan import (
        DetectionOptions, failures,
        render_json, render_sarif, render_text, scan,
    )

    options = (DetectionOptions.from_path(Path(args.options))
               if args.options else DetectionOptions())
    root = Path(args.root)
    findings = scan(
        root,
        options=options,
        strict=getattr(args, "strict", False),
        arc56=getattr(args, "arc56", None),
    )

    # --update-baseline accepts the CURRENT findings and exits 0.
    if args.update_baseline:
        from tealql.security.suppress import write_baseline
        n = write_baseline(args.update_baseline, findings)
        print(f"wrote {n} fingerprint(s) to {args.update_baseline}", file=sys.stderr)
        return 0

    # Suppressions — inline `// tealql-ignore` (always) + --baseline fingerprints
    # — drop findings from BOTH the output and the exit code.
    from tealql.security.suppress import partition, load_baseline
    baseline = load_baseline(args.baseline) if args.baseline else set()
    # HAZARD: partition returns PLAIN lists, which would drop the degradation
    # notifications on the floor — and a suppression config silently deleting
    # "this detector never ran" is the exact failure the notifications exist to
    # prevent. Suppressions apply to FINDINGS; they never apply to these.
    from tealql.security.scan import ScanResults
    notes = getattr(findings, "notifications", ())
    findings, suppressed = partition(findings, root=root, baseline=baseline)
    findings = ScanResults(findings, notes)
    if suppressed:
        logger.info("%d finding(s) suppressed (inline / baseline)", len(suppressed))

    # --format wins over the short JSON flag.
    fmt = args.format or ("json" if args.json_out else "text")
    renderer = {"text": render_text, "json": render_json, "sarif": render_sarif}[fmt]
    print(renderer(findings))
    # Exit 1 only on FAILURES: with --options, findings below `fail_on` are
    # reported but do not fail CI.
    return 1 if failures(findings, options) else 0


def _cmd_all(args) -> int:
    from tealql.security.run import run_all_dict, run_all_findings
    prog = _load(args)
    if args.json_out:
        payload = run_all_dict(prog)
        print(_json.dumps(payload, indent=2))
        n_findings = sum(len(v) for v in payload["detectors"].values())
    else:
        text, n_findings = run_all_findings(prog)
        print(text, end="")
    return 1 if n_findings else 0


def register(sub, add) -> None:
    tq = add("taint-query",
             "open taint reachability: dangerous sinks reachable from a source "
             "(--from LINE), attacker inputs steering a sink (--to LINE), the "
             "sink/source inventories (--sinks/--sources), per-sink guard-aware "
             "verdicts (--verify), or (default) the whole attacker-input -> sink "
             "attack surface; --precise backs reachability with the lifted IR",
             _cmd_taint_query)
    tqg = tq.add_mutually_exclusive_group()
    tqg.add_argument("--from", dest="from_line", type=int, default=None,
                     metavar="LINE", help="source TEAL line -> reachable sinks")
    tqg.add_argument("--from-src", dest="from_src", default=None,
                     metavar="[FILE:]LINE",
                     help="HIGH-LEVEL source line (via the compiler's source map) "
                          "-> reachable sinks")
    tqg.add_argument("--to", dest="to_line", type=int, default=None,
                     metavar="LINE", help="sink TEAL line -> attacker sources reaching it")
    tqg.add_argument("--sinks", dest="list_sinks", action="store_true",
                     help="list every dangerous sink in the program")
    tqg.add_argument("--sources", dest="list_sources", action="store_true",
                     help="list every attacker-input source")
    tqg.add_argument("--verify", dest="verify", action="store_true",
                     help="attack surface + per-sink VERDICT: chain each reachable "
                          "sink to its guard-aware detector (CONFIRMED / guarded / "
                          "unverified)")
    tq.add_argument("--precise", dest="precise", action="store_true",
                    help="back reachability with the lifted Puya IR (drops phantom "
                         "reaches + recovers interprocedural ones); applies to the "
                         "attack surface and --verify. Needs the lift; falls back to "
                         "the coarse graph when the contract doesn't lift")

    add("all", "run every detector + report", _cmd_all)

    xc = add("xcontract", "cross-contract appcall analysis", _cmd_xcontract)
    xc_src = xc.add_mutually_exclusive_group(required=True)
    xc_src.add_argument("--registry",
                        help="yaml mapping AppID → callee .teal path")
    xc_src.add_argument("--from-chain", action="store_true",
                        help="auto-discover the registry by fetching each "
                             "reachable callee's deployed approval program from "
                             "chain (transitive, cached) — no hand-written "
                             "--registry needed")
    xc.add_argument("--cache-dir", default=None,
                    help="directory --from-chain caches fetched callee .teal in "
                         "(default: ~/.cache/tealql/xcontract-callees)")
    xc.add_argument("--detections", action="store_true",
                    help="also run the security detector suite against each "
                         "callee across the appcall boundary (caller-pinned "
                         "ApplicationArgs are treated as trusted; seeded "
                         "path-predicates propagate)")
    # No `choices=` here: enumerating detector names at parser-build time
    # imports the full auto-discovery for EVERY invocation (`--help`
    # included, measured 0.33s). The handler validates against DETECTORS.
    xc.add_argument("--detector", default=None,
                    help="scope the cross-contract detections to one detector "
                         "(implies --detections; see `tealql detections "
                         "--list` for names)")

    audit_p = sub.add_parser(
        "audit",
        help="one-command mainnet audit of a deployed app by ID: fetch its "
             "approval program + cross-contract callees from chain, run every "
             "app-mode detector, print a consolidated report")
    audit_p.set_defaults(handler=_cmd_audit)
    audit_p.add_argument("app_id", type=int, metavar="APP_ID",
                         help="the on-chain application ID to audit")
    audit_p.add_argument("--cache-dir", default=None,
                         help="directory to cache fetched .teal in "
                              "(default: ~/.cache/tealql/xcontract-callees)")
    _add_common_flags(audit_p)

    gt = sub.add_parser(
        "group-taint",
        help="cross-member taint over an atomic group (shared scratch / logs)",
    )
    gt.add_argument("members", nargs="+", metavar="member.teal",
                    help="the group's member .teal files IN GROUP ORDER "
                         "(members[i] is group txn i)")
    _add_common_flags(gt)
    gt.set_defaults(handler=_cmd_group_taint)

    det = sub.add_parser(
        "detections",
        help="run one (or every) Algorand-security-guide detection",
    )
    det.set_defaults(handler=_cmd_detections)
    # Target is optional because --list doesn't need one.
    det.add_argument(
        "target", nargs="?", default=None,
        help="path to a .teal file or a directory of .teal files "
             "(omit when using --list)",
    )
    _add_common_flags(det)
    det.add_argument("--mode", choices=["app", "logicsig"], default=None,
                     help="declare the target's mode; with --all, skips "
                          "detectors that don't apply to that mode")
    det.add_argument("--config", default=None,
                     help="detection-mode config (yaml/json); the target "
                          "path is matched against its globs to pick a mode")
    group = det.add_mutually_exclusive_group(required=True)
    # No `choices=` — see the xcontract --detector note above; the handler
    # validates against DETECTORS and --list prints the names.
    group.add_argument(
        "--detector",
        help="detector short name (e.g. fee-validation); see --list",
    )
    group.add_argument("--all", action="store_true",
                       help="run every registered detection")
    group.add_argument("--list", action="store_true",
                       help="list available detector short names and exit")

    # detections-scan walks a directory and reconstructs each parent dir's SSA,
    # so it bypasses `resolve_target` and re-declares the common flags.
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
                          "exit-code threshold, `auto_mode:`")
    sgs.add_argument("--format", choices=["text", "json", "sarif"], default=None,
                     help="output format: text (default), json (versioned "
                          "finding schema), or sarif (SARIF 2.1.0 for GitHub "
                          "code scanning / CI dashboards)")
    sgs.add_argument("--json", action="store_true", dest="json_out",
                     help="alias for --format json")
    sgs.add_argument("-v", "--verbose", action="count", default=0,
                     help="progress logging to stderr; repeat (-vv) for "
                          "per-pass timings")
    sgs.add_argument("--strict", action="store_true",
                     help="exit 2 if any scanned file fails to parse or "
                          "reconstruct instead of skipping it with a warning")
    sgs.add_argument("--baseline", default=None,
                     help="JSON baseline of accepted finding fingerprints; "
                          "findings in it are suppressed (fail only on NEW ones)")
    sgs.add_argument("--update-baseline", default=None, metavar="PATH",
                     help="write the current findings' fingerprints to PATH and "
                          "exit 0 (accept the current state as the baseline)")
    sgs.add_argument("--arc56", default=None, metavar="SPEC.json",
                     help="ARC-56 app spec; keeps ABI method-name attribution on "
                          "findings even when the source's `method` comments were "
                          "stripped (optional, degrades cleanly)")
    sgs.set_defaults(handler=_cmd_detections_scan)
