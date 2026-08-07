"""``tealql`` — unified CLI for the TealQL static-analysis toolkit.

Each subcommand takes one ``<target>`` (a ``.teal`` file or a directory of them)
and reconstructs everything from that source — nothing to build or cache.

HAZARD — the exit-code contract, uniform across every subcommand:

  ``0``  clean — analysis ran, no findings
  ``1``  findings — at least one detector reported something
  ``2``  error — bad target, unparseable source under ``--strict``, or any other
         expected failure (clean message on stderr; genuine bugs still traceback)

CI depends on 1 meaning "findings", so a handler must never return 1 for an
error, nor 0 when it found something.
"""
from __future__ import annotations

import argparse
import json as _json
import contextlib
import logging
import sys
from pathlib import Path
from typing import Callable, Iterable

from tealql.tealtools._utils.targets import resolve_target
from tealql.tealtools.errors import TealParseError, TealQLError

logger = logging.getLogger("tealql.tealtools.cli")


def _configure_logging(verbosity: int) -> None:
    """Attach the one stderr handler for the whole ``tealql`` logger hierarchy,
    at WARNING / INFO / DEBUG per the ``-v`` count."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    root = logging.getLogger("tealql")
    root.setLevel(level)
    # Replace, don't append: `main()` runs repeatedly in-process (tests, library
    # embedding), and appending multiplied every log line by the call count.
    for existing in [h for h in root.handlers
                     if getattr(h, "_tealql_cli", False)]:
        root.removeHandler(existing)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-7s %(message)s"))
    handler._tealql_cli = True                    # type: ignore[attr-defined]
    root.addHandler(handler)


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _add_common_flags(sp: argparse.ArgumentParser) -> None:
    """The non-positional flags every subcommand shares (output + parse health)."""
    sp.add_argument("--json", action="store_true",
                    dest="json_out",
                    help="emit JSON instead of text")
    sp.add_argument("-v", "--verbose", action="count", default=0,
                    help="progress logging to stderr; repeat (-vv) for "
                         "per-pass timings")
    sp.add_argument("--strict", action="store_true",
                    help="exit 2 if any TEAL failed to parse instead of "
                         "analyzing the partial program with a warning")


def _add_target_args(sp: argparse.ArgumentParser, *, dest: str = "target",
                     optional: bool = False) -> None:
    """Add the universal ``<target>`` positional plus the common flags;
    ``optional`` is for commands that can run without a target."""
    if optional:
        sp.add_argument(dest, nargs="?", default=None,
                        help="path to a .teal file or a directory of .teal files")
    else:
        sp.add_argument(
            dest,
            help="path to a .teal file or a directory of .teal files",
        )
    _add_common_flags(sp)


def _resolve(args) -> Path:
    """Validate the target path (raises if it isn't TEAL source)."""
    return resolve_target(args.target)


def _check_parse_health(prog, args) -> None:
    """Warn (or, under ``--strict``, raise → exit 2) about anything the analysis
    silently lost.

    HAZARD: the parser DROPS unparseable spans and an opcode unknown to this
    build is modelled with a (0, 0) stack effect that corrupts the whole
    simulation. Both must be surfaced — a partial contract must never read as
    clean. Read the PER-PROGRAM set the builder recorded, not the process-wide
    ``avm.unknown_opcodes()`` union — in one run over many contracts the union
    blames every later program for the first one's exotic opcode."""
    unknown = sorted(getattr(prog, "unknown_ops", ()))
    if unknown:
        logger.warning(
            "%d opcode(s) unknown to this build were modelled with NO stack "
            "effect, so results for programs using them are unreliable "
            "(%s). This build may predate the contract's AVM version.",
            len(unknown), ", ".join(unknown[:8]),
        )
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
    from tealql.tealtools.ssa import SSAProgram
    source = _resolve(args)
    logger.info("building SSA program from %s", source)
    prog = SSAProgram(str(source), strict=False)
    # Construction only tags direct pushes. Cross-contract discovery keys on
    # CONSTANT AppIDs, so without this the callees are silently missed.
    prog.propagate_constants()
    logger.info("SSA program ready (%d assignments)", len(prog.assignments))
    _check_parse_health(prog, args)
    return prog


def _load_programs(args) -> "list[tuple]":
    """Resolve target → ``[(SSAProgram, file_filter), …]``, ONE program per
    ``.teal`` file, each const-propagated as :func:`_load` does.

    HAZARD: never merge a directory into one program. The AVM runs each program
    independently, so dominance / path-predicate detectors give WRONG answers
    once several programs' entries and exits are pooled. ``file_filter`` is the
    basename (so detectors scope to it), or ``None`` for a single file."""
    from tealql.tealtools._utils.targets import _discover_teal_files
    from tealql.tealtools.ssa import SSAProgram
    source = _resolve(args)
    teal_files = _discover_teal_files(Path(source))
    single = len(teal_files) == 1
    progs: list[tuple] = []
    for teal in teal_files:
        logger.info("building SSA program from %s", teal)
        prog = SSAProgram(str(teal), strict=False)
        prog.propagate_constants()
        _check_parse_health(prog, args)
        progs.append((prog, None if single else teal.name))
    return progs


def _emit_findings(findings: Iterable, *, json_out: bool) -> int:
    """Render finding-style output; returns the exit code (1 = findings)."""
    findings = list(findings)
    if json_out:
        from tealql.tealtools._utils.serialize import finding_to_dict
        print(_json.dumps([finding_to_dict(f) for f in findings], indent=2))
    else:
        if not findings:
            print("(no violations)")
        else:
            for v in findings:
                print(v.pretty())
    return 1 if findings else 0


def _emit_dict(payload: dict, *, json_out: bool, text: str) -> int:
    """Render report-style output; the caller pre-computes both forms."""
    print(_json.dumps(payload, indent=2) if json_out else text)
    return 0


# ---------------------------------------------------------------------------
# Analysis subcommands
#
# One ``_cmd_*`` per subcommand, each returning the module's exit code. The
# user-facing description of every command lives in its ``add(...)`` help text
# in :func:`build_parser`, not in these docstrings.
# ---------------------------------------------------------------------------


def _lifted_programs(args, command: str):
    """Yield ``(label, main, subs)`` per target program lifted to real Puya IR —
    the shared preamble of the ``puya``-gated subcommands.

    HAZARD: a program that does not lift is a COVERAGE GAP, not a failure — it
    is warned about and SKIPPED, so results here are silently partial (one
    stubborn contract must not sink a directory-wide audit).

    HAZARD: puya's IR builder writes to STDOUT, and not through ``logging`` —
    it prints via structlog, so raising the ``puya`` logger's level silences
    nothing. Its lines landed ahead of the payload and made ``--json`` emit
    unparseable output, breaking the one path the flag exists for. The lift is
    therefore run with stdout redirected to STDERR: diagnostics still reach a
    human, and stdout carries only the payload. The redirect wraps ONLY the
    ``to_puya`` call — this is a generator, so holding it open would also
    capture whatever the CALLER prints between yields."""
    try:
        from tealql.tealtools.lift import to_puya
    except ImportError as e:
        raise TealQLError(
            f"{command} requires the 'puya' package (pip install puyapy)") from e
    logging.getLogger("puya").setLevel(logging.CRITICAL)   # the stdlib half
    for prog, name in _load_programs(args):
        label = name or Path(getattr(prog, "source_path", "") or "<program>").name
        try:
            with contextlib.redirect_stdout(sys.stderr):
                main_sub, subs = to_puya(prog)
        except Exception as e:                       # coverage gap, not a crash
            logger.warning("%s: %s did not lift (%s: %s) — skipped",
                           command, label, type(e).__name__, e)
            continue
        yield label, main_sub, subs


def _cmd_auth(args) -> int:
    from tealql.tealtools.auth_domination import AuthDominationDetector
    return _emit_findings(
        AuthDominationDetector(_load(args)).detect(),
        json_out=args.json_out,
    )


def _cmd_loops(args) -> int:
    """Loop cost / iteration-bound table."""
    from tealql.tealtools.loop_bounds import analyze_loops, render
    rc = 0
    for prog, _file_filter in _load_programs(args):
        name = getattr(prog, "source_path", None)
        name = name.name if name else "<program>"
        loops = analyze_loops(prog)
        if args.json_out:
            import json
            print(json.dumps({
                "file": name,
                "loops": [{
                    "header_line": b.first_line,
                    "blocks": len(b.body),
                    "min_iteration_cost": b.min_iteration_cost,
                    "stack_delta": b.stack_delta,
                    "max_iterations": b.max_iterations,
                    "bound": b.bound_reason,
                } for b in loops],
            }, indent=1))
        else:
            print(f"== {name}")
            print(render(prog))
    return rc


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


def _cmd_abi_audit(args) -> int:
    """Report caller-supplied ``arc4.Address`` values reaching a fund / asset sink,
    flagging the UNGUARDED ones (arbitrary recipient); exit 1 if any.

    The recovered ABI address type is what identifies a 32-byte operand as a
    caller-chosen recipient, and that recovery is SPECULATIVE."""
    leads: list = []
    for label, main, subs in _lifted_programs(args, "abi-audit"):
        from tealql.tealtools.lift import to_puya_ir
        for lead in to_puya_ir.abi_address_fund_flows(main, subs):
            leads.append({"file": label, **lead})

    danger = [x for x in leads
              if x["caller_supplied"] and not x["guarded"]]
    if args.json_out:
        print(_json.dumps(leads, indent=2))
        return 1 if danger else 0
    if not leads:
        print("(no arc4.Address values reach a fund/asset sink)")
        return 0
    print(f"abi-audit: {len(leads)} address→sink flow(s), "
          f"{len(danger)} arbitrary-recipient (caller-supplied & UNGUARDED)")
    for x in sorted(leads, key=lambda d: (not (d["caller_supplied"]
                                               and not d["guarded"]),
                                          d["file"], d["subroutine"], d["field"])):
        if x["caller_supplied"] and not x["guarded"]:
            tag = "  ⚠ CALLER-SUPPLIED, UNGUARDED"
        elif x["caller_supplied"]:
            tag = "  caller-supplied, guarded"
        else:
            tag = "  (not directly caller-supplied)"
        conf = "confident" if x.get("confident") else "somewhat"
        print(f"  {x['file']}: itxn_field {x['field']} (sub {x['subroutine']}) "
              f"<- {x['encoding']} [{conf}]{tag}")
    return 1 if danger else 0


def _cmd_box_audit(args) -> int:
    """Report address-keyed BoxMaps whose key is CALLER-SUPPLIED rather than bound
    to ``txn Sender`` — cross-user access to any account's slot; exit 1 if any."""
    rows: list = []
    for label, main, subs in _lifted_programs(args, "box-audit"):
        from tealql.tealtools.lift.box_recovery import box_access_control
        for f in box_access_control(main, subs):
            rows.append((label, f))

    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "prefix": f.prefix.decode("latin-1"),
             "key_type": f.key_type, "written": f.written, "ops": sorted(f.ops)}
            for lbl, f in rows], indent=2))
        return 1 if rows else 0
    if not rows:
        print("(no cross-user box-access leads)")
        return 0
    for lbl, f in rows:
        print(f"  ⚠ {lbl}: {f.render()}")
    return 1


def _cmd_storage_schema(args) -> int:
    """Reconstruct the global / local / box storage schema with recovered key and
    value types: a constant key is one stored value, a computed or
    ``concat(prefix, encode(k))`` key is a map."""
    spec = None
    if getattr(args, "arc56", None):
        from tealql.tealtools import arc56 as _arc56
        spec = _arc56.load(args.arc56)          # explicit path -> surface errors

    rows: list = []
    for label, main, subs in _lifted_programs(args, "storage-schema"):
        from tealql.tealtools.lift.box_recovery import (
            annotate_with_arc56, recover_storage_schema)
        for entry in annotate_with_arc56(recover_storage_schema(main, subs), spec):
            rows.append((label, entry))

    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "kind": s.kind, "is_map": s.is_map, "name": s.name,
             "key_or_prefix": s.key_or_prefix.decode("latin-1"),
             "arc56_key_type": s.arc56_key_type,
             "arc56_value_type": s.arc56_value_type,
             "storage_type": s.storage_type,
             "value_confident": s.value_confident, "ops": sorted(s.ops)}
            for lbl, s in rows], indent=2))
        return 0
    if not rows:
        print("(no app storage)")
        return 0
    for lbl, s in rows:
        print(f"  {lbl}: {s.render()}")
    return 0


def _fmt_abi_arg(t: str, name: str = "") -> str:
    """``name: type[NB]``, or bare ``type[NB]`` when the arg has no declared name
    (source-extracted signatures carry none); ``[NB]`` only for fixed widths."""
    from tealql.tealtools.abi import abi_type_byte_length
    n = abi_type_byte_length(t)
    core = f"{t}[{n}B]" if n is not None else t
    return f"{name}: {core}" if name else core


def _cmd_methods(args) -> int:
    """Print the ABI method table — selector, name, arg types, return type.

    HAZARD: the table comes only from HIGH-LEVEL info — an ``--arc56`` spec
    (authoritative) or the source's ``method "sig"`` pseudo-ops / ``// method``
    comments. NOTHING is reverse-engineered from the selector hash (it is
    irreversible; the selector is recomputed FORWARD and matched). Raw bytecode
    with neither simply reports no method info.

    Not every signature in the table is a method the contract SERVES: the same
    ``method "sig"`` pseudo-ops also carry the selectors of ARC-28 events it logs
    and of methods it CALLS on other contracts. Those are not attack surface, so
    each row is marked routable / not-routable by asking whether the router
    actually dispatches its selector. That question is only answerable when the
    dispatch shape is recognised; when it is not, every row is left unmarked
    rather than guessed at."""
    from tealql.tealtools.abi import (abi_type_byte_length, extract_method_table,
                                      method_line_ranges)
    rows = []   # (label, AbiMethod, routable: True | False | None-if-undetermined)
    if getattr(args, "arc56", None):
        from tealql.tealtools import arc56 as _arc56
        spec = _arc56.load(args.arc56)          # explicit path -> surface errors
        label = spec.name or Path(args.arc56).name
        # An ARC-56 spec lists what the contract SERVES, so every entry is routable
        # by construction — there is no router to consult and nothing to determine.
        rows = [(label, m, True) for m in spec.methods]
    elif not getattr(args, "target", None):
        print("error: a target (.teal file or directory) is required unless "
              "--arc56 SPEC.json is given", file=sys.stderr)
        return 2
    else:
        for prog, name in _load_programs(args):
            src = Path(getattr(prog, "source_path", "") or "")
            label = name or (src.name if src.name else "<program>")
            text = src.read_text(errors="ignore") if src.exists() else ""
            # method_line_ranges is conservative: an unrecognised dispatch yields NO
            # attribution. Empty therefore means "could not tell", NOT "serves none" —
            # collapsing those two would silently blank the table on every contract
            # whose router this does not model yet.
            served = {m.selector for _, _, m in method_line_ranges(text)} or None
            for m in extract_method_table(text).values():
                rows.append((label, m, None if served is None else m.selector in served))
    rows.sort(key=lambda r: (r[0], r[1].name))
    if getattr(args, "routable", False):
        rows = [r for r in rows if r[2] is not False]     # keep undetermined rows
    if args.json_out:
        print(_json.dumps([
            {"file": lbl, "selector": m.selector_hex, "name": m.name,
             "arg_types": list(m.arg_types), "arg_names": list(m.arg_names),
             "return_type": m.return_type,
             "arg_byte_lengths": [abi_type_byte_length(a) for a in m.arg_types],
             "signature": m.signature, "routable": routable}
            for lbl, m, routable in rows], indent=2))
        return 0
    if not rows:
        print("(no ABI method info in source)")
        return 0
    for lbl, m, routable in rows:
        names = m.arg_names or ("",) * len(m.arg_types)
        args_str = ", ".join(_fmt_abi_arg(a, n) for a, n in zip(m.arg_types, names))
        mark = "" if routable is not False else "   [not routable: event or outgoing call]"
        print(f"  {lbl}: {m.selector_hex}  {m.name}({args_str}) -> {m.return_type}{mark}")
    return 0


def _cmd_arc56(args) -> int:
    """Dump an ARC-56 app spec's methods and state schema — the authoritative but
    OPTIONAL source of the ABI typing the analysis consumes; exit 2 on a bad spec."""
    from tealql.tealtools import arc56 as _arc56
    try:
        spec = _arc56.load(args.spec)
    except Exception as e:
        print(f"could not read ARC-56 spec {args.spec}: {e}", file=sys.stderr)
        return 2

    def _state(entries):
        return [
            {"name": s.name, "value_type": s.value_type, "key_type": s.key_type,
             "is_map": s.is_map,
             **({"prefix_b64": s.prefix_b64} if s.is_map else {"key_b64": s.key_b64})}
            for s in entries
        ]

    doc = {
        "name": spec.name,
        "structs": spec.structs,
        "methods": [
            {"selector": m.selector_hex, "name": m.name,
             "arg_types": list(m.arg_types), "arg_names": list(m.arg_names),
             "return_type": m.return_type, "signature": m.signature}
            for m in spec.methods],
        "state": {"global": _state(spec.global_state),
                  "local": _state(spec.local_state),
                  "box": _state(spec.box_state)},
    }
    if args.json_out:
        print(_json.dumps(doc, indent=2))
        return 0
    print(f"contract: {spec.name or '<unnamed>'}")
    if spec.structs:
        print("structs:")
        for nm, tt in sorted(spec.structs.items()):
            print(f"  {nm} = {tt}")
    print(f"methods ({len(spec.methods)}):")
    for m in sorted(spec.methods, key=lambda x: x.name):
        names = m.arg_names or ("",) * len(m.arg_types)
        args_str = ", ".join(_fmt_abi_arg(a, n) for a, n in zip(m.arg_types, names))
        print(f"  {m.selector_hex}  {m.name}({args_str}) -> {m.return_type}")
    for scope, entries in (("global", spec.global_state), ("local", spec.local_state),
                           ("box", spec.box_state)):
        if entries:
            print(f"{scope} state ({len(entries)}):")
            for s in sorted(entries, key=lambda x: x.name):
                kind = "map" if s.is_map else "key"
                print(f"  {kind} {s.name}: {s.key_type or '?'} -> {s.value_type or '?'}")
    return 0


def _cmd_itxn_report(args) -> int:
    from tealql.tealtools.inner_txn_report import InnerTxnReport
    r = InnerTxnReport(_load(args))
    return _emit_dict(r.to_dict(), json_out=args.json_out, text=r.render())


def _cmd_group_shape(args) -> int:
    from tealql.tealtools.group_reasoning import analyze, analyze_per_exit
    prog = _load(args)
    if getattr(args, "per_exit", False):
        # DISTINCT shapes per approving exit, not their intersection — the common
        # summary drops any shape not shared by every exit.
        s = analyze_per_exit(prog)
    else:
        s = analyze(prog)
    return _emit_dict(s.to_dict(), json_out=args.json_out, text=s.render())


def _cmd_group_layout(args) -> int:
    from tealql.tealtools.group_reasoning import analyze_layout
    layout = analyze_layout(_load(args))
    return _emit_dict(layout.to_dict(), json_out=args.json_out, text=layout.render())


def _cmd_functional(args) -> int:
    """Run the canonical SSA pipeline and print the functional dump."""
    from tealql.tealtools.passes import functional_dump
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
    from tealql.tealtools.path_predicates import PathPredicateAnalysis
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


def _cmd_audit(args) -> int:
    """Fetch deployed app ``<ID>`` and its callees from chain, run every app-mode
    detector, and print a consolidated report; exit 2 if the app can't be fetched.

    NETWORK-touching: the mainnet API for program bytes plus a local algod on
    :4001 for disassembly (both env-overridable), cached under ``--cache-dir``."""
    from tealql.tealtools._utils.chain import fetch_approval
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.xcontract import _DEFAULT_CALLEE_CACHE, XContractGraph
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
        from tealql.tealtools.abi import extract_method_table, method_line_ranges
        _text = teal_path.read_text()
        served = {m.selector for _, _, m in method_line_ranges(_text)}
        methods = [m for m in extract_method_table(_text).values()
                   if not served or m.selector in served]
    except Exception:
        pass

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
    from tealql.tealtools.xcontract import (
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
        for name in sorted(DETECTORS):
            print(name)
        return 0

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
    if args.all:
        # Supersession dedup AFTER mode filtering: a superseded detector is
        # skipped only if its superseder survived the filter and will run.
        from tealql.security.scan import default_detection_names
        names = default_detection_names(names)
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
        DetectionOptions, ScanConfig, failures,
        render_json, render_sarif, render_text, scan,
    )
    from tealql.security.config import ConfigError, DetectionConfig

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
    root = Path(args.root)
    findings = scan(
        root,
        config=config,
        detection_config=detection_config,
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

    # --format wins; --json is the back-compat alias for --format json.
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


def _cmd_dump(args) -> int:
    import sys as _sys
    from tealql.tealtools.viz import dump_all
    source = str(_resolve(args))
    text = dump_all(source, args.out_dir, svg=not args.no_svg, registry=args.registry)
    if args.out_dir:
        _sys.stderr.write(
            f"wrote full dump to {args.out_dir}/ "
            f"(contract.txt + graph/cfg/ssa)\n")
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

    def add(name: str, help_: str, handler: Callable, *,
            optional_target: bool = False) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        _add_target_args(sp, optional=optional_target)
        sp.set_defaults(handler=handler)
        return sp

    add("auth", "auth-domination detector", _cmd_auth)

    add("loops", "loop cost + iteration bounds (budget / stack ceilings)",
        _cmd_loops)

    box_df = add("box-df", "box dataflow (into / out / correlated)", _cmd_box_df)
    box_df.add_argument(
        "--flavour", required=True, choices=["into", "out", "correlated"],
        help="which box-dataflow analysis to run",
    )

    methods_p = add("methods",
        "recover the ABI method table (name / args / selector) from source "
        "method signatures or an --arc56 spec — optional, empty on raw bytecode",
        _cmd_methods, optional_target=True)   # target unused with --arc56
    methods_p.add_argument(
        "--arc56", default=None, metavar="SPEC.json",
        help="use an ARC-56 app spec as the AUTHORITATIVE method table "
             "(struct-resolved arg/return types + arg names)")
    methods_p.add_argument(
        "--routable", action="store_true",
        help="list only methods the router actually dispatches — drops ARC-28 "
             "event signatures and selectors of methods called on OTHER contracts, "
             "which share the same method table but are not this app's surface")

    arc56_p = sub.add_parser(
        "arc56",
        help="ingest an ARC-56 app spec and dump its methods + state schema "
             "(the authoritative, optional high-level typing source)")
    arc56_p.add_argument("spec", help="path to an ARC-56 app-spec JSON file")
    _add_common_flags(arc56_p)
    arc56_p.set_defaults(handler=_cmd_arc56)

    add("itxn-report", "inner-transaction report", _cmd_itxn_report)
    add("abi-audit",
        "ABI type-driven audit: caller-supplied arc4.Address paid to a "
        "fund/asset sink unguarded (needs puya)", _cmd_abi_audit)
    storage_p = add("storage-schema",
        "reconstruct global/local/box storage schema (keys + maps) with "
        "recovered key/value types (needs puya)", _cmd_storage_schema)
    storage_p.add_argument(
        "--arc56", default=None, metavar="SPEC.json",
        help="annotate entries with authoritative names + value/key types from "
             "an ARC-56 app spec (matched on kind + key/prefix bytes)")
    add("box-audit",
        "box access-control: caller-supplied address-keyed BoxMap not bound to "
        "txn Sender = cross-user access (needs puya)", _cmd_box_audit)
    group_shape_p = add("group-shape", "forced group shape", _cmd_group_shape)
    group_shape_p.add_argument(
        "--per-exit", action="store_true",
        help="enumerate the DISTINCT group shapes per approving exit (ABI-labelled) "
             "instead of only the common shape across all exits")
    add("group-layout", "forced group size + per-position layout", _cmd_group_layout)

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

    add("path-predicates", "per-BB path predicates", _cmd_path_predicates)
    add("all", "run every detector + report", _cmd_all)

    dump_p = add("dump", "dump EVERY representation of a contract (debug)", _cmd_dump)
    dump_p.add_argument("-o", "--out-dir", default=None,
                        help="also write contract.txt + graph/cfg/ssa "
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
    from tealql.security import DETECTORS as _DETS
    xc.add_argument("--detector", choices=sorted(_DETS), default=None,
                    help="scope the cross-contract detections to one detector "
                         "(implies --detections)")

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

    from tealql.security import DETECTORS as _DETECTORS
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
                          "exit-code threshold, `auto_mode:`. Replaces "
                          "--config/--mode-config")
    sgs.add_argument("--config", default=None,
                     help="yaml/json with `rules:` for per-file detector selection")
    sgs.add_argument("--mode-config", default=None,
                     help="yaml/json with `modes:` declaring each file's "
                          "app/logicsig mode; detectors that don't apply to "
                          "a file's mode are skipped")
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

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(getattr(args, "verbose", 0))
    try:
        return args.handler(args)
    except (TealQLError, FileNotFoundError) as e:
        # Every EXPECTED failure exits 2 with a clean message (see the
        # module-level exit-code contract); genuine bugs still traceback.
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
