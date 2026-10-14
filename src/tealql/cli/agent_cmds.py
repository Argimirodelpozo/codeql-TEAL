"""Agent-facing subcommands: ``mcp`` (serve the tool registry over stdio),
``brief`` (the one-call contract brief) and ``explain`` (everything known about
one TEAL line). The analysis behind them is :mod:`tealql.agent`."""
from __future__ import annotations

import json as _json

from ._common import _add_common_flags, _resolve


def _cmd_mcp(args) -> int:
    from tealql.agent.server import McpServer, TOOLS
    if args.list_tools:
        if args.json_out:
            print(_json.dumps([t.mcp_descriptor() for t in TOOLS.values()], indent=2))
        else:
            for t in TOOLS.values():
                print(f"{t.name}\n    {t.description}\n")
        return 0
    # stdout is the protocol channel from here on: nothing else may print to it.
    return McpServer().serve()


def _cmd_brief(args) -> int:
    """Exit codes mirror ``all``: 1 when the brief contains findings, 2 when any
    section was incomplete, else 0."""
    from tealql.agent.brief import contract_brief, render_brief_markdown
    from tealql.agent.tools import _single_file
    path = _resolve(args)
    teal = _single_file(path, getattr(args, "file", None))
    brief = contract_brief(teal, precise=not args.coarse)
    if args.json_out:
        print(_json.dumps(brief, indent=2, default=str))
    else:
        print(render_brief_markdown(brief))
    if not brief["complete"]:
        return 2
    return 1 if brief["findings"] else 0


def _cmd_explain(args) -> int:
    from tealql.agent.tools import source_context
    path = _resolve(args)
    ctx = source_context(target=str(path), file=getattr(args, "file", None),
                         line=args.line, before=args.before, after=args.after)
    if args.json_out:
        print(_json.dumps(ctx, indent=2, default=str))
        return 0
    print(f"{ctx['file']}:{ctx['line']}"
          + (f"  ({ctx['high_level_source']})" if ctx.get("high_level_source") else "")
          + (f"  in {ctx['abi_method']['signature']}" if ctx.get("abi_method") else ""))
    for w in ctx["window"]:
        mark = ">>" if w["focus"] else "  "
        print(f"{mark} {w['line']:5}  {w['text']}")
    if ctx.get("instruction"):
        i = ctx["instruction"]
        print(f"\ninstruction: {i['op']}  outputs={i['outputs']}  operands={i['operands']}")
    print("\nholds on every path here (dominating predicates):")
    for p in ctx["path_predicates"] or ["  (none)"]:
        print(f"  {p}")
    print("\nattacker inputs reaching this line (coarse):")
    for s in ctx.get("attacker_sources_reaching") or []:
        print(f"  {s['file']}:{s['line']}  {s.get('op', s['node_class'])}")
    if not ctx.get("attacker_sources_reaching"):
        print("  (none)")
    print("\ndangerous sinks reachable from this line (coarse):")
    for h in ctx.get("sinks_reachable_from") or []:
        print(f"  [{h['severity']}] {h['file']}:{h['line']}  {h['category']}  "
              f"{h['op']} {h['field']}".rstrip())
    if not ctx.get("sinks_reachable_from"):
        print("  (none)")
    return 0


def _cmd_diff(args) -> int:
    """Exit 1 when the NEW revision has findings the old one did not (a security
    regression), 2 when either side was incomplete, else 0."""
    from tealql.agent.tools import diff
    out = diff(old=args.old, new=args.new, mode=args.mode)
    if args.json_out:
        print(_json.dumps(out, indent=2, default=str))
    else:
        s = out["summary"]
        print(f"tealql diff: {s['added']} added, {s['removed']} removed, "
              f"{s['unchanged']} unchanged  ({s['old_total']} -> {s['new_total']} findings)")
        for tag, rows in (("+", out["added"]), ("-", out["removed"])):
            for f in rows:
                loc = f"{f['file']}:{f['line']}" if f.get("line") else f"{f['file']}"
                print(f"  {tag} [{f['severity'].upper()}] {f['rule_id']} @ {loc}: {f['message']}")
        se = out["semantic_equivalence"]
        print(f"semantic equivalence: {se.get('status')} — {se.get('reason')}")
        if not out["complete"]:
            print("\nAnalysis INCOMPLETE:")
            for n in out["notifications"]:
                print(f"  [{n.get('kind')}] {n.get('message')}")
    if not out["complete"]:
        return 2
    return 1 if out["added"] else 0


def register(sub, add) -> None:
    mcp = sub.add_parser(
        "mcp",
        help="serve the analysis as Model Context Protocol tools over stdio "
             "(for Claude Code / any MCP client); --list-tools to inspect them")
    mcp.add_argument("--list-tools", action="store_true",
                     help="print the tool catalogue and exit")
    _add_common_flags(mcp)
    mcp.set_defaults(handler=_cmd_mcp)

    brief = add("brief",
                "one-call contract brief: ABI surface, lifecycle, storage, inner "
                "txns, forced group shape, attack surface with verdicts, findings "
                "(Markdown; --json for the structured form)", _cmd_brief)
    brief.add_argument("--file", default=None,
                       help="for a directory target: which program to brief")
    brief.add_argument("--coarse", action="store_true",
                       help="skip the lifted-IR attack surface (faster, less precise)")

    explain = add("explain",
                  "everything the analysis knows about one TEAL line: source "
                  "window, high-level origin, ABI method, dominating predicates, "
                  "attacker inputs reaching it and sinks it reaches", _cmd_explain)
    explain.add_argument("--line", type=int, required=True, help="1-based TEAL line")
    explain.add_argument("--file", default=None,
                         help="for a directory target: which program the line is in")
    explain.add_argument("--before", type=int, default=6)
    explain.add_argument("--after", type=int, default=6)

    diff_p = sub.add_parser(
        "diff",
        help="security diff between two revisions: findings added/removed "
             "(line- and filename-insensitive) + bounded semantic equivalence; "
             "exit 1 only on NEW findings")
    diff_p.add_argument("old", help="old revision (.teal file or directory)")
    diff_p.add_argument("new", help="new revision (.teal file or directory)")
    diff_p.add_argument("--mode", choices=["auto", "app", "logicsig"], default="auto")
    _add_common_flags(diff_p)
    diff_p.set_defaults(handler=_cmd_diff)
