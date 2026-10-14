"""The contract brief: one structured summary of a TEAL program for triage.

An auditor's first questions about an unknown Algorand app are always the
same — what can be called, who can upgrade or delete it, what it stores, what
it pays out and to whom, what group it demands, and where attacker input
reaches something dangerous. Every one of those is already computed somewhere
in the toolkit; this module composes them into ONE document with a shared
completeness envelope, so an agent (or a reviewer) gets the whole picture in a
single call instead of twelve.

Nothing here adds analysis. Lifecycle facts are read off the lifecycle
detectors, the attack surface off ``sink_verdict``, storage off the lift's
schema recovery (optional backend), and so on. The brief therefore inherits
every caveat of its sources, and it says so: ``complete`` is the conjunction of
the parts' completeness and ``notifications`` their union.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

_LIFECYCLE_RULES = {
    "is-updatable": ("updatable", "an approving path exists under OnCompletion == "
                                  "UpdateApplication"),
    "unprotected-updatable": ("update_not_creator_gated",
                              "that update path has no sender == creator guard"),
    "timelock-upgrade": ("update_without_time_delay",
                         "the update path is not delayed by a LatestTimestamp check"),
    "is-deletable": ("deletable", "an approving path exists under OnCompletion == "
                                  "DeleteApplication"),
    "unprotected-deletable": ("delete_not_creator_gated",
                              "that delete path has no sender == creator guard"),
    "delete-funds-check": ("delete_without_funds_check",
                           "deletion does not check the app balance first"),
}

_TYPE_ENUM = {"1": "pay", "2": "keyreg", "3": "acfg", "4": "axfer", "5": "afrz", "6": "appl"}


def _pragma_version(text: str) -> Optional[int]:
    m = re.search(r"^\s*#pragma\s+version\s+(\d+)", text, re.MULTILINE)
    return int(m.group(1)) if m else None


def _compact_itxns(report: dict) -> list[dict]:
    """``itxn-report`` groups reduced to what a reader needs: per txn the type and
    each field's possible values (capped), plus the submit line."""
    out = []
    for g in report.get("groups", ()):
        txns = []
        for t in g.get("txns", ()):
            fields: dict[str, Any] = {}
            kind = None
            for fld in t.get("fields", ()):
                vals = [str(v) for v in fld.get("possible_values", ())]
                if fld.get("name") == "TypeEnum":
                    kind = sorted({_TYPE_ENUM.get(v, v) for v in vals}) or None
                    continue
                fields[fld["name"]] = {"line": fld.get("line"),
                                       "values": vals[:4] + (["…"] if len(vals) > 4 else [])}
            txns.append({"type": kind, "begin_line": (t.get("begin") or {}).get("line"),
                         "fields": fields})
        out.append({"submit_line": g.get("submit_line"), "txns": txns})
    return out


def contract_brief(teal_path: "str | Path", *, precise: bool = True) -> dict:
    """Build the brief for ONE ``.teal`` program (a directory is a collection —
    brief each member)."""
    from tealql.security._program_shape import classify_program
    from tealql.security.scan import SEVERITY_ORDER
    from . import tools as T

    path = Path(teal_path).resolve()
    text = path.read_text(errors="replace")
    prog = T.load_program(path)
    notes: list[dict] = []
    complete = True

    def _absorb(section: dict) -> None:
        nonlocal complete
        if section.get("complete") is False:
            complete = False
        notes.extend(section.get("notifications", ()))

    # Health of the substrate itself (parse gaps, unknown opcodes, …).
    health = prog.health(deep=True).to_dict()
    _absorb(health)

    mode = classify_program(prog)
    out: dict[str, Any] = {
        "schema": "tealql.brief/1",
        "file": path.name,
        "path": str(path),
        "avm_version": _pragma_version(text),
        "lines": len(text.splitlines()),
        "mode": mode,
        "mode_basis": "opcode classification (an app-only opcode ⇒ app; else logicsig)",
    }

    meth = T.methods(target=str(path))
    out["abi_methods"] = meth["methods"]

    analysis = T.analyze(target=str(path), mode=mode)
    _absorb(analysis)
    findings = analysis["findings"]
    out["findings"] = findings
    out["findings_summary"] = analysis["summary"]
    out["detectors_run"] = next(iter(analysis["programs"].values()), {}).get("detectors", [])

    # Lifecycle: read off the lifecycle detectors' verdicts.
    fired = {f["rule_id"] for f in findings}
    lifecycle: dict[str, Any] = {}
    for rule, (key, meaning) in _LIFECYCLE_RULES.items():
        if rule in out["detectors_run"]:
            lifecycle[key] = rule in fired
        else:
            lifecycle[key] = None                      # detector did not run (mode)
    lifecycle["meaning"] = {k: v[1] for k, v in _LIFECYCLE_RULES.items()}
    out["lifecycle"] = lifecycle

    if mode == "app":
        storage = T.storage_schema(target=str(path))
        _absorb(storage)
        out["storage"] = storage["entries"]
    else:
        out["storage"] = []

    itxn = T.inner_transactions(target=str(path))
    out["inner_transactions"] = _compact_itxns(itxn)

    shape = T.group_shape(target=str(path), per_exit=True)
    out["group_shape"] = shape["shape"]
    out["group_layout"] = shape["layout"]

    surface = T.verify_sinks(target=str(path), precise=precise)
    out["attack_surface"] = surface["verdicts"]
    out["attack_surface_counts"] = surface["counts"]

    out["complete"] = complete
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    out["headline"] = _headline(out, rank)
    # De-duplicate notifications that several sections re-reported.
    seen: set = set()
    uniq = []
    for n in notes:
        key = (n.get("kind"), n.get("message"), n.get("file"), n.get("detector"))
        if key not in seen:
            seen.add(key)
            uniq.append(n)
    out["notifications"] = uniq
    out["semantics"] = (
        "findings and attack_surface CONFIRMED entries are detector verdicts "
        "(attacker data reaches the sink / the action is reachable, with no "
        "recognised dominating guard); NOT_FLAGGED is not a proof of a guard; "
        "lifecycle null = the detector did not apply to this mode. complete=false "
        "means some section could not be fully analysed — see notifications.")
    return out


def _headline(b: dict, rank: dict) -> list[str]:
    """Three to six sentences a reader should see first."""
    lines = []
    lc = b["lifecycle"]
    if lc.get("updatable"):
        gate = "by anyone" if lc.get("update_not_creator_gated") else "creator-gated"
        lines.append(f"Upgradeable ({gate}"
                     + (", no time delay" if lc.get("update_without_time_delay") else "")
                     + ").")
    elif lc.get("updatable") is False:
        lines.append("Not upgradeable.")
    if lc.get("deletable"):
        gate = "by anyone" if lc.get("delete_not_creator_gated") else "creator-gated"
        lines.append(f"Deletable ({gate}).")
    confirmed = [v for v in b["attack_surface"] if v["verdict"] == "CONFIRMED"]
    if confirmed:
        cats = sorted({v["category"] for v in confirmed})
        lines.append(f"{len(confirmed)} attacker-reachable sink(s) CONFIRMED unguarded: "
                     + ", ".join(cats) + ".")
    elif b["attack_surface"]:
        lines.append(f"{len(b['attack_surface'])} attacker-reachable sink(s), none "
                     "confirmed unguarded by the detectors.")
    else:
        lines.append("No dangerous sink is reachable from attacker input.")
    worst = max((f["severity"] for f in b["findings"]), key=lambda s: rank.get(s, -1),
                default=None)
    if worst:
        lines.append(f"{len(b['findings'])} finding(s); worst severity {worst}.")
    if b["inner_transactions"]:
        kinds = sorted({k for g in b["inner_transactions"] for t in g["txns"]
                        for k in (t["type"] or ["?"])})
        lines.append(f"Sends inner transactions ({', '.join(kinds)}).")
    if not b["complete"]:
        lines.append("Analysis INCOMPLETE — see notifications.")
    return lines


def render_brief_markdown(b: dict) -> str:
    """A compact Markdown rendering (what an agent pastes into a review)."""
    o: list[str] = []
    o.append(f"# {b['file']} — AVM v{b['avm_version']}, {b['mode']}, {b['lines']} lines")
    o.append("")
    for s in b["headline"]:
        o.append(f"- {s}")
    o.append("")
    if b["abi_methods"]:
        o.append("## ABI methods")
        for m in b["abi_methods"]:
            tag = "" if m["routable"] is not False else "  _(not routable: event/outgoing)_"
            span = f" L{m['lines'][0]}–{m['lines'][1]}" if m.get("lines") else ""
            o.append(f"- `{m['selector']}` `{m['signature']}`{span}{tag}")
        o.append("")
    lc = b["lifecycle"]
    o.append("## Lifecycle")
    for key in ("updatable", "update_not_creator_gated", "update_without_time_delay",
                "deletable", "delete_not_creator_gated", "delete_without_funds_check"):
        v = lc.get(key)
        o.append(f"- {key}: {'yes' if v else 'no' if v is False else 'n/a'}")
    o.append("")
    if b["storage"]:
        o.append("## Storage")
        for s in b["storage"]:
            kind = f"{s['kind']} {'map' if s['is_map'] else 'key'}"
            key = s.get("name") or repr(s.get("key_or_prefix"))
            types = " -> ".join(x for x in (s.get("arc56_key_type"), s.get("arc56_value_type")
                                            or s.get("storage_type")) if x)
            o.append(f"- {kind} {key}: {types}  ops={','.join(s.get('ops', ()))}")
        o.append("")
    if b["inner_transactions"]:
        o.append("## Inner transactions")
        for g in b["inner_transactions"]:
            o.append(f"- submit @L{g['submit_line']}:")
            for t in g["txns"]:
                flds = ", ".join(f"{k}={'|'.join(v['values']) or '?'}" for k, v in t["fields"].items())
                o.append(f"  - {'/'.join(t['type'] or ['?'])} @L{t['begin_line']}: {flds}")
        o.append("")
    o.append("## Attack surface (attacker input → dangerous sink)")
    if not b["attack_surface"]:
        o.append("- none reachable")
    for v in b["attack_surface"]:
        by = f" ({', '.join(v['confirmed_by'])})" if v.get("confirmed_by") else ""
        src = f"  ← {v['source']}" if v.get("source") else ""
        o.append(f"- **{v['verdict']}** [{v['severity']}] {v['file']}:{v['line']} "
                 f"{v['category']} {v['op']} {v['field']}{by}{src}".rstrip())
    o.append("")
    o.append(f"## Findings ({b['findings_summary']['total']})")
    if not b["findings"]:
        o.append("- none")
    for f in b["findings"]:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f"{f['file']} (whole program)"
        meth = f" [{f['method']}]" if f.get("method") else ""
        o.append(f"- [{f['severity'].upper()}] {f['rule_id']} @ {loc}{meth}: {f['message']}")
    o.append("")
    if b["group_shape"].get("constraints") or b["group_shape"].get("exits"):
        o.append("## Forced group shape")
        o.append("```json")
        import json as _json
        o.append(_json.dumps(b["group_shape"], indent=1)[:4000])
        o.append("```")
        o.append("")
    o.append(f"## Analysis health: {'complete' if b['complete'] else 'INCOMPLETE'}")
    for n in b["notifications"]:
        where = f" {n.get('file')}" if n.get("file") else ""
        who = f" [{n.get('detector')}]" if n.get("detector") else ""
        o.append(f"- {n.get('kind')}{where}{who}: {n.get('message')}")
    o.append("")
    o.append(f"_{b['semantics']}_")
    return "\n".join(o)


__all__ = ["contract_brief", "render_brief_markdown"]
