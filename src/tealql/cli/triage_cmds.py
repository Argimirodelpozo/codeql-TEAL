"""Triage subcommands: ``triage`` (report the triage store joined to the current
findings; ``--export-baseline`` writes the false-positive-triaged findings as a
v2 baseline) and ``triage-eval`` (agreement of stored verdicts with the
labelled benchmark). The store and its semantics live in
:mod:`tealql.agent.triage`; verdicts there are advice, never detector verdicts."""
from __future__ import annotations

import json as _json
import sys

from ._common import _add_common_flags, _resolve


def _cmd_triage(args) -> int:
    """Exit 2 when the scan was incomplete, else 0 (a report, not a gate)."""
    from tealql.agent.triage import export_baseline, triage_report
    path = _resolve(args)
    if args.export_baseline:
        out = export_baseline(str(path), args.export_baseline, store=args.store,
                              mode=args.mode)
        if args.json_out:
            print(_json.dumps(out, indent=2))
        else:
            print(f"wrote {out['fingerprints']} false-positive fingerprint(s) to "
                  f"{out['written']}" + (f" ({out['stale_excluded']} stale record(s) "
                                         "excluded)" if out["stale_excluded"] else ""),
                  file=sys.stderr)
        return 0
    rep = triage_report(target=str(path), store=args.store, mode=args.mode)
    if args.json_out:
        print(_json.dumps(rep, indent=2, default=str))
        return 0 if rep["complete"] else 2
    s = rep["summary"]
    print(f"tealql triage: {s['findings']} finding(s), {s['triaged']} triaged, "
          f"{s['untriaged']} untriaged, {s['stale_records']} stale record(s)  "
          f"[store {rep['store']}]")
    for verdict, n in s["by_verdict"].items():
        print(f"  {verdict}: {n}")
    for r in rep["records"]:
        f = r["finding"]
        loc = f"{f['file']}:{f['line']}" if f.get("line") else f["file"]
        print(f"  [{r['verdict']}] {r['rule']} @ {loc}  ({r['reviewer']}, "
              f"evidence {r['evidence_lines'] or '-'}): {r['rationale']}")
    for r in rep["untriaged"]:
        loc = f"{r['file']}:{r['line']}" if r.get("line") else r["file"]
        print(f"  [untriaged] [{r['severity'].upper()}] {r['rule']} @ {loc}  "
              f"{r['fingerprint']}")
    for r in rep["stale"]:
        print(f"  [STALE] {r['rule']} @ {r['file']} ({r['verdict']}): finding "
              f"{r['fingerprint']} no longer produced — re-triage")
    if not rep["complete"]:
        print("\nAnalysis INCOMPLETE:")
        for n in rep["notifications"]:
            print(f"  [{n.get('kind')}] {n.get('message')}")
        return 2
    return 0


def _cmd_triage_eval(args) -> int:
    from tealql.agent.triage import evaluate_against_benchmark
    out = evaluate_against_benchmark(args.store)
    if args.json_out:
        print(_json.dumps(out, indent=2))
        return 0
    o = out["overall"]
    rate = "n/a" if o["agreement"] is None else f"{o['agreement']:.1%}"
    print(f"triage agreement with the labelled benchmark: {rate} "
          f"({o['agree']} agree, {o['disagree']} disagree, {o['abstain']} needs_context; "
          f"{out['unlabelled']} unlabelled record(s) ignored)")
    for det, r in out["per_detector"].items():
        rr = "n/a" if r["agreement"] is None else f"{r['agreement']:.1%}"
        print(f"  {det:32} {rr:>7}  agree={r['agree']} disagree={r['disagree']} "
              f"abstain={r['abstain']}")
    for d in out["disagreements"]:
        print(f"  DISAGREE {d['rule']} {d['file']} (label {d['label']}, verdict "
              f"{d['verdict']}, {d['reviewer']})")
    return 0


def register(sub, add) -> None:
    tri = add("triage",
              "report the agent/human triage store joined to the current findings "
              "(verdicts are advice; stale records flagged); --export-baseline PATH "
              "writes the false_positive-triaged findings as a v2 baseline",
              _cmd_triage)
    tri.add_argument("--store", default=None,
                     help="triage store JSON (default <scan root>/.tealql/triage.json)")
    tri.add_argument("--mode", choices=["auto", "app", "logicsig"], default="auto")
    tri.add_argument("--export-baseline", default=None, metavar="PATH",
                     help="write a baseline of ONLY the findings triaged false_positive "
                          "(with the audit trail) for detections-scan --baseline")

    ev = sub.add_parser(
        "triage-eval",
        help="agreement of a triage store's verdicts with the labelled benchmark "
             "(tests/benchmark/<detector>/{vuln,safe}/), per detector — measure a "
             "reviewer this way before trusting it")
    ev.add_argument("--store", required=True, help="triage store JSON to evaluate")
    _add_common_flags(ev)
    ev.set_defaults(handler=_cmd_triage_eval)
