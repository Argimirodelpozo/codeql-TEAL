"""Differential gate for the subroutine-partition policies (script-only).

Captures all three policies from :mod:`tealql.tealtools.subroutines`
(corrected / sound / construction) on EVERY fixture program — the tealtools
snapshot fixtures, the benchmark corpus, the real contracts, the puya corpus,
and the merged mainnet-probes program (~490 programs, ~25k callsubs) — keyed
identically so runs are byte-comparable.

This is THE gate for touching subroutine boundary semantics (the C2
unification was proven with it): capture a baseline on the old code, make the
change, re-capture, and `cmp` the JSONs. Any intended semantic change must
show up as an EXPLAINED diff here plus the lift corpus + behavioural gates
(see tests/test_subroutines.py for the pinned cross-policy invariants).

    python -m tests.subroutines_differential before.json   # on the old code
    ... apply the change ...
    python -m tests.subroutines_differential after.json
    cmp before.json after.json

pytest never collects this file (no test_ prefix).
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from tealql.tealtools.ssa import SSAProgram          # noqa: E402
from tealql.tealtools.ssa.ssa import PySSA           # noqa: E402
from tealql.tealtools.subroutines import identify_subroutines  # noqa: E402
from tealql.tealtools.path_predicates import PathPredicateAnalysis  # noqa: E402


def bb_key(bb):
    # Key by the first ASSIGNMENT's line (not bb.first_line, which is the
    # label line) so BasicBlock keys align with PyBlock first-op keys.
    if bb.assignments:
        loc = bb.assignments[0].location
        return f"{loc.file}:{loc.line}"
    return f"{bb.file}:{bb.first_line}"


def pyblock_key(b):
    if b.ops:
        return f"{b.ops[0].file}:{b.ops[0].line}"
    return f"<empty:{b.key}>"


def capture_ct(prog):
    info = identify_subroutines(prog)
    return {
        "entries": sorted(bb_key(b) for b in info["entries"]),
        "callsub_target": {bb_key(c): bb_key(t) for c, t in sorted(
            info["callsub_target"].items(), key=lambda kv: bb_key(kv[0]))},
        "continuations": {bb_key(c): (bb_key(t) if t is not None else None)
                          for c, t in sorted(info["continuations"].items(),
                                             key=lambda kv: bb_key(kv[0]))},
        "bodies": {bb_key(e): sorted(bb_key(b) for b in body)
                   for e, body in sorted(info["bodies"].items(),
                                         key=lambda kv: bb_key(kv[0]))},
    }


def capture_pp(prog):
    pp = PathPredicateAnalysis(prog)
    caller_of, return_target_of = pp._callsub_return_maps()
    return {
        "return_target_of": {bb_key(c): bb_key(t) for c, t in sorted(
            return_target_of.items(), key=lambda kv: bb_key(kv[0]))},
    }


def capture_ssa(prog):
    import bisect
    py = PySSA._construct(prog)
    bb_to_sub = {pyblock_key(b): pyblock_key(r)
                 for b, r in py._bb_to_sub.items()}
    # Replicate return_point (the ssa continuation policy) for the baseline.
    op_lines = sorted((op.file, op.line) for b in py.blocks for op in b.ops)
    line_to_bb = {}
    for b in py.blocks:
        for op in b.ops:
            line_to_bb[(op.file, op.line)] = b
    rps = {}
    for b in py.blocks:
        if b.ops and b.ops[-1].op == "callsub":
            last = b.ops[-1]
            i = bisect.bisect_right(op_lines, (last.file, last.line))
            rp = None
            if i < len(op_lines) and op_lines[i][0] == last.file:
                rp = line_to_bb[op_lines[i]]
            rps[pyblock_key(b)] = pyblock_key(rp) if rp is not None else None
    return {
        "bb_to_sub": dict(sorted(bb_to_sub.items())),
        "return_points": dict(sorted(rps.items())),
        "proto_io": {pyblock_key(b): list(v)
                     for b, v in sorted(py._proto_io.items(),
                                        key=lambda kv: pyblock_key(kv[0]))},
    }


def program_dirs():
    seen = []
    for root in ("tests/tealtools", "tests/benchmark", "tests/contracts",
                 "tests/experimental_IR_lift", "tests/xcontract"):
        base = REPO / root
        if not base.exists():
            continue
        for d in sorted(base.rglob("*")):
            if d.is_dir() and any(f.suffix == ".teal" for f in d.iterdir() if f.is_file()):
                seen.append(d)
    # also any top-level tests/* dirs with teal files directly
    for d in sorted((REPO / "tests").iterdir()):
        if d.is_dir() and any(f.suffix == ".teal" for f in d.iterdir() if f.is_file()):
            if d not in seen:
                seen.append(d)
    return seen


def main(out_path):
    results = {}
    fails = []
    dirs = program_dirs()
    for i, d in enumerate(dirs):
        rel = str(d.relative_to(REPO))
        try:
            prog = SSAProgram(str(d))
            entry = {
                "ct": capture_ct(prog),
                "pp": capture_pp(prog),
                "ssa": capture_ssa(prog),
            }
            results[rel] = entry
        except Exception as e:  # noqa: BLE001
            fails.append((rel, f"{type(e).__name__}: {e}"))
        if (i + 1) % 100 == 0:
            print(f"  {i+1}/{len(dirs)}", file=sys.stderr)
    Path(out_path).write_text(json.dumps(
        {"programs": results, "build_failures": fails}, indent=0, sort_keys=True))
    # cross-policy divergence stats
    n_cs = n_ssa_ct_differ = n_pp_subset_violations = 0
    for rel, r in results.items():
        ct_cont = r["ct"]["continuations"]
        ssa_rp = r["ssa"]["return_points"]
        pp_rt = r["pp"]["return_target_of"]
        for cs, tgt in ct_cont.items():
            n_cs += 1
            if cs in ssa_rp and ssa_rp[cs] != tgt:
                n_ssa_ct_differ += 1
        for cs, tgt in pp_rt.items():
            if ct_cont.get(cs, "<missing>") != tgt:
                n_pp_subset_violations += 1
    print(f"programs={len(results)} build_failures={len(fails)} callsubs={n_cs}")
    print(f"ssa-vs-ct continuation differs: {n_ssa_ct_differ}")
    print(f"pp target != ct continuation (where pp resolved): {n_pp_subset_violations}")
    for rel, err in fails[:5]:
        print("  FAIL", rel, err)


if __name__ == "__main__":
    main(sys.argv[1])
