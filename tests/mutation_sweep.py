"""Which decisions does the ground-truth corpus actually pin?

`test_mutation_gates.py` asks that of a hand-picked handful. This sweeps it:
force every analysis predicate to a constant and record which `safe/` fixtures
flip. A fixture flipped by NOTHING is passing by accident — it proves the code
agrees with itself, not that the code is right.

Not a test (it answers a research question, not a regression one, and the taint
layer is slow). Run it directly:

    python -m tests.mutation_sweep --layer guard     # ~1 min, the useful default
    python -m tests.mutation_sweep --timeout 30      # both layers, bounded

COST, measured: the guard layer sweeps in about a minute. The taint layer does
NOT — several taint mutations do not merely change the answer, they explode the
analysis (forcing `TaintAnalysis._in_scope` true propagates taint to everything),
so a pass stops finishing. `--timeout` bounds each mutation and reports the skip,
but note a signal cannot interrupt a long call inside a C extension, so a
pathological mutation can still overrun its alarm. Budget accordingly rather
than assuming the default finishes.

WHY THIS FILE EXISTS: the sweep was written from scratch three times in one
session and hit the SAME two harness bugs each time. Both make a working
predicate look untested, which reads as a coverage gap that is not there:

1. Patching only the defining module is a no-op wherever a consumer did
   `from .mod import pred`. First run reported 28 false gaps. Fix: patch EVERY
   module holding the name, and assert at least one binding was hit.
2. Collecting predicates by walking `ast.parse(src).body` finds MODULE-LEVEL
   functions only. `FundFlowFinding.guarded` is a `@property`, so it was
   silently absent and its whole lifted family read as "0 fixtures pinned" —
   forcing the property directly shows it pins 16. Fix: walk ClassDef bodies
   too and patch class attributes with `setattr(cls, name, property(...))`.

Measured 2026-07-30: 108 of 127 safe fixtures are pinned by a guard or taint
decision. Of the remaining 19, some are pinned by a detector's own predicate
(`unsafe-division-order._divides_by_one`) and the rest are decided by INLINE
logic that is not a named bool function, so this instrument cannot reach them —
a limit of the method, not a proven gap.
"""
from __future__ import annotations

import argparse
import ast
import collections
import importlib
import pathlib
import signal
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
BENCH = REPO / "tests" / "benchmark"

#: Modules whose bool predicates decide GUARD questions.
GUARD_MODULES = {
    "tealql.security._enforcement": "src/tealql/security/_enforcement.py",
    "tealql.security._field_protection": "src/tealql/security/_field_protection.py",
    "tealql.security._action_guards": "src/tealql/security/_action_guards.py",
    "tealql.tealtools.cfg.path_predicates": "src/tealql/tealtools/cfg/path_predicates.py",
    "tealql.tealtools.cfg.exits": "src/tealql/tealtools/cfg/exits.py",
}
#: ...and TAINT / value questions.
TAINT_MODULES = {
    "tealql.tealtools.dataflow.engine": "src/tealql/tealtools/dataflow/engine.py",
    "tealql.tealtools.dataflow.byte_taint": "src/tealql/tealtools/dataflow/byte_taint.py",
    "tealql.tealtools.dataflow.taint_graph": "src/tealql/tealtools/dataflow/taint_graph.py",
    "tealql.tealtools.dataflow.predicate_aware":
        "src/tealql/tealtools/dataflow/predicate_aware.py",
    "tealql.tealtools.lift.taint": "src/tealql/tealtools/lift/taint.py",
    "tealql.tealtools.lift.fund_flow": "src/tealql/tealtools/lift/fund_flow.py",
    "tealql.security._value_flow": "src/tealql/security/_value_flow.py",
    "tealql.security.sink_verdict": "src/tealql/security/sink_verdict.py",
}


def predicates(modules: dict) -> "list[tuple[str, str, str]]":
    """``(module, name, kind)`` for every bool predicate — including class
    methods and properties, which a ``tree.body`` walk alone would miss."""
    out = []
    for mod, rel in modules.items():
        p = REPO / rel
        if not p.exists():
            continue
        for n in ast.parse(p.read_text()).body:
            if (isinstance(n, ast.FunctionDef) and isinstance(n.returns, ast.Name)
                    and n.returns.id == "bool"):
                out.append((mod, n.name, "func"))
            elif isinstance(n, ast.ClassDef):
                for m in n.body:
                    if (isinstance(m, ast.FunctionDef)
                            and isinstance(m.returns, ast.Name)
                            and m.returns.id == "bool"
                            and not m.name.startswith("__")):
                        kind = "prop" if any(getattr(d, "id", "") == "property"
                                             for d in m.decorator_list) else "meth"
                        out.append((mod, f"{n.name}.{m.name}", kind))
    return out


def _apply(mod_name: str, name: str, kind: str, value: bool):
    """Force one predicate to ``value``; returns a restore callable.

    HAZARD: for a module-level function this MUST patch every module that bound
    the name, and must fail loudly when it binds none — a mutation that does not
    land reads as "survived", i.e. as a coverage gap that does not exist."""
    m = importlib.import_module(mod_name)
    if "." in name:
        cls_name, member = name.split(".")
        cls = getattr(m, cls_name)
        original = cls.__dict__.get(member, getattr(cls, member))
        setattr(cls, member,
                property(lambda self, _v=value: _v) if kind == "prop"
                else (lambda self, *a, _v=value, **k: _v))
        return lambda: setattr(cls, member, original)

    original = getattr(m, name)
    forced = lambda *a, _v=value, **k: _v          # noqa: E731
    holders = [mod for mod in list(sys.modules.values())
               if mod is not None and getattr(mod, name, None) is original]
    if not holders:
        raise RuntimeError(f"{mod_name}::{name}: patched NOTHING — vacuous")
    for mod in holders:
        setattr(mod, name, forced)
    return lambda: [setattr(mod, name, original) for mod in holders]


def firing_safe_fixtures() -> "set[str]":
    from tealql.security import DETECTORS
    from tealql.tealtools.ssa import SSAProgram

    out = set()
    for f in sorted(BENCH.glob("*/safe/*.teal")):
        det = f.parent.parent.name
        cls = DETECTORS.get(det)
        if cls is None:
            continue
        try:
            if cls(SSAProgram(str(f))).detect():
                out.add(f"{det}/{f.name}")
        except Exception:
            continue
    return out


def _raise_timeout(signum, frame):
    raise TimeoutError


def sweep(modules: dict, per_mutation_timeout: int = 90) -> "dict[str, set[str]]":
    """``fixture -> {mutations that make it fire}``."""
    pinned: "dict[str, set[str]]" = collections.defaultdict(set)
    baseline = firing_safe_fixtures()
    if baseline:
        print(f"WARNING: {len(baseline)} safe fixture(s) fire unmutated: "
              f"{sorted(baseline)}", file=sys.stderr)
    for mod, name, kind in predicates(modules):
        for value in (True, False):
            try:
                restore = _apply(mod, name, kind, value)
            except Exception as e:
                print(f"  skip {mod}::{name}: {e}", file=sys.stderr)
                continue
            # HAZARD: some mutations make the analysis EXPLODE rather than
            # merely answer differently — forcing `TaintAnalysis._in_scope`
            # true propagates taint to everything and one pass stops finishing
            # in any useful time. Bound each mutation and record the skip; an
            # unbounded sweep just hangs, printing nothing for 20+ minutes.
            try:
                signal.signal(signal.SIGALRM, _raise_timeout)
                signal.alarm(per_mutation_timeout)
                try:
                    for fx in firing_safe_fixtures() - baseline:
                        pinned[fx].add(f"{name}:{'T' if value else 'F'}")
                finally:
                    signal.alarm(0)
            except TimeoutError:
                print(f"  TIMEOUT {mod}::{name}:{'T' if value else 'F'} "
                      f"(>{per_mutation_timeout}s) — this mutation explodes the "
                      f"analysis; not measurable this way", file=sys.stderr)
            finally:
                restore()
    return pinned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--layer", choices=("guard", "taint", "both"), default="both")
    ap.add_argument("--timeout", type=int, default=90,
                    help="seconds per mutation before skipping it")
    args = ap.parse_args()
    mods = {}
    if args.layer in ("guard", "both"):
        mods.update(GUARD_MODULES)
    if args.layer in ("taint", "both"):
        mods.update(TAINT_MODULES)

    pinned = sweep(mods, args.timeout)
    allsafe = {f"{f.parent.parent.name}/{f.name}" for f in BENCH.glob("*/safe/*.teal")}
    unpinned = sorted(allsafe - set(pinned))
    print(f"safe fixtures        : {len(allsafe)}")
    print(f"pinned by a mutation : {len(pinned)}")
    print(f"UNPINNED             : {len(unpinned)}")
    for d, n in collections.Counter(u.split("/")[0] for u in unpinned).most_common():
        print(f"   {d:34} {n}")
    print("\nAn unpinned fixture proves nothing about the analysis — either it "
          "needs a decisive case, or its detector's logic is inline rather than "
          "a named predicate and this instrument cannot see it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
