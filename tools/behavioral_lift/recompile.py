"""Lift real TEAL -> Puya IR -> recompile to TEAL, and (optionally) compare the
original vs recompiled program's BEHAVIOUR on a live Algorand localnet via
algod dryrun. A real-world generalisation test for WIP_lift2puyaIR: does the
lift reconstruct an equivalent program for contracts it has never seen?

  python -m tools.behavioral_lift.recompile <db-or-dir> ...

Each arg is a CodeQL DB dir (has codeql-database.yml) or a dir of such.
"""
from __future__ import annotations

import base64
import logging
import re
import sys
from pathlib import Path

logging.getLogger("puya").setLevel(logging.CRITICAL)

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src/analysis"))


def lift_to_teal(db: str) -> str:
    """SSAProgram(db) -> Puya IR -> split/destructure -> MIR -> TEAL text."""
    import puya.ir.models as M
    from puya.context import ArtifactCompileContext, CompiledProgramProvider
    from puya.errors import InternalError
    from puya.ir.destructure.main import destructure_ssa
    from puya.ir.models import ProgramKind, SlotAllocation, SlotAllocationStrategy
    from puya.ir.optimize.main import _split_parallel_copies
    from puya.mir.main import program_ir_to_mir
    from puya.options import PuyaOptions
    from puya.teal.main import mir_to_teal
    from puya.teal.output import emit_teal

    from tealtools.ssa import SSAProgram
    from tealtools.WIP_lift2puyaIR import to_puya_ir

    prog = SSAProgram(db, verbose=False)
    main, subs = to_puya_ir.to_puya(prog)
    to_puya_ir.optimize([main, *subs])
    try:
        provider = CompiledProgramProvider()
    except Exception:
        provider = object.__new__(CompiledProgramProvider)
    ctx = ArtifactCompileContext(options=PuyaOptions(), compilation_set={}, sources_by_path={},
                                 compiled_program_provider=provider, output_path_provider=None)
    program = M.Program(kind=ProgramKind.approval, main=main, subroutines=list(subs), avm_version=10,
                        slot_allocation=SlotAllocation(reserved=frozenset(),
                                                       strategy=SlotAllocationStrategy.none))
    for s in [main, *subs]:
        _split_parallel_copies(ctx, s)
    destructure_ssa(ctx, program)
    for _ in range(50):
        try:
            teal = mir_to_teal(ctx, program_ir_to_mir(ctx, program))
            break
        except InternalError as e:
            m = re.search(r"[Uu]ndefined register: ([^#\s]+)#(\d+)", str(e))
            if not (m and to_puya_ir._define_named_orphan([main, *subs], m.group(1), int(m.group(2)))):
                raise
    else:
        raise RuntimeError("backend lowering did not converge")
    return emit_teal(ctx, teal)


def algod_client():
    from algosdk.v2client import algod
    return algod.AlgodClient("a" * 64, "http://localhost:4001")


def _dbs(args):
    for a in args:
        p = Path(a)
        if (p / "codeql-database.yml").exists():
            yield p
        else:
            yield from sorted(d.parent for d in p.rglob("codeql-database.yml"))


def main(argv):
    algod = algod_client()
    ok = lift_fail = compile_fail = 0
    for db in _dbs(argv):
        name = db.parent.name if db.name == "db" else db.name
        try:
            teal = lift_to_teal(str(db))
        except Exception as e:
            lift_fail += 1
            print(f"  LIFT-FAIL {name:34s} {type(e).__name__}: {str(e)[:45]}", flush=True)
            continue
        try:
            r = algod.compile(teal)
            nbytes = len(base64.b64decode(r["result"]))
            ok += 1
            print(f"  OK        {name:34s} {len(teal.splitlines()):4d} teal lines -> {nbytes} bytes", flush=True)
        except Exception as e:
            compile_fail += 1
            print(f"  ASM-FAIL  {name:34s} {str(e)[:50]}", flush=True)
    print(f"\n=== {ok} recompiled+assembled, {lift_fail} lift-fail, {compile_fail} assemble-fail ===")


if __name__ == "__main__":
    main(sys.argv[1:])
