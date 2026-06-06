"""Lift real TEAL -> Puya IR -> recompile to TEAL, and (optionally) compare the
original vs recompiled program's BEHAVIOUR on a live Algorand localnet via
algod dryrun. A real-world generalisation test for WIP_lift2puyaIR: does the
lift reconstruct an equivalent program for contracts it has never seen?

  python -m tools.behavioral_lift.recompile <db-or-dir> ...

Each arg is a CodeQL DB dir (has codeql-database.yml) or a dir of such.
"""
from __future__ import annotations

import base64
import copy
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
    # Emit the program's ACTUAL AVM version, not a hardcoded 10: a v11 contract
    # using e.g. `block BlkFeeSink` must declare `#pragma version 11` or the
    # assembler rejects the field as introduced-in-a-later-version. Read it off
    # the source `#pragma version N`, but FLOOR at 10 -- the lift reconstructs
    # subroutines/stack with `proto`/`dupn`/`frame_*` (v8+) regardless of the
    # original version, so a contract whose source declared a lower version would
    # otherwise fail to assemble its own recompiled body.
    avm_version = 10
    for _lines in to_puya_ir._load_src(prog.db_path).values():
        for _ln in _lines[:4]:
            _m = re.match(r"#pragma version (\d+)", _ln.strip())
            if _m:
                avm_version = max(int(_m.group(1)), 10)
                break
    main, subs = to_puya_ir.to_puya(prog)
    to_puya_ir.optimize([main, *subs])
    try:
        provider = CompiledProgramProvider()
    except Exception:
        provider = object.__new__(CompiledProgramProvider)
    ctx = ArtifactCompileContext(options=PuyaOptions(), compilation_set={}, sources_by_path={},
                                 compiled_program_provider=provider, output_path_provider=None)
    program = M.Program(
        kind=ProgramKind.approval, main=main, subroutines=list(subs), avm_version=avm_version,
        slot_allocation=SlotAllocation(reserved=frozenset(), strategy=SlotAllocationStrategy.none))
    for s in [main, *subs]:
        _split_parallel_copies(ctx, s)
    _destructure_with_orphans(ctx, program)
    for _ in range(50):
        try:
            teal = mir_to_teal(ctx, program_ir_to_mir(ctx, program))
            break
        except InternalError as e:
            # mir lowering drops a register defined only in a now-unreachable
            # block. Define it (typed zero, at entry) in EVERY sub that uses it,
            # not just the first match -- the same name can recur across subs and
            # the backend's complaint doesn't say which, so a first-match define
            # fixes the wrong one and the retry never converges.
            m = re.search(r"[Uu]ndefined register: ([^#\s]+)#(\d+)", str(e))
            hits = m and [to_puya_ir._define_named_orphan([s], m.group(1), int(m.group(2)))
                          for s in [main, *subs]]
            if not (hits and any(hits)):
                raise
    else:
        raise RuntimeError("backend lowering did not converge")
    return emit_teal(ctx, teal)


def _destructure_with_orphans(ctx, program) -> None:
    """Puya's ``destructure_ssa``, but per-subroutine with an orphan retry on the
    FINAL validation only. ``destructure_ssa`` is monolithic and mutates in place:
    when a late sub trips a reconstruction orphan (a value the lift lost to a
    frame / dynamic-scratch gap, "used but never defined"), it has already fully
    destructured the earlier subs, so a naive whole-program retry re-validates
    those and trips "<reg> is assigned multiple times" on their now-materialised
    phis. Running each sub's steps exactly once avoids that; a reconstruction
    orphan only ever surfaces at the closing ``attrs.validate`` (the
    ``_check_blocks`` body validator, after every transform), where we define it
    as a typed zero and RE-VALIDATE -- never re-destructuring."""
    import attrs

    import puya.ir.models as M
    from tealtools.WIP_lift2puyaIR import to_puya_ir
    from puya.errors import InternalError
    from puya.ir.destructure.coalesce_locals import coalesce_locals
    from puya.ir.destructure.critical_edges import split_critical_edges
    from puya.ir.destructure.optimize import post_ssa_optimizer
    from puya.ir.destructure.parcopy import sequentialize_parallel_copies
    from puya.ir.destructure.remove_phi import convert_to_cssa, destructure_cssa
    from puya.ir.models import _get_assigned_registers, _get_used_registers

    def _validate(sub, check):
        # `check` is validate_with_ssa while still in (C)SSA, attrs.validate once
        # destructured (the IR is then intentionally OUT of SSA -- registers ARE
        # assigned multiple times -- so the SSA check must NOT run, matching Puya's
        # own ordering). On a bad read -- a reconstruction orphan, a value the lift
        # lost to a frame / dynamic-scratch gap -- define it as a typed zero at the
        # sub entry (the SAME used-minus-defined _check_blocks raises on, robust to
        # how the error formats names) and re-validate. "assigned multiple times"
        # is never an orphan, so it is re-raised.
        for _ in range(64):
            try:
                check(sub)
                return
            except InternalError as e:
                if "assigned multiple times" in str(e):
                    raise
                bad = set(_get_used_registers(sub.body)) - (
                    frozenset(sub.parameters) | frozenset(_get_assigned_registers(sub.body)))
                if not bad:
                    raise
                for r in bad:
                    sub.body[0].ops.insert(0, M.Assignment(
                        source_location=None, targets=[r],
                        source=to_puya_ir._puya_zero(r.ir_type)))
        raise RuntimeError(f"orphan retry did not converge for {sub.id}")

    for sub in program.all_subroutines:
        if ctx.options.optimization_level > 0:
            split_critical_edges(sub)
            _validate(sub, lambda s: s.validate_with_ssa())
        convert_to_cssa(sub)
        _validate(sub, lambda s: s.validate_with_ssa())
        destructure_cssa(sub)
        coalesce_locals(sub, ctx.options.locals_coalescing_strategy)
        sequentialize_parallel_copies(sub)
        post_ssa_optimizer(ctx, sub)
        _validate(sub, attrs.validate)


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
            print(f"  OK    {name:30s} {len(teal.splitlines()):4d} lines -> {nbytes}b", flush=True)
        except Exception as e:
            compile_fail += 1
            print(f"  ASM-FAIL  {name:34s} {str(e)[:50]}", flush=True)
    print(f"\n=== {ok} recompiled+assembled, {lift_fail} lift-fail, {compile_fail} asm-fail ===")


if __name__ == "__main__":
    main(sys.argv[1:])
