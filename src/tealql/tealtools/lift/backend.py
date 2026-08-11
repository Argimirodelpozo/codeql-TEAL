"""Full decompilation backend: SSA -> Puya IR -> split/destructure -> MIR -> TEAL.

Runs Puya's OWN backend on past where the lift proper (:mod:`to_puya_ir`) stops, so a
contract can be round-tripped: disassemble -> lift -> recompile.

HAZARD: this imports the ``puya`` package, so it must stay behind the lazy
:func:`lift_to_teal` export — ``import tealql.tealtools.lift`` has to remain
puya-free. Failures surface as :class:`tealql.tealtools.diagnostics.errors.LiftError`.
"""
from __future__ import annotations

import logging
import re

from ..diagnostics.errors import LiftError
from . import _puya_compat as _compat

logger = logging.getLogger("tealql.tealtools.lift")


def lift_to_teal(source, *, aggressive: bool = False,
                 diagnostics: list | None = None) -> str:
    """``SSAProgram(source)`` -> Puya IR -> split/destructure -> MIR -> TEAL text.

    ``aggressive`` additionally runs the codegen-changing optimiser passes (intrinsic
    folding, ARC4 encode/decode elimination). Any failure raises
    :class:`tealql.tealtools.diagnostics.errors.LiftError`, cause chained, tagged with the stage
    that failed. Errors puya merely LOGS along the way (its validators do not raise)
    are appended to ``diagnostics`` when given — see
    :func:`to_puya_ir._puya_error_capture`."""
    import puya.ir.models as M
    from puya.context import ArtifactCompileContext, CompiledProgramProvider
    from puya.errors import InternalError
    from puya.ir.models import ProgramKind, SlotAllocation, SlotAllocationStrategy
    from puya.mir.main import program_ir_to_mir
    from puya.options import PuyaOptions
    from puya.teal.main import mir_to_teal
    from puya.teal.output import emit_teal
    from ..ssa import SSAProgram
    from . import to_puya_ir

    prog = SSAProgram(str(source))
    # Emit the program's ACTUAL AVM version: a v11 field like `block BlkFeeSink`
    # needs `#pragma version 11` or the assembler rejects it. FLOOR at 10 -- the lift
    # always reconstructs subroutines/stack with `proto`/`dupn`/`frame_*` (v8+), so a
    # lower-versioned source could not assemble its own recompiled body.
    # MAX across every source, and scan past a header: the pragma is only required
    # to precede the first instruction, so a licence comment pushes it below a
    # fixed 4-line window, and taking the LAST file's answer instead of the
    # highest lets a v10 file veto a v11 sibling. Either way the version comes out
    # too low and the recompiled body stops assembling — the failure this block
    # exists to avoid. Stop at the first non-comment, non-blank line.
    avm_version = 10
    for _lines in to_puya_ir._load_src(prog).values():
        for _ln in _lines:
            _s = _ln.strip()
            if not _s or _s.startswith("//"):
                continue
            _m = re.match(r"#pragma version (\d+)", _s)
            if _m:
                avm_version = max(avm_version, int(_m.group(1)))
            break                      # first real line decides for this file
    # Lower + optimise (these raise LiftError stage lower/optimize themselves).
    # MIR rejects Puya's exact ``any`` type. This private path concretises only
    # values whose family recovery genuinely remained unresolved; public Puya
    # IR and every analysis retain them as ``any`` and cannot mistake the
    # backend placeholder for recovered uint64 evidence.
    main, subs = to_puya_ir._to_puya_for_codegen(prog, diagnostics=diagnostics)
    to_puya_ir.optimize([main, *subs], aggressive=aggressive, diagnostics=diagnostics)
    try:
        with to_puya_ir._puya_error_capture("backend", diagnostics):
            try:
                provider = CompiledProgramProvider()
            except Exception:
                provider = object.__new__(CompiledProgramProvider)
            ctx = ArtifactCompileContext(
                options=PuyaOptions(), compilation_set={}, sources_by_path={},
                compiled_program_provider=provider, output_path_provider=None)
            program = M.Program(
                kind=ProgramKind.approval, main=main, subroutines=list(subs),
                avm_version=avm_version,
                slot_allocation=SlotAllocation(
                    reserved=frozenset(), strategy=SlotAllocationStrategy.none))
            for s in [main, *subs]:
                _compat.split_parallel_copies(ctx, s)
            _destructure_with_orphans(ctx, program)
            for _ in range(50):
                try:
                    teal = mir_to_teal(ctx, program_ir_to_mir(ctx, program))
                    break
                except InternalError as e:
                    # MIR lowering drops a register defined only in a now-unreachable
                    # block. Define it (typed zero, at entry) in EVERY sub using that
                    # name: the error doesn't say which sub, and the same name recurs
                    # across subs, so a first-match define never converges.
                    m = _compat.UNDEFINED_REGISTER_RE.search(str(e))
                    hits = m and [
                        to_puya_ir._define_named_orphan([s], m.group(1), int(m.group(2)))
                        for s in [main, *subs]]
                    if not (hits and any(hits)):
                        raise
                    logger.warning(
                        "reconstruction orphan %s#%s defined as typed ZERO during MIR "
                        "lowering — recompiled TEAL may compute with 0",
                        m.group(1), m.group(2))
            else:
                raise RuntimeError("backend lowering did not converge")
            return emit_teal(ctx, teal)
    except LiftError:
        raise
    except Exception as e:
        raise LiftError(f"{type(e).__name__}: {e}", stage="backend") from e


def _destructure_with_orphans(ctx, program) -> None:
    """Puya's ``destructure_ssa``, per-subroutine, with an orphan retry on the final validation.

    HAZARD: never retry the whole program. ``destructure_ssa`` mutates in place, so
    when a late sub trips a reconstruction orphan the earlier subs are already
    destructured, and re-validating them raises "assigned multiple times" on their
    now-materialised phis. Run each sub's steps EXACTLY once; an orphan only surfaces
    at the closing ``attrs.validate``, where it is defined as a typed zero and
    RE-VALIDATED -- never re-destructured."""
    import attrs

    import puya.ir.models as M
    from . import to_puya_ir
    from puya.errors import InternalError
    from puya.ir.destructure.coalesce_locals import coalesce_locals
    from puya.ir.destructure.critical_edges import split_critical_edges
    from puya.ir.destructure.optimize import post_ssa_optimizer
    from puya.ir.destructure.parcopy import sequentialize_parallel_copies
    from puya.ir.destructure.remove_phi import convert_to_cssa, destructure_cssa

    def _validate(sub, check):
        # `check` is validate_with_ssa while still in (C)SSA, attrs.validate once
        # destructured -- the IR is then intentionally OUT of SSA (registers ARE
        # assigned multiple times), so the SSA check must NOT run there. A bad read is
        # a reconstruction orphan (a value the lift lost to a frame / dynamic-scratch
        # gap): define it as a typed zero at the sub entry and re-validate.
        # "assigned multiple times" is never an orphan, so it is re-raised.
        for _ in range(64):
            try:
                check(sub)
                return
            except InternalError as e:
                if _compat.ASSIGNED_MULTIPLE in str(e):
                    raise
                bad = set(_compat.get_used_registers(sub.body)) - (
                    frozenset(sub.parameters)
                    | frozenset(_compat.get_assigned_registers(sub.body)))
                if not bad:
                    raise
                # On an uncovered contract this is a silently-wrong recompile.
                logger.warning(
                    "reconstruction orphan(s) in %s defined as typed ZERO — "
                    "recompiled TEAL may compute with 0 for: %s",
                    sub.id, ", ".join(sorted(r.name for r in bad)))
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
