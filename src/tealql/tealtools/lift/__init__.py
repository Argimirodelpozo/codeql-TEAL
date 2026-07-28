"""Lift a :class:`tealql.tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

Map: :mod:`lift` builds the pre-IR (:mod:`pre_ir`), :mod:`to_puya_ir` lowers it to
real Puya IR, :mod:`backend` carries that down to TEAL again; literals in
:mod:`teal_const`, AVM metadata in :mod:`tealql.tealtools.avm`.

HAZARD: ``render`` / ``to_puya`` are exported LAZILY (PEP 562) because
:mod:`to_puya_ir` is the only module on this path that imports ``puya``. The
detector-facing side — ``lift`` / ``_Lifter`` and the pre-IR taint layer — must stay
puya-free, so never import them eagerly here.
"""
from . import pre_ir
from .lift import lift

__all__ = ["render", "to_puya", "lift", "lift_to_teal", "pre_ir", "build_lifter"]


def build_lifter(prog):
    """Build + cache the pre-IR ``_Lifter`` for ``prog``, or ``None`` if it does not lift.

    HAZARD: the lift MUTATES its input CFG, so this lifts a FRESH ``SSAProgram`` off
    ``prog.source_path`` — never hand it ``prog`` itself. Unlike
    ``security.common.ir_lifter`` it degrades QUIETLY; both share the ``_ir_lifter``
    cache, so when ``ir_lifter`` may also run, pre-warm through IT or its
    reduced-precision warnings are lost."""
    sentinel = object()
    cached = getattr(prog, "_ir_lifter", sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    src = str(getattr(prog, "source_path", "") or "")
    if src:
        try:
            from tealql.tealtools.ssa import SSAProgram
            from .lift import _Lifter
            fresh = SSAProgram(src)
            fresh.propagate_constants()
            lf = _Lifter(fresh)
            lf.build()
            lifter = lf
        except Exception:
            lifter = None            # any lift/import failure -> coarse fallback
    try:
        prog._ir_lifter = lifter
    except Exception:
        pass
    return lifter


def __getattr__(name: str):
    # Deferred so the package imports without puya installed.
    if name in ("render", "to_puya"):
        from . import to_puya_ir
        return getattr(to_puya_ir, name)
    if name == "lift_to_teal":
        from . import backend
        return backend.lift_to_teal
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
