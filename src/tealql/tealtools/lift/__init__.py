"""Lift a :class:`tealql.tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift import render
    print(render(SSAProgram("contract.teal"), optimize_ir=True))

``lift`` (:mod:`lift`) builds the pre-IR (:mod:`pre_ir`); ``render``
(:mod:`to_puya_ir`) lowers it to real Puya IR. Metadata in :mod:`tealql.tealtools.avm`,
literal parsing in :mod:`teal_const`. ``python -m tealql.tealtools.lift <contract>``
renders a contract.

``render`` / ``to_puya`` are exported LAZILY (PEP 562 ``__getattr__``):
they live in :mod:`to_puya_ir`, the only module on this path that imports
the ``puya`` package. The detector-facing side — ``lift`` / ``_Lifter``
and the pre-IR taint layer — is puya-free, so ``import tealql.tealtools.lift``
(which the security ``ir_lifter`` bridge triggers via
``from tealql.tealtools.lift.lift import _Lifter``) must not pull in puya. Only
touching ``render`` / ``to_puya`` does.
"""
from . import pre_ir
from .lift import lift

__all__ = ["render", "to_puya", "lift", "lift_to_teal", "pre_ir", "build_lifter"]


def build_lifter(prog):
    """Build + cache the pre-IR ``_Lifter`` for ``prog``, or ``None`` if it does
    not lift. Puya-free (the pre-IR path never imports ``puya``).

    The QUERY-side counterpart to ``security.common.ir_lifter``: that one warns
    loudly (its detectors must surface reduced precision), whereas this degrades
    *quietly* so a caller can transparently fall back to a coarser analysis. Like
    ``ir_lifter`` it lifts a FRESH ``SSAProgram`` off ``prog.source_path`` (the
    lift mutates its input CFG) so ``prog``'s own SSA substrate stays pristine.

    Both share ONE cache attribute (``_ir_lifter``), so a program is lifted at
    most once no matter which side runs first. When ``ir_lifter`` might also run
    (e.g. a ``--verify`` flow), pre-warm through IT so its warnings aren't lost to
    this function's quiet build."""
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
    # Deferred so the package imports without puya installed; only the
    # decompilation entry points need it.
    if name in ("render", "to_puya"):
        from . import to_puya_ir
        return getattr(to_puya_ir, name)
    if name == "lift_to_teal":
        from . import backend
        return backend.lift_to_teal
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
