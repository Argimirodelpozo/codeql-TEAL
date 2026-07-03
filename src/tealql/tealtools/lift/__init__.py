"""Lift a :class:`tealql.tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift import render
    print(render(SSAProgram("contract.teal"), optimize_ir=True))

``lift`` (:mod:`lift`) builds the pre-IR (:mod:`pre_ir`); ``render``
(:mod:`to_puya_ir`) lowers it to real Puya IR. Metadata in :mod:`optypes`,
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

__all__ = ["render", "to_puya", "lift", "lift_to_teal", "pre_ir"]


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
