"""Lift a :class:`tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

    from tealtools.ssa import SSAProgram
    from tealtools.WIP_lift2puyaIR import render
    print(render(SSAProgram(db), optimize_ir=True))

``lift`` (:mod:`lift`) builds the pre-IR (:mod:`pre_ir`); ``render``
(:mod:`to_puya_ir`) lowers it to real Puya IR. Metadata in :mod:`optypes`,
literal parsing in :mod:`teal_const`. ``python -m tealtools.WIP_lift2puyaIR <db>``
renders a DB.
"""
from . import pre_ir
from .lift import lift
from .to_puya_ir import render

__all__ = ["render", "lift", "pre_ir"]
