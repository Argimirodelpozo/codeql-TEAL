"""Lift a :class:`tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

The lift reconstructs a typed, Puya-shaped IR from decompiled TEAL and renders /
optimises it with Puya's own machinery (its text emitter and optimiser passes):

    from tealtools.ssa import SSAProgram
    from tealtools.WIP_lift2puyaIR import render
    print(render(SSAProgram(db), optimize_ir=True))

Pipeline: ``lift`` (:mod:`lift`) builds an intermediate *pre-IR* model
(:mod:`pre_ir`); ``render`` (:mod:`to_puya_ir`) lowers it to the real Puya IR. Shared
op/type metadata lives in :mod:`optypes`, TEAL-literal parsing in
:mod:`teal_const`.  ``python -m tealtools.WIP_lift2puyaIR <db>`` renders a DB.
"""
from . import pre_ir
from .lift import lift
from .to_puya_ir import render

__all__ = ["render", "lift", "pre_ir"]
