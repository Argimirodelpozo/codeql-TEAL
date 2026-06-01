"""Experimental sandbox — third iteration.

A Puya-shaped IR **lifter** for debugging xgov: build the SSAProgram, run the
passes in :data:`~tealtools.WIP_lift2puyaIR.pipeline.PASSES`, ``lift`` it into
the Puya IR model (:mod:`~tealtools.WIP_lift2puyaIR.ir`), apply the model
transforms, and render the ``.ssa.slot.ir`` shape to the repo-root
``xgov.ssa.ir``. Exploratory / demo; not wired into the detector or CLI
surface. See :mod:`tealtools.WIP_lift2puyaIR.pipeline`.

    python -m tealtools.WIP_lift2puyaIR
"""
from . import ir
from .lift import lift
from .pipeline import PASSES, main, render

__all__ = ["PASSES", "main", "render", "lift", "ir"]
