"""Experimental sandbox — third iteration.

A block-argument renderer for debugging xgov: build the program, run the
passes in :data:`~tealtools.experimental_3.pipeline.PASSES` (edit as we add
passes), render the block-argument out-of-SSA view to the repo-root
``xgov_block_args.txt``. Exploratory / demo; not wired into the detector or
CLI surface. See :mod:`tealtools.experimental_3.pipeline`.

    python -m tealtools.experimental_3
"""
from .pipeline import PASSES, main, render
from .puya_ir import render_puya

__all__ = ["PASSES", "main", "render", "render_puya"]
