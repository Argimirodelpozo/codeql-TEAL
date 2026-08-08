"""Compatibility facade for the canonical frame-slot model.

Frame semantics live in :mod:`tealql.tealtools.ssa.frame_slots` beside the
stack interpreter that produces their values. These names remain importable for
downstream users of the former pass module.
"""
from __future__ import annotations

from ..ssa.frame_slots import (
    FrameLayout,
    _declared_nargs,
    resolve_layout,
    resolve_program,
)
from ..ssa.operands import imm0 as _imm0  # noqa: F401 - compatibility export

# Established public names. Keep forwarding aliases rather than duplicating
# the implementation or forcing consumers to migrate in lockstep.
SubFrames = FrameLayout
resolve_sub = resolve_layout
resolve = resolve_program
_proto_nargs = _declared_nargs

__all__ = ["FrameLayout", "SubFrames", "resolve", "resolve_layout", "resolve_sub"]
