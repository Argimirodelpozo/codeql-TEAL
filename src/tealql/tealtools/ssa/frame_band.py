"""Backward-compatible import path for bottom-anchored frame analysis.

The implementation moved to :mod:`.frame_slots`, which now owns both stack
simulation instructions and public SSA frame provenance.  Keep ``build_plan``
here because downstream users may have imported the former internal module.
"""
from __future__ import annotations

from .frame_slots import build_plan

__all__ = ["build_plan"]
