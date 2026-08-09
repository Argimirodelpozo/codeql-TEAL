"""Deprecated bridge for the former in-place assert-range pass."""
from __future__ import annotations

import warnings

from ..analysis import DerivedProfile, derived_program


def propagate_assert_ranges(prog):
    """Return a guard-refined immutable view without changing ``prog``."""
    warnings.warn(
        "passes.range_assert.propagate_assert_ranges() no longer mutates its "
        "argument; consume the returned guarded view",
        DeprecationWarning,
        stacklevel=2,
    )
    return derived_program(prog, DerivedProfile.GUARDED)


__all__ = ["propagate_assert_ranges"]
