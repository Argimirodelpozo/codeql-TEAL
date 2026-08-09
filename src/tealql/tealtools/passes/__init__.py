"""Deprecated import bridge for the former mutating pass pipeline.

Analysis now lives in :mod:`tealql.tealtools.analysis` and returns immutable,
query-scoped views.  This package remains only so shipped notebooks and known
downstream consumers fail loudly and migratably instead of at import time.
"""
from __future__ import annotations

import warnings

from ..analysis import DerivedProfile, derived_program, functional_dump


def run_all_passes(prog):
    """Deprecated: return a read-only presentation view of ``prog``."""
    warnings.warn(
        "tealtools.passes.run_all_passes() no longer mutates its argument; "
        "use analysis.derived_program(..., DerivedProfile.PRESENTATION)",
        DeprecationWarning,
        stacklevel=2,
    )
    return derived_program(prog, DerivedProfile.PRESENTATION)


__all__ = ["functional_dump", "run_all_passes"]
