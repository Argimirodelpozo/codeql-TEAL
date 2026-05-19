"""Fresh-start experimental sandbox — second iteration.

Built on the existing :mod:`tealtools.ssa` substrate. The pipeline
and one-stop functional-dump entry points used to live here; they
now live in :mod:`tealtools.passes` next to the per-pass helper
modules. This package keeps the structured printer and re-exports
the pipeline entry points so existing callers / notebooks keep
working.
"""

from ..passes import functional_dump, run_all_passes
from .printer import structured_dump

__all__ = ["functional_dump", "run_all_passes", "structured_dump"]
