"""Optional SSA analysis / cleanup passes, one module per pass, reached through
the lazy-import bridge methods on :class:`SSAProgram` or :func:`run_all_passes`."""
from .orchestrate import functional_dump, run_all_passes

__all__ = ["functional_dump", "run_all_passes"]
