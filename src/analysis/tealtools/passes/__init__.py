"""SSA functional-pass package.

Houses every optional analysis / cleanup pass that layers on top of
the :mod:`tealtools.ssa` substrate. Two kinds of code live here:

  - **Per-pass helpers** (one module per pass): the actual
    semantics of constant folding, input unification, range
    propagation, byte_length inference, bytemath, dead-code
    cleanup. The substrate exposes a thin lazy-import bridge
    method (e.g. :meth:`SSAProgram.propagate_byte_lengths`) that
    delegates here.

  - **Orchestration** (:mod:`tealtools.passes.orchestrate`): a
    canonical-order ``run_all_passes`` driver plus
    ``functional_dump``, the one-stop renderer that runs every
    pass and produces the most-annotated flat dump.

Importing this package gives you the orchestration entry points
directly. The per-pass modules are best invoked via the
``SSAProgram.propagate_*`` / ``SSAProgram.cleanup_*`` methods on
the substrate; calling them as plain functions is supported but
mostly useful when writing a new pass that consumes another's
output (or when wiring a custom pipeline).
"""
from .orchestrate import functional_dump, run_all_passes

__all__ = ["functional_dump", "run_all_passes"]
