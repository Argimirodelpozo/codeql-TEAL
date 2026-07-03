"""CFG package — re-exports the contents of :mod:`tealql.tealtools.cfg.cfg` so
external imports (``from tealql.tealtools.cfg import CFG``) keep working
unchanged after the file was moved inside a folder.

The per-program :class:`CFG` and :func:`dominance.iterative_dominators` are
pure substrate (they import only ``ssa`` + ``_utils``). :class:`SuperCFG`
and :mod:`super_auth` are cross-contract ANALYSES — they import
:mod:`tealql.tealtools.xcontract` (top of the stack). They live in this folder for
historical reasons, but they are re-exported LAZILY (PEP 562 ``__getattr__``)
so that ``import tealql.tealtools.cfg`` / ``from tealql.tealtools.cfg import CFG`` does NOT
drag the whole cross-contract analysis layer (xcontract → auth_domination,
inner_txn_report) into the substrate. ``from tealql.tealtools.cfg import SuperCFG``
still works — it just triggers the analysis import at that point, not at
substrate load."""
from .cfg import *  # noqa: F401,F403

_SUPERCFG_EXPORTS = {"SuperCFG", "SuperBlock", "SuperEdge"}


def __getattr__(name: str):
    if name in _SUPERCFG_EXPORTS:
        from . import supercfg
        return getattr(supercfg, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
