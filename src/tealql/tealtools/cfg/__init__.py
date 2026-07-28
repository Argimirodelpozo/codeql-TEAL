"""CFG package — re-exports :mod:`tealql.tealtools.cfg.cfg` so
``from tealql.tealtools.cfg import CFG`` keeps working.

HAZARD: :class:`CFG` and :mod:`dominance` are pure substrate (``ssa`` +
``_utils`` only), while :class:`SuperCFG` / :mod:`super_auth` are cross-contract
ANALYSES importing :mod:`tealql.tealtools.xcontract` (top of the stack). Those are
re-exported LAZILY (PEP 562 ``__getattr__``) so importing the substrate does not
drag the analysis layer in; keep any new eager re-export substrate-only."""
from .cfg import *  # noqa: F401,F403

_SUPERCFG_EXPORTS = {"SuperCFG", "SuperBlock", "SuperEdge"}


def __getattr__(name: str):
    if name in _SUPERCFG_EXPORTS:
        from . import supercfg
        return getattr(supercfg, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
