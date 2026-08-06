"""CFG package — everything that derives or reads control flow, in TIERS.

Lowest first; each tier is importable without dragging the ones above it in,
which is why nothing here is re-exported eagerly:

* :mod:`.build`     — the extractor floor: AST nodes -> CFG edges + basic
                      blocks. Runs BEFORE any SSA exists and imports nothing
                      from ``tealtools``; ``ast.parse`` and ``graph`` consume it.
* :mod:`.dominance` — pure graph algorithms (no ``tealtools`` imports at all).
* :mod:`.cfg`, :mod:`.exits` — views over an already-built ``SSAProgram``.
* :mod:`.supercfg`, :mod:`.super_auth` — cross-contract ANALYSES, which import
                      :mod:`tealql.tealtools.xcontract` (the top of the stack).

HAZARD: :mod:`.build` sits BELOW ``ssa`` and :mod:`.cfg` sits ABOVE it, in one
package — they share a SUBJECT, not a layer. An eager re-export here would make
importing the floor (i.e. importing the PARSER) pull the whole SSA and analysis
stack, and a later ``ssa -> graph -> parse`` edge would then close a cycle
through a half-initialised package. Keep every re-export lazy (PEP 562);
``tests/test_layering.py`` pins that, and ``build``'s leaf status.
"""
from importlib import import_module

#: Public name -> the submodule defining it. Imported on first attribute
#: access, never at package import.
_LAZY_EXPORTS = {
    "CFG": "cfg",
    "SuperCFG": "supercfg",
    "SuperBlock": "supercfg",
    "SuperEdge": "supercfg",
}


def __getattr__(name: str):
    mod = _LAZY_EXPORTS.get(name)
    if mod is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(import_module(f".{mod}", __name__), name)


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
