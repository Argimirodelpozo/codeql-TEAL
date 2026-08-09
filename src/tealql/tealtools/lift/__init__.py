"""Lift a :class:`tealql.tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

Map: :mod:`lift` builds the pre-IR (:mod:`pre_ir`), :mod:`to_puya_ir` lowers it to
real Puya IR, :mod:`backend` carries that down to TEAL again; literals in
:mod:`teal_const`, AVM metadata in :mod:`tealql.tealtools.language.avm`.

HAZARD: ``render`` / ``to_puya`` are exported LAZILY (PEP 562) because
:mod:`to_puya_ir` is the only module on this path that imports ``puya``. The
detector-facing side — ``lift`` / ``_Lifter`` and the pre-IR taint layer — must stay
puya-free, so never import them eagerly here.
"""
from importlib import import_module
import logging

# ``lift`` is both a public function and a real child-module name. Python sets
# ``package.lift`` to that module whenever it is imported, which bypasses PEP
# 562 and turns ``from ...lift import lift`` into a module nondeterministically.
# Bind the function once here, after child-module loading, to keep the long-held
# callable API stable. The expensive Puya backend remains fully deferred.
from .lift import lift

__all__ = ["render", "to_puya", "lift", "lift_to_teal", "pre_ir", "build_lifter"]

logger = logging.getLogger("tealql.tealtools.lift")


def build_lifter(prog, file=None):
    """Build + cache the pre-IR ``_Lifter`` for ``prog``, or ``None`` if it does not lift.

    A directory-backed SSA collection is independently projected to ``file``;
    otherwise this lifts ``prog`` itself. The lift restores its input CFG on
    exit (the dead-edge prune is save/restored), so no fresh re-parse is needed
    and in-memory programs lift too. A ``LiftError`` degrades quietly on this
    query-side path; an unexpected crash warns because it points at a bug."""
    from .cache import LifterRequest

    request = LifterRequest(prog, file)
    hit, cached = request.lookup()
    if hit:
        return cached
    lifter = None
    try:
        from .lift import _Lifter
        target = request.target()
        target.propagate_constants()
        lf = _Lifter(target)
        lf.build()
        lifter = lf
    except Exception as e:
        try:
            from ..diagnostics.errors import LiftError
        except ImportError:
            LiftError = ()
        if not isinstance(e, LiftError):
            logger.warning(
                "pre-IR lift crashed UNEXPECTEDLY (%s: %s) — degrading to the "
                "SSA layer; this is likely a bug", type(e).__name__, e)
        lifter = None                # lift failure -> coarse fallback
    request.store(lifter)
    return lifter


_LAZY_EXPORTS = {
    "pre_ir": (".pre_ir", None),
    # Deferred so the package imports without puya installed.
    "render": (".to_puya_ir", "render"),
    "to_puya": (".to_puya_ir", "to_puya"),
    "lift_to_teal": (".backend", "lift_to_teal"),
}


def __getattr__(name: str):
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = target
    module = import_module(module_name, __name__)
    value = module if attr is None else getattr(module, attr)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
