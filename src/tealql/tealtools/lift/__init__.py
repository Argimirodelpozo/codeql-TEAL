"""Lift a :class:`tealql.tealtools.ssa.SSAProgram` into genuine ``puya.ir.models``.

Map: :mod:`lift` builds the pre-IR (:mod:`pre_ir`), :mod:`to_puya_ir` lowers it to
real Puya IR, :mod:`backend` carries that down to TEAL again; literals in
:mod:`teal_const`, AVM metadata in :mod:`tealql.tealtools.avm`.

HAZARD: ``render`` / ``to_puya`` are exported LAZILY (PEP 562) because
:mod:`to_puya_ir` is the only module on this path that imports ``puya``. The
detector-facing side — ``lift`` / ``_Lifter`` and the pre-IR taint layer — must stay
puya-free, so never import them eagerly here.
"""
import logging

from . import pre_ir
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
    files = getattr(prog, "source_files", ())
    projected = len(files) > 1 and file is not None
    cache_name = "_ir_lifters_by_file" if projected else "_ir_lifter"
    sentinel = object()
    if projected:
        cache = getattr(prog, cache_name, None)
        if cache is None:
            cache = {}
            try:
                setattr(prog, cache_name, cache)
            except Exception:
                pass
        cached = cache.get(file, sentinel)
    else:
        cache = None
        cached = getattr(prog, cache_name, sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    try:
        from .lift import _Lifter
        target = prog.for_file(file, strict=False) if projected else prog
        target.propagate_constants()
        lf = _Lifter(target)
        lf.build()
        lifter = lf
    except Exception as e:
        try:
            from ..errors import LiftError
        except ImportError:
            LiftError = ()
        if not isinstance(e, LiftError):
            logger.warning(
                "pre-IR lift crashed UNEXPECTEDLY (%s: %s) — degrading to the "
                "SSA layer; this is likely a bug", type(e).__name__, e)
        lifter = None                # lift failure -> coarse fallback
    try:
        if cache is not None:
            cache[file] = lifter
        else:
            setattr(prog, cache_name, lifter)
    except Exception:
        pass
    return lifter


def __getattr__(name: str):
    # Deferred so the package imports without puya installed.
    if name in ("render", "to_puya"):
        from . import to_puya_ir
        return getattr(to_puya_ir, name)
    if name == "lift_to_teal":
        from . import backend
        return backend.lift_to_teal
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
