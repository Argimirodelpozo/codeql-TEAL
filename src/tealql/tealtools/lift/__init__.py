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


def build_lifter(prog):
    """Build + cache the pre-IR ``_Lifter`` for ``prog``, or ``None`` if it does not lift.

    Lifts ``prog`` ITSELF — the lift restores its input CFG on exit (the dead-edge
    prune is save/restored), so no fresh re-parse is needed and in-memory programs
    without a ``source_path`` lift too. Shares the ``_ir_lifter`` cache with
    ``security.common.ir_lifter``. A ``LiftError`` (an expected coverage gap)
    degrades QUIETLY by design on this query-side path — when ``ir_lifter`` may
    also run, pre-warm through IT so its reduced-precision warnings are seen; an
    UNEXPECTED crash warns either way, since that points at a bug."""
    sentinel = object()
    cached = getattr(prog, "_ir_lifter", sentinel)
    if cached is not sentinel:
        return cached
    lifter = None
    try:
        from .lift import _Lifter
        prog.propagate_constants()
        lf = _Lifter(prog)
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
        prog._ir_lifter = lifter
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
