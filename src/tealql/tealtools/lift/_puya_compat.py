"""Single audit point for the places the lift reaches OUTSIDE puya's API.

This is not a claim that puya's IR API is unstable — it is not. ``Register`` /
``Intrinsic`` / ``Subroutine``, ``AVMOp.code`` / ``get_variant`` /
``immediate_types`` / ``cost`` are public and steady, and the lift imports them
DIRECTLY at use sites; none of that belongs here.

What is collected here is the surface no API promise covers, in three kinds:

* **Private module functions** — ``_get_used_registers``,
  ``_get_assigned_registers``, ``_split_parallel_copies``, ``_render_body``.
  Public equivalents do not exist: ``to_text_visitor.render_program`` needs an
  ``ArtifactCompileContext`` and WRITES output rather than returning a body.
* **Frozen-model mutation** — ``object.__setattr__`` deliberately bypasses
  attrs' frozen contract, and one write targets ``_types``, the backing field
  behind a read-only property.
* **Error MESSAGE TEXT** — the backend's orphan-define retry matches on the
  wording of an ``InternalError``. No project promises its error strings,
  however stable its API; this is the least defensible dependency here and the
  first worth removing if puya ever grows a typed error for it.

Keeping them in ONE file makes a puya bump a one-file audit, and
:func:`check_compat` probes every one so a break fails loudly in CI instead of
surfacing as a mysterious lift error.
"""
from __future__ import annotations

import re

# --- error-message matchers (puya raises InternalError with these) ----------
# The backend's orphan-define retry keys on the register name in the message.
UNDEFINED_REGISTER_RE = re.compile(r"[Uu]ndefined register: ([^#\s]+)#(\d+)")
# The optimiser's rejected-register retry (a slightly different wording).
NOT_DEFINED_RE = re.compile(r"not defined: ([^#\s]+)#(\d+)")
# Sentinel that means "genuinely double-assigned", NOT a reconstruction orphan.
ASSIGNED_MULTIPLE = "assigned multiple times"


# --- private-function re-exports (imported lazily so this module still loads for
#     `check_compat` to REPORT a break rather than failing at import) -----------

def get_used_registers(body):
    from puya.ir.models import _get_used_registers
    return _get_used_registers(body)


def get_assigned_registers(body):
    from puya.ir.models import _get_assigned_registers
    return _get_assigned_registers(body)


def split_parallel_copies(ctx, sub):
    from puya.ir.optimize.main import _split_parallel_copies
    return _split_parallel_copies(ctx, sub)


def langspec_variants(op):
    """The ``_variants`` of an ``AVMOp``: a ``Variant``, a field-keyed
    ``DynamicVariants``, or ``None``.

    TESTS ONLY — they ENUMERATE every variant to diff our tables against the
    langspec, which the public API cannot do (``get_variant`` resolves ONE
    variant from a given immediate). Production code wants exactly that
    resolution and uses the public accessor instead."""
    return getattr(op, "_variants", None)


def text_emitter_and_render():
    """``(TextEmitter, _render_body)`` from puya's text visitor, for the human-readable IR dump."""
    from puya.ir.to_text_visitor import TextEmitter, _render_body
    return TextEmitter, _render_body


# --- frozen-attrs model mutation --------------------------------------------

def set_ir_type(register, ir_type) -> None:
    """Set a puya ``Register``'s frozen ``ir_type`` field."""
    object.__setattr__(register, "ir_type", ir_type)


def set_intrinsic_types(intrinsic, types_tuple) -> None:
    """Sync an ``Intrinsic``'s result types.

    HAZARD: the write must target the attrs backing field ``_types`` — the public
    ``types`` is a read-only property and writing it silently no-ops."""
    object.__setattr__(intrinsic, "_types", tuple(types_tuple))


# --- canary -----------------------------------------------------------------

def check_compat() -> dict:
    """Resolve every fragile puya name the lift depends on, raising on the first that is gone."""
    found: dict = {}
    from puya.ir.models import _get_used_registers, _get_assigned_registers
    found["_get_used_registers"] = _get_used_registers
    found["_get_assigned_registers"] = _get_assigned_registers
    from puya.ir.optimize.main import _split_parallel_copies
    found["_split_parallel_copies"] = _split_parallel_copies
    from puya.ir.to_text_visitor import TextEmitter, _render_body
    found["TextEmitter"] = TextEmitter
    found["_render_body"] = _render_body
    from puya.ir.avm_ops import AVMOp
    from puya.ir.avm_ops_models import DynamicVariants, Variant
    found["DynamicVariants"] = DynamicVariants
    found["Variant"] = Variant
    v = langspec_variants(AVMOp.itob)
    assert isinstance(v, (DynamicVariants, Variant)), f"AVMOp._variants shape changed: {v!r}"
    found["AVMOp._variants"] = type(v).__name__
    # Frozen-attrs write path: the fields object.__setattr__ targets must still exist.
    import puya.ir.models as M
    assert hasattr(M, "Register") and hasattr(M, "Intrinsic")
    found["Register"] = M.Register
    found["Intrinsic"] = M.Intrinsic
    return found
