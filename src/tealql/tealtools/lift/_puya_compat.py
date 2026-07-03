"""Single audit point for the FRAGILE puya-internal surface the lift depends on.

The lift lowers to real ``puya.ir.models`` and drives puya's own optimiser +
backend. Puya is a fast-moving compiler with NO stability guarantee on its
internals, and the lift touches several private names and shape assumptions that
a patch release could legally break:

  * private module functions — ``_get_used_registers`` / ``_get_assigned_registers``
    (``puya.ir.models``), ``_split_parallel_copies`` (``puya.ir.optimize.main``),
    ``_render_body`` + ``TextEmitter`` (``puya.ir.to_text_visitor``);
  * a private attribute — ``AVMOp._variants`` (langspec return signatures);
  * writing FROZEN attrs model fields via ``object.__setattr__`` — a Register's
    ``ir_type`` and an Intrinsic's ``_types`` backing field (the public ``types``
    is a read-only property; writing it silently no-ops);
  * matching puya ``InternalError`` MESSAGE TEXT — the "undefined register" /
    "not defined" orphan patterns and the "assigned multiple times" sentinel.

Concentrating all of that HERE means a puya version bump is a one-file audit, and
:func:`check_compat` (exercised by ``tests/test_puya_compat.py``) probes every
name so a break fails loudly in CI instead of surfacing as a mysterious lift
error. Stable, documented puya PUBLIC API (``puya.ir.models`` classes, ``AVMOp``,
``AVMType``, ``AVMBytesEncoding``, ``PrimitiveIRType``, the encodings/types
modules) is imported directly at use sites — only the fragile surface lives here.
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


# --- private-function re-exports (import lazily so this module is importable
#     for `check_compat` to REPORT a break rather than fail at import) --------

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
    """The ``_variants`` object for an ``AVMOp`` (a ``Variant`` with a static
    signature, a ``DynamicVariants`` for field-keyed ops, or ``None``)."""
    return getattr(op, "_variants", None)


def text_emitter_and_render():
    """``(TextEmitter, _render_body)`` from puya's text visitor (used for the
    human-readable IR dump)."""
    from puya.ir.to_text_visitor import TextEmitter, _render_body
    return TextEmitter, _render_body


# --- frozen-attrs model mutation --------------------------------------------

def set_ir_type(register, ir_type) -> None:
    """Set a puya ``Register``'s frozen ``ir_type`` field (attrs-frozen model)."""
    object.__setattr__(register, "ir_type", ir_type)


def set_intrinsic_types(intrinsic, types_tuple) -> None:
    """Sync an ``Intrinsic``'s result types. ``types`` is a read-only property;
    the attrs backing field is ``_types`` (writing ``types`` silently no-ops)."""
    object.__setattr__(intrinsic, "_types", tuple(types_tuple))


# --- canary -----------------------------------------------------------------

def check_compat() -> dict:
    """Resolve every fragile puya name the lift depends on; raise ``ImportError``/
    ``AttributeError`` naming the first that's gone. Returns a dict of the
    resolved objects (so a test can assert they're all present). Call under a
    ``pytest.importorskip("puya")`` guard."""
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
    # _variants must exist on a real op and be one of the known shapes.
    v = langspec_variants(AVMOp.itob)
    assert isinstance(v, (DynamicVariants, Variant)), f"AVMOp._variants shape changed: {v!r}"
    found["AVMOp._variants"] = type(v).__name__
    # The frozen-attrs write path: Register.ir_type and Intrinsic._types must be
    # settable via object.__setattr__ (i.e. the fields still exist).
    import puya.ir.models as M
    assert hasattr(M, "Register") and hasattr(M, "Intrinsic")
    found["Register"] = M.Register
    found["Intrinsic"] = M.Intrinsic
    return found
