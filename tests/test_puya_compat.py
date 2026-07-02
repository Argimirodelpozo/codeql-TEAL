"""CI canary for the fragile puya-internal surface the lift depends on.

``tealtools.lift._puya_compat`` concentrates every private puya name + shape
assumption the lift uses (see its docstring). This probes each one so a puya
version bump breaks HERE with a clear message, instead of surfacing as an opaque
lift failure deep in a scan.

Puya-gated: without puya there is nothing to probe.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealtools.lift import _puya_compat as compat


def test_check_compat_resolves_every_fragile_name():
    found = compat.check_compat()
    # Each fragile name the lift touches must have resolved.
    for name in ("_get_used_registers", "_get_assigned_registers",
                 "_split_parallel_copies", "TextEmitter", "_render_body",
                 "DynamicVariants", "Variant", "AVMOp._variants",
                 "Register", "Intrinsic"):
        assert name in found, f"puya compat lost: {name}"


def test_frozen_attr_setters_actually_write():
    # set_ir_type / set_intrinsic_types must still mutate the frozen model
    # (a puya switch away from attrs-frozen, or a field rename, would break the
    # lift's type recovery silently — this makes it loud).
    import puya.ir.models as M
    from puya.ir.types_ import PrimitiveIRType as PT
    reg = M.Register(name="t", version=0, ir_type=PT.uint64, source_location=None)
    compat.set_ir_type(reg, PT.bytes)
    assert reg.ir_type is PT.bytes


def test_error_message_matchers_present():
    assert compat.UNDEFINED_REGISTER_RE.search("Undefined register: x#3")
    assert compat.NOT_DEFINED_RE.search("not defined: y#1")
    assert compat.ASSIGNED_MULTIPLE == "assigned multiple times"


def test_langspec_variants_shapes():
    from puya.ir.avm_ops import AVMOp
    from puya.ir.avm_ops_models import DynamicVariants, Variant
    # A static-signature op and a field-keyed dynamic op.
    assert isinstance(compat.langspec_variants(AVMOp.itob), (Variant, DynamicVariants))
    assert isinstance(compat.langspec_variants(AVMOp.txn), (Variant, DynamicVariants))
