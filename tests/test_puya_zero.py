"""Unit tests for ``to_puya_ir._puya_zero`` — the typed-zero builder used to
define orphan registers (values the reconstruction lost to a frame / dynamic-
scratch gap) at their subroutine entry.

The load-bearing case is an ARC4 ``EncodedType`` target (e.g. a tuple of three
uint64s = 24 bytes): a uint64 zero is the WRONG AVM type for it, so Puya's
``Assignment`` type-check rejects ``source=(uint64) target=(Encoded(...))`` and
the whole contract fails to lift. ``_puya_zero`` must emit a bytes zero of the
type's fixed width, typed AS the target, so the orphan-default assignment
type-checks exactly. Regression for the v11 mainnet liftfail surfaced by the
mainnet sweep (app_3000631550 and ~dozens of sibling deployments).
"""
import pytest

pytest.importorskip("puya")

import puya.ir.models as M  # noqa: E402
from puya.avm import AVMType  # noqa: E402
from puya.ir.encodings import TupleEncoding, UIntEncoding  # noqa: E402
from puya.ir.types_ import EncodedType, PrimitiveIRType as PT  # noqa: E402

from tealtools.lift.to_puya_ir import _puya_zero  # noqa: E402


def _encoded_uint64_tuple(n: int) -> EncodedType:
    return EncodedType(encoding=TupleEncoding(elements=(UIntEncoding(n=64),) * n,
                                              names=None))


def test_encoded_tuple_zero_is_typed_bytes_of_fixed_width():
    enc = _encoded_uint64_tuple(3)            # 3 * 8 = 24 bytes
    z = _puya_zero(enc)
    assert isinstance(z, M.BytesConstant)
    # typed AS the target so an Assignment(target: enc) type-checks exactly
    assert z.ir_type == enc
    assert z.ir_type.avm_type == AVMType.bytes
    assert len(z.value) == enc.num_bytes == 24


def test_encoded_zero_assignment_typechecks():
    # the actual failure mode was Puya's Assignment validator rejecting a
    # uint64 source against an Encoded target; building the assignment exercises
    # exactly that validator.
    enc = _encoded_uint64_tuple(3)
    reg = M.Register(source_location=None, name="v%0", version=0, ir_type=enc)
    # must not raise CodeError("incompatible types on assignment: ...")
    M.Assignment(source_location=None, targets=[reg], source=_puya_zero(enc))


def test_uint64_zero_unchanged():
    z = _puya_zero(PT.uint64)
    assert isinstance(z, M.UInt64Constant)
    assert z.value == 0


def test_plain_bytes_zero_unchanged():
    z = _puya_zero(PT.bytes)
    assert isinstance(z, M.BytesConstant)
    assert z.value == b""
