"""Unit tests for the per-op range kernel of ``bytemath`` — the interval
arithmetic that bounds a bytemath op's result (``b+``/``b-``/``b*``/``b/``/
``b%``/``b&``/``b|``/``b^``) from its operands' big-endian-integer ranges.

``_bytemath_result`` is a pure function of ``(op, IntRange, IntRange)`` and
``_operand_bigint_range`` duck-types its operand, so both run as plain unit
tests with real ``IntRange`` / ``Const`` / ``TealType`` — no SSA fixpoint, fixture,
or puya. Ranges are arbitrary-precision (no uint64 cap): a long ``b*`` chain can
legitimately exceed 2**64.
"""
from tealtools.passes.bytemath import (
    _bytemath_result,
    _bytes_to_int,
    _operand_bigint_range,
    propagate_bytemath_ranges,
)
from tealtools.ssa import Const, IntRange, Phi, SSAVar, TealType
from ssa_builders import mk_asn as _asn, mk_var as _var, mk_prog


def _R(lo, hi):
    return IntRange(lo, hi)


def _prog(assignments, phis=()):
    # bytemath also needs ranges-already-done so the pass skips range seeding.
    return mk_prog(assignments, phis, _ranges_propagated=True)


# -- _bytes_to_int: the lru_cache'd literal-value helper added this session --


def test_bytes_to_int():
    assert _bytes_to_int("0x0102") == 0x0102        # 258, big-endian
    assert _bytes_to_int("0xff") == 255
    assert _bytes_to_int("0x") == 0                 # empty bytes -> 0
    assert _bytes_to_int("ff") == 255               # no prefix
    assert _bytes_to_int("0x123") is None           # odd nibble count
    assert _bytes_to_int("0xzz") is None            # not hex


# -- _bytemath_result: interval arithmetic per op --


def test_b_add():
    assert _bytemath_result("b+", _R(1, 3), _R(10, 20)) == (11, 23)


def test_b_sub():
    assert _bytemath_result("b-", _R(10, 20), _R(1, 3)) == (7, 19)


def test_b_sub_underflow_clamps_low_and_rejects_empty():
    # lo floors at 0 (TEAL bytes are unsigned); when the high end also goes
    # negative the range is empty -> None.
    assert _bytemath_result("b-", _R(1, 8), _R(3, 5)) == (0, 5)
    assert _bytemath_result("b-", _R(1, 2), _R(5, 10)) is None


def test_b_mul():
    assert _bytemath_result("b*", _R(2, 3), _R(4, 5)) == (8, 15)


def test_b_div():
    assert _bytemath_result("b/", _R(10, 20), _R(2, 5)) == (2, 10)


def test_b_div_by_certain_zero_is_none():
    assert _bytemath_result("b/", _R(10, 20), _R(0, 0)) is None


def test_b_div_divisor_range_includes_zero():
    # divisor possibly-but-not-certainly zero: max(rb.lo, 1) guards the //.
    assert _bytemath_result("b/", _R(10, 20), _R(0, 5)) == (2, 20)


def test_b_mod():
    assert _bytemath_result("b%", _R(5, 17), _R(1, 4)) == (0, 3)


def test_b_mod_by_certain_zero_is_none():
    assert _bytemath_result("b%", _R(5, 17), _R(0, 0)) is None


def test_b_and_bounds_by_smaller_operand():
    assert _bytemath_result("b&", _R(5, 12), _R(0, 7)) == (0, 7)


def test_b_or_sets_bits_up_to_wider_operand():
    # max bit-length is 3 (from 5=0b101) -> ceiling (1<<3)-1 = 7; floor max(lo).
    assert _bytemath_result("b|", _R(4, 5), _R(1, 2)) == (4, 7)


def test_b_xor_floor_zero():
    # a ^ a == 0 so the floor is 0; ceiling as for b|.
    assert _bytemath_result("b^", _R(4, 5), _R(1, 2)) == (0, 7)


def test_unknown_op_is_none():
    assert _bytemath_result("b~", _R(1, 2), _R(3, 4)) is None


def test_ranges_are_arbitrary_precision():
    # no uint64 cap: a product can exceed 2**64.
    big = (1 << 70)
    assert _bytemath_result("b*", _R(big, big), _R(2, 2)) == (2 * big, 2 * big)


# -- _operand_bigint_range: where an operand's range comes from --


def test_operand_range_from_type_int_value_range():
    v = SSAVar("t.teal", 1, 0)
    v.type = TealType("bytes", int_value_range=_R(5, 9))
    assert _operand_bigint_range(v) == _R(5, 9)


def test_operand_range_from_bytes_const_literal():
    assert _operand_bigint_range(Const("bytes", "0x0102")) == _R(258, 258)


def test_operand_range_from_const_value():
    v = SSAVar("t.teal", 1, 0)
    v.const_value = Const("bytes", "0xff")
    assert _operand_bigint_range(v) == _R(255, 255)


def test_operand_range_unknown_is_none():
    assert _operand_bigint_range(SSAVar("t.teal", 1, 0)) is None


# -- propagate_bytemath_ranges: the worklist end-to-end on tiny SSA graphs --


def test_propagate_forward_chain_through_fan_out():
    # two bytes consts (10, 3) feed b+ -> 13. Seeded in REVERSE (the b+ before its
    # operand producers) so the result depends on the consts' changes fanning out
    # along .uses, exercising the worklist re-trigger rather than seed order.
    v1, v2, v3 = _var(10, 0), _var(11, 1), _var(12, 2)
    a1 = _asn("bytec_0", outputs=[v1], const=Const("bytes", "0x0a"))   # 10
    a2 = _asn("bytec_1", outputs=[v2], const=Const("bytes", "0x03"))   # 3
    a3 = _asn("b+", inputs=[v1, v2], outputs=[v3])
    v1.uses.append(a3)
    v2.uses.append(a3)
    propagate_bytemath_ranges(_prog([a3, a1, a2]))
    assert v1.type.int_value_range == _R(10, 10)
    assert v3.type.int_value_range == _R(13, 13)


def test_propagate_itob_seeds_bigint_range_from_const_int():
    # itob (uint64 -> bytes) carries the integer value across into bytes-land.
    v = _var(10, 0)
    propagate_bytemath_ranges(_prog([_asn("itob", inputs=[Const("int", "7")], outputs=[v])]))
    assert v.type.int_value_range == _R(7, 7)


def test_propagate_btoi_bridges_to_uint64_range():
    # btoi (bytes -> uint64) lifts the bigint range back into the SSAVar.range
    # uint64 lattice (not int_value_range).
    v_bytes, v_int = _var(10, 0), _var(11, 1)
    a1 = _asn("bytec_0", outputs=[v_bytes], const=Const("bytes", "0x03"))
    a2 = _asn("btoi", inputs=[v_bytes], outputs=[v_int])
    v_bytes.uses.append(a2)
    propagate_bytemath_ranges(_prog([a2, a1]))
    assert v_int.range == _R(3, 3)


def test_propagate_phi_unions_bigint_ranges():
    v1, v2 = _var(10, 0), _var(11, 1)
    a1 = _asn("bytec_0", outputs=[v1], const=Const("bytes", "0x05"))   # 5
    a2 = _asn("bytec_1", outputs=[v2], const=Const("bytes", "0x0a"))   # 10
    ph = Phi("t.teal", 12, 0, "DirectPhi")
    ph.args = [v1, v2]
    propagate_bytemath_ranges(_prog([a1, a2], phis=[ph]))
    assert ph.type.int_value_range == _R(5, 10)
