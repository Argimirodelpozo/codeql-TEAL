"""Unit tests for the per-op byte-length kernel of ``byte_length_prop`` — the
table that derives an output's byte length from one TEAL op plus its operands
(``itob``→8, ``concat``→sum of input lengths, ``sha256``→32, ``extract`` /
``substring`` slices, length-preserving ``setbyte``/``replace``, …).

``_op_byte_length`` is the semantic core the forward byte-length fixpoint drives;
it reads only ``a.const`` / ``a.op`` / ``a.immediates`` / ``a.inputs`` and
duck-types operands (``getattr(operand, "type"/"const_value", …)``), so it runs
as plain unit tests over hand-built ``Assignment``s with real ``Const`` /
``TealType`` operands — no SSA fixpoint, DB, or puya.
"""
from tealtools.passes.byte_length_prop import _hex_byte_length, _op_byte_length
from tealtools.ssa import Assignment, Const, Location, SSAVar, TealType


def _asn(op, *, imm="", inputs=(), const=None):
    return Assignment(outputs=[], op=op, immediates=imm, inputs=list(inputs),
                      location=Location("t.teal", 1), ast_code="", const=const)


def _bytes_operand(byte_length):
    """An operand carrying a known bytes TealType (a prior-pass / prior-iteration
    result); ``None`` length models 'bytes-typed but length not yet known'."""
    v = SSAVar("t.teal", 10, 0)
    v.type = TealType("bytes", byte_length=byte_length)
    return v


def _int(value):
    return Const("int", str(value))


def _bytes(hexlit):
    return Const("bytes", hexlit)


# -- _hex_byte_length: the lru_cache'd literal-length helper added this session --


def test_hex_byte_length():
    assert _hex_byte_length("0x1234") == 2
    assert _hex_byte_length("0X1234") == 2        # upper-case prefix
    assert _hex_byte_length("abcd") == 2          # no prefix
    assert _hex_byte_length("0x") == 0            # empty
    assert _hex_byte_length("0x123") is None      # odd nibble count
    assert _hex_byte_length("0xzz") is None       # not hex


# -- fixed-width ops --


def test_itob_is_8():
    assert _op_byte_length(_asn("itob", inputs=[_int(42)])) == 8


def test_hash_digests_are_32():
    for op in ("sha256", "sha512_256", "keccak256", "sha3_256"):
        assert _op_byte_length(_asn(op, inputs=[_bytes_operand(99)])) == 32


def test_const_bytes_literal_length():
    assert _op_byte_length(_asn("bytec_0", const=_bytes("0xdeadbeef"))) == 4


# -- bzero --


def test_bzero_const_count():
    assert _op_byte_length(_asn("bzero", inputs=[_int(16)])) == 16


def test_bzero_non_const_or_negative_is_none():
    assert _op_byte_length(_asn("bzero", inputs=[_bytes_operand(4)])) is None
    assert _op_byte_length(_asn("bzero", inputs=[_int(-1)])) is None


# -- concat --


def test_concat_sums_known_lengths():
    assert _op_byte_length(_asn("concat", inputs=[_bytes_operand(3), _bytes_operand(5)])) == 8


def test_concat_unknown_input_is_none():
    assert _op_byte_length(_asn("concat", inputs=[_bytes_operand(3), _bytes_operand(None)])) is None


# -- extract / substring (immediate forms) --


def test_extract_fixed_length():
    assert _op_byte_length(_asn("extract", imm="2 5")) == 5


def test_extract_to_end_uses_input_length():
    # `extract 2 0` = bytes[2:], length = len(input) - 2
    assert _op_byte_length(_asn("extract", imm="2 0", inputs=[_bytes_operand(10)])) == 8


def test_extract_to_end_past_input_is_none():
    assert _op_byte_length(_asn("extract", imm="20 0", inputs=[_bytes_operand(10)])) is None


def test_substring_length():
    assert _op_byte_length(_asn("substring", imm="2 7")) == 5
    assert _op_byte_length(_asn("substring", imm="7 2")) is None     # end < start


# -- extract3 / substring3 (stack forms) --


def test_extract3_const_count():
    # (X, A, B) -> bytes[A:A+B], length B
    assert _op_byte_length(_asn("extract3", inputs=[_bytes_operand(10), _int(2), _int(4)])) == 4


def test_substring3_const_endpoints():
    assert _op_byte_length(_asn("substring3", inputs=[_bytes_operand(10), _int(2), _int(7)])) == 5


def test_substring3_non_const_is_none():
    asn = _asn("substring3", inputs=[_bytes_operand(10), _bytes_operand(1), _int(7)])
    assert _op_byte_length(asn) is None


# -- length-preserving ops inherit input[0]'s length --


def test_length_preserving_inherits_input0():
    for op in ("setbyte", "replace2", "replace3"):
        asn = _asn(op, inputs=[_bytes_operand(12), _int(0), _int(255)])
        assert _op_byte_length(asn) == 12


def test_length_preserving_unknown_input_is_none():
    assert _op_byte_length(_asn("setbyte", inputs=[_bytes_operand(None), _int(0), _int(1)])) is None


# -- anything else --


def test_unknown_op_is_none():
    assert _op_byte_length(_asn("addw", inputs=[_int(1), _int(2)])) is None
