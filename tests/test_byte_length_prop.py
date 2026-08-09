"""Unit tests for the per-op byte-length kernel of ``byte_length_prop`` — the
table that derives an output's byte length from one TEAL op plus its operands
(``itob``→8, ``concat``→sum of input lengths, ``sha256``→32, ``extract`` /
``substring`` slices, length-preserving ``setbyte``/``replace``, …).

``_op_byte_length`` is the semantic core the forward byte-length fixpoint drives;
it reads only ``a.const`` / ``a.op`` / ``a.immediates`` / ``a.inputs`` and
duck-types operands (``getattr(operand, "type"/"const_value", …)``), so it runs
as plain unit tests over hand-built ``Assignment``s with real ``Const`` /
``TealType`` operands — no SSA fixpoint, fixture, or puya.
"""
from tealql.tealtools.analysis._byte_lengths import (
    _hex_byte_length,
    _input_min_length,
    _op_byte_length,
    propagate_byte_lengths,
)
from tealql.tealtools.ssa import Const, IntRange, Phi, SSAVar, TealType
from ssa_builders import mk_asn as _asn, mk_var as _var, mk_prog as _prog


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
#
# Operands are TOP-FIRST (inputs[0] = topmost popped), so for `extract3 X A B`
# the SSA inputs are [B, A, X] — count/end FIRST, buffer LAST. (The prior tests
# here built inputs source-first, matching an operand-order bug in the pass; both
# are now corrected to real SSA order.)


def test_extract3_const_count():
    # extract3 X A B -> bytes[A:A+B], length B (the count = inputs[0])
    assert _op_byte_length(_asn("extract3", inputs=[_int(4), _int(2), _bytes_operand(10)])) == 4


def test_substring3_const_endpoints():
    # substring3 X A B -> bytes[A:B], length B - A. inputs = [B, A, X]
    assert _op_byte_length(_asn("substring3", inputs=[_int(7), _int(2), _bytes_operand(10)])) == 5


def test_substring3_non_const_is_none():
    # non-const START (inputs[1]) -> unknown length
    asn = _asn("substring3", inputs=[_int(7), _bytes_operand(1), _bytes_operand(10)])
    assert _op_byte_length(asn) is None


# -- length-preserving ops inherit the BUFFER's length (deepest operand) --


def test_length_preserving_inherits_buffer():
    # setbyte X i b -> [b, i, X]; replace2 X V -> [V, X]; replace3 X A V -> [V, A, X].
    # The buffer X is pushed first, so it is the DEEPEST operand = inputs[-1].
    for op in ("setbyte", "setbit", "replace2", "replace3"):
        asn = _asn(op, inputs=[_int(255), _int(0), _bytes_operand(12)])
        assert _op_byte_length(asn) == 12


def test_length_preserving_unknown_buffer_is_none():
    assert _op_byte_length(_asn("setbyte", inputs=[_int(1), _int(0), _bytes_operand(None)])) is None


# -- anything else --


def test_unknown_op_is_none():
    assert _op_byte_length(_asn("addw", inputs=[_int(1), _int(2)])) is None


# -- _input_min_length: inverse constraints (a successful op bounds an input) --
# Return is (buffer_input_index, min_len, max_len). Under top-first the buffer is
# NOT inputs[0]: for `getbyte X i` = [i, X] it is index 1; for the 3-input forms
# [.., .., X] it is index 2.


def test_input_min_length_btoi():
    # btoi(X) succeeds => len(X) in [0, 8]. go-algorand's opBtoi fails only
    # for len > 8 — btoi("") legally yields 0, so 0 is a reachable length.
    assert _input_min_length(_asn("btoi", inputs=[_var()])) == (0, 0, 8)


def test_input_min_length_getbyte_const_index():
    # getbyte X i -> [i, X]; needs len(X) >= i+1, constraint on X = index 1
    assert _input_min_length(_asn("getbyte", inputs=[_int(5), _var()])) == (1, 6, None)


def test_input_min_length_getbyte_non_const_index_is_none():
    assert _input_min_length(_asn("getbyte", inputs=[_bytes_operand(1), _var()])) is None


def test_input_min_length_extract_uint_widths():
    assert _input_min_length(_asn("extract_uint16", inputs=[_int(4), _var()])) == (1, 6, None)
    assert _input_min_length(_asn("extract_uint32", inputs=[_int(4), _var()])) == (1, 8, None)
    assert _input_min_length(_asn("extract_uint64", inputs=[_int(0), _var()])) == (1, 8, None)


def test_input_min_length_extract_and_substring_immediate():
    assert _input_min_length(_asn("extract", imm="2 5", inputs=[_var()])) == (0, 7, None)
    assert _input_min_length(_asn("substring", imm="2 7", inputs=[_var()])) == (0, 7, None)


def test_input_min_length_extract3_substring3_const():
    # inputs = [B, A, X]; constraint on the buffer X = index 2
    assert _input_min_length(_asn("extract3", inputs=[_int(5), _int(2), _var()])) == (2, 7, None)
    assert _input_min_length(_asn("substring3", inputs=[_int(7), _int(2), _var()])) == (2, 7, None)


def test_input_min_length_setbyte():
    # setbyte X i b -> [b, i, X]; needs len(X) >= i+1, constraint on X = index 2
    assert _input_min_length(_asn("setbyte", inputs=[_int(255), _int(3), _var()])) == (2, 4, None)


def test_input_min_length_none_for_unconstraining_op():
    assert _input_min_length(_asn("concat", inputs=[_var(), _var()])) is None


# -- propagate_byte_lengths: the worklist end-to-end on tiny SSA graphs --


def test_propagate_forward_chain_through_fan_out():
    # itob -> v1 (8), then concat v1 v1 -> v2 (16). The assignments are seeded in
    # REVERSE (concat before itob) so v2 can only get its length once v1's change
    # fans out along v1.uses — exercising the worklist's re-trigger, not seed luck.
    v1, v2 = _var(10, 0), _var(11, 1)
    a_itob = _asn("itob", inputs=[_int(5)], outputs=[v1])
    a_concat = _asn("concat", inputs=[v1, v1], outputs=[v2])
    v1.uses.append(a_concat)
    propagate_byte_lengths(_prog([a_concat, a_itob]))
    assert v1.type.byte_length == 8
    assert v2.type.byte_length == 16


def test_propagate_phi_exact_length_agreement():
    # both phi args are length 8 -> phi pinned to exact length 8
    v1, v2 = _var(10, 0), _var(11, 1)
    a1 = _asn("itob", inputs=[_int(5)], outputs=[v1])
    a2 = _asn("itob", inputs=[_int(6)], outputs=[v2])
    ph = Phi("t.teal", 12, 0)
    ph.args = [v1, v2]
    propagate_byte_lengths(_prog([a1, a2], phis=[ph]))
    assert ph.type.byte_length == 8


def test_propagate_phi_range_union_on_disagreement():
    # args of length 8 and 32 disagree -> phi falls back to the range [8, 32]
    v1, v2 = _var(10, 0), _var(11, 1)
    a1 = _asn("itob", inputs=[_int(5)], outputs=[v1])           # 8
    a2 = _asn("sha256", inputs=[_bytes_operand(3)], outputs=[v2])  # 32
    ph = Phi("t.teal", 12, 0)
    ph.args = [v1, v2]
    propagate_byte_lengths(_prog([a1, a2], phis=[ph]))
    assert ph.type.byte_length is None
    assert ph.type.byte_length_range == IntRange(8, 32)


def test_propagate_inverse_constraint_seeds_input_range(tmp_path):
    # btoi(X) succeeding bounds X's length to [0, 8] even though nothing
    # forward-derives X's own length. Built from real TEAL (not a synthetic
    # assignment list) because the install is dominance-gated: the op must
    # dominate every other use of X, which needs real basic blocks.
    p = tmp_path / "a.teal"
    p.write_text("#pragma version 8\ntxn ApplicationArgs 0\nbtoi\nreturn\n")
    from tealql.tealtools.ssa import SSAProgram
    prog = SSAProgram(str(p))
    propagate_byte_lengths(prog)
    (arg_read,) = [a for a in prog.assignments if a.op == "txn"]
    x = arg_read.outputs[0]
    assert x.type.byte_length is None
    assert x.type.byte_length_range == IntRange(0, 8)


def test_inverse_constraint_not_installed_without_dominance(tmp_path):
    # One branch btoi's X; the other passes X along un-narrowed. The btoi does
    # NOT dominate the other branch's use, so NO global byte_length_range may
    # be installed on X — a range would cap X (e.g. byte-taint span) on paths
    # that never ran the btoi.
    p = tmp_path / "b.teal"
    p.write_text(
        "#pragma version 8\n"
        "txn ApplicationArgs 0\n"     # X (single SSA read site)
        "txn NumAppArgs\n"
        "bz other\n"
        "dup\n"
        "btoi\n"
        "pop\n"
        "pop\n"
        "int 1\n"
        "return\n"
        "other:\n"
        "len\n"                        # use of X NOT dominated by the btoi
        "return\n"
    )
    from tealql.tealtools.ssa import SSAProgram
    prog = SSAProgram(str(p))
    propagate_byte_lengths(prog)
    (arg_read,) = [a for a in prog.assignments if a.op == "txn"
                   and "ApplicationArgs" in a.immediates]
    x = arg_read.outputs[0]
    rng = getattr(x.type, "byte_length_range", None) if x.type else None
    assert rng is None or rng.hi > 8   # no unsound [.., 8] cap leaks across


# --------------------------------------------------------------------------
# Fixed-width bytes FIELDS (32-byte addresses / keys, 64-byte StateProofPK)
# --------------------------------------------------------------------------


def test_op_byte_length_address_fields():
    assert _op_byte_length(_asn("txn", imm="Sender")) == 32
    assert _op_byte_length(_asn("txn", imm="RekeyTo")) == 32
    assert _op_byte_length(_asn("txn", imm="ConfigAssetClawback")) == 32
    assert _op_byte_length(_asn("txn", imm="StateProofPK")) == 64
    # gtxn carries the field as the SECOND immediate (after the group index).
    assert _op_byte_length(_asn("gtxn", imm="0 Receiver")) == 32
    assert _op_byte_length(_asn("global", imm="ZeroAddress")) == 32
    assert _op_byte_length(_asn("global", imm="CurrentApplicationAddress")) == 32
    # A non-fixed-width field stays unknown (e.g. Note is variable length).
    assert _op_byte_length(_asn("txn", imm="Note")) is None


def test_op_byte_length_field_form_completeness():
    # Array-element address read via txna / gtxnsa (field is first immediate).
    assert _op_byte_length(_asn("txna", imm="Accounts 0")) == 32
    assert _op_byte_length(_asn("gtxnsa", imm="Accounts 0")) == 32
    # Inner-txn array + group-indexed forms.
    assert _op_byte_length(_asn("itxna", imm="Accounts 0")) == 32
    assert _op_byte_length(_asn("gitxn", imm="0 Sender")) == 32
    assert _op_byte_length(_asn("gitxna", imm="0 Accounts 1")) == 32


# --------------------------------------------------------------------------
# Multi-output crypto ops — positional fixed lengths (_OP_OUTPUT_BYTELEN)
# --------------------------------------------------------------------------


def test_ecdsa_pk_decompress_both_outputs_32():
    x, y = _var(10, 0), _var(10, 1)
    propagate_byte_lengths(
        _prog([_asn("ecdsa_pk_decompress", imm="Secp256k1",
                    inputs=[_bytes_operand(3)], outputs=[x, y])])
    )
    assert x.type.byte_length == 32
    assert y.type.byte_length == 32


def test_vrf_verify_output_is_64_bytes():
    # outputs[0] is the 0/1 verified flag (a uint64, no byte length);
    # outputs[1] is the 64-byte VRF output.
    flag, out = _var(10, 0), _var(10, 1)
    propagate_byte_lengths(
        _prog([_asn("vrf_verify", imm="VrfAlgorand",
                    inputs=[_bytes_operand(3)], outputs=[flag, out])])
    )
    assert out.type.byte_length == 64
    # the flag output isn't tagged with a bytes length
    assert getattr(flag.type, "byte_length", None) is None


# --------------------------------------------------------------------------
# *_params_get value output (outputs[1]) — field-keyed addresses
# --------------------------------------------------------------------------


def test_params_get_value_address_lengths():
    for op, field in (("app_params_get", "AppAddress"),
                      ("app_params_get", "AppCreator"),
                      ("asset_params_get", "AssetManager"),
                      ("asset_params_get", "AssetMetadataHash"),
                      ("acct_params_get", "AcctAuthAddr")):
        exists, value = _var(10, 0), _var(10, 1)
        propagate_byte_lengths(
            _prog([_asn(op, imm=field, inputs=[_int(0)],
                        outputs=[exists, value])])
        )
        assert value.type.byte_length == 32, (op, field)
        # the exists flag isn't a bytes value
        assert getattr(exists.type, "byte_length", None) is None, (op, field)


def test_params_get_unbounded_value_field_left_alone():
    # AssetTotal's value is a uint64 amount, not a fixed-width bytes field.
    exists, value = _var(10, 0), _var(10, 1)
    propagate_byte_lengths(
        _prog([_asn("asset_params_get", imm="AssetTotal", inputs=[_int(0)],
                    outputs=[exists, value])])
    )
    assert getattr(value.type, "byte_length", None) is None
