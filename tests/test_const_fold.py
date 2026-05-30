"""Unit tests for the constant folder (``tealtools.passes.const_fold``).

Pure-function tests — no CodeQL DB required. Focused on the uint64
bitwise / shift folds added on top of the arithmetic ones, where the
AVM semantics have sharp edges (``<<`` wraps mod 2^64; shift counts
>= 64 zero the result; ``~`` is the uint64 complement, not Python's
sign-flipping ``~``).
"""
from tealtools.ssa import Assignment, Const, Location, SSAVar
from tealtools.passes.const_fold import (
    _fold_bitwise,
    _fold_bitwise_not,
    try_fold_assignment,
)

UMAX = (1 << 64) - 1


def _c(n: int) -> Const:
    return Const("int", str(n))


def _val(c):
    return None if c is None else int(c.value)


class TestBitwiseBinary:
    def test_and_or_xor(self):
        assert _val(_fold_bitwise("&", [_c(0xFF), _c(0x0F)])) == 0x0F
        assert _val(_fold_bitwise("&", [_c(0xF0), _c(0x0F)])) == 0x00
        assert _val(_fold_bitwise("|", [_c(0xF0), _c(0x0F)])) == 0xFF
        assert _val(_fold_bitwise("^", [_c(0xFF), _c(0x0F)])) == 0xF0

    def test_shl_basic(self):
        assert _val(_fold_bitwise("<<", [_c(1), _c(4)])) == 16
        assert _val(_fold_bitwise("<<", [_c(1), _c(63)])) == 1 << 63

    def test_shl_wraps_mod_2_64(self):
        # AVM ``<<`` is ``A * 2^B mod 2^64`` — the top bit overflows away.
        assert _val(_fold_bitwise("<<", [_c(3), _c(63)])) == (3 << 63) & UMAX
        assert _val(_fold_bitwise("<<", [_c(UMAX), _c(1)])) == (UMAX << 1) & UMAX

    def test_shift_count_ge_64_is_zero(self):
        # B >= 64 zeroes the result; must not allocate a giant Python int.
        assert _val(_fold_bitwise("<<", [_c(1), _c(64)])) == 0
        assert _val(_fold_bitwise("<<", [_c(UMAX), _c(UMAX)])) == 0
        assert _val(_fold_bitwise(">>", [_c(1), _c(64)])) == 0

    def test_shr(self):
        assert _val(_fold_bitwise(">>", [_c(256), _c(4)])) == 16
        assert _val(_fold_bitwise(">>", [_c(UMAX), _c(63)])) == 1

    def test_non_const_or_oob_rejected(self):
        assert _fold_bitwise("&", [Const("bytes", "0x01"), _c(1)]) is None
        assert _fold_bitwise("&", [_c(-1), _c(1)]) is None
        assert _fold_bitwise("&", [_c(1 << 65), _c(1)]) is None
        assert _fold_bitwise("&", [_c(1)]) is None  # wrong arity


class TestBitwiseNot:
    def test_uint64_complement(self):
        assert _val(_fold_bitwise_not([_c(0)])) == UMAX
        assert _val(_fold_bitwise_not([_c(UMAX)])) == 0
        assert _val(_fold_bitwise_not([_c(1)])) == UMAX - 1

    def test_oob_rejected(self):
        assert _fold_bitwise_not([_c(-1)]) is None
        assert _fold_bitwise_not([_c(1 << 64)]) is None


def _assign(op: str, *const_inputs: Const) -> Assignment:
    """Minimal single-output Assignment with Const inputs for dispatch tests."""
    out = SSAVar("f.teal", 1, 1)
    return Assignment(
        outputs=[out],
        op=op,
        immediates="",
        inputs=list(const_inputs),
        location=Location("f.teal", 1),
        ast_code=op,
        const=None,
        basic_block=None,
    )


class TestDispatch:
    def test_bitwise_routed(self):
        assert _val(try_fold_assignment(_assign("&", _c(0xFF), _c(0x0F)))) == 0x0F
        assert _val(try_fold_assignment(_assign("<<", _c(1), _c(4)))) == 16
        assert _val(try_fold_assignment(_assign("~", _c(0)))) == UMAX

    def test_logical_not_confused_with_bitwise(self):
        # ``&&`` / ``||`` are logical (folded separately); they must keep
        # their boolean semantics, not be treated as ``&`` / ``|``.
        assert _val(try_fold_assignment(_assign("&&", _c(2), _c(3)))) == 1
        assert _val(try_fold_assignment(_assign("||", _c(0), _c(0)))) == 0
        assert _val(try_fold_assignment(_assign("!", _c(0)))) == 1

    def test_byte_complement_not_folded_here(self):
        # ``b~`` (byte complement) is deliberately not folded — its result
        # depends on byte length, which this int folder doesn't model.
        assert try_fold_assignment(_assign("b~", Const("bytes", "0x00"))) is None
