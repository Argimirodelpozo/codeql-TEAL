"""Unit tests for the constant folder (``tealql.tealtools.ssa.const_fold``).

Pure-function tests — no CodeQL DB required. Focused on the uint64
bitwise / shift folds added on top of the arithmetic ones, where the
AVM semantics have sharp edges (``<<`` wraps mod 2^64; shift counts
>= 64 zero the result; ``~`` is the uint64 complement, not Python's
sign-flipping ``~``).
"""
from tealql.tealtools.ssa import Assignment, Const, Location, SSAVar
from tealql.tealtools.ssa.const_fold import (
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
        assert _val(_fold_bitwise("shl", [_c(1), _c(4)])) == 16
        assert _val(_fold_bitwise("shl", [_c(1), _c(63)])) == 1 << 63

    def test_shl_wraps_mod_2_64(self):
        # AVM ``<<`` is ``A * 2^B mod 2^64`` — the top bit overflows away.
        assert _val(_fold_bitwise("shl", [_c(3), _c(63)])) == (3 << 63) & UMAX
        assert _val(_fold_bitwise("shl", [_c(UMAX), _c(1)])) == (UMAX << 1) & UMAX

    def test_shift_count_ge_64_halts_no_fold(self):
        # B > 63 HALTS the AVM ("shl/shr arg too big") — folding to 0 would
        # fabricate a constant on an always-erroring path, so return None.
        assert _fold_bitwise("shl", [_c(1), _c(64)]) is None
        assert _fold_bitwise("shl", [_c(UMAX), _c(UMAX)]) is None
        assert _fold_bitwise("shr", [_c(1), _c(64)]) is None
        assert _val(_fold_bitwise("shr", [_c(1), _c(63)])) == 0   # 63 still folds

    def test_shr(self):
        assert _val(_fold_bitwise("shr", [_c(256), _c(4)])) == 16
        assert _val(_fold_bitwise("shr", [_c(UMAX), _c(63)])) == 1

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
    """Minimal single-output Assignment with Const inputs for dispatch tests.

    ``const_inputs`` are given in source order — ``A, B`` for the AVM op
    ``A op B`` (``A`` the deeper stack value). Real ``Assignment.inputs`` are
    **top-first** (``inputs[0]`` = topmost popped) per the SSA simulator, so we
    store them reversed here. That way the dispatch tests exercise
    ``try_fold_assignment`` with the same operand order it sees in production
    (it reverses back internally) — which is what makes non-commutative folds
    (``<<``, ``-``, ``/``, ``concat``, …) directional-correct.
    """
    out = SSAVar("f.teal", 1, 1)
    return Assignment(
        outputs=[out],
        op=op,
        immediates="",
        inputs=list(reversed(const_inputs)),
        location=Location("f.teal", 1),
        ast_code=op,
        const=None,
        basic_block=None,
    )


def test_wide_constant_outputs_match_uint128_arithmetic():
    from itertools import product
    from tealql.tealtools.ssa.const_fold import try_fold_outputs
    values = [0, 1, 3, 2 ** 32 - 1, 2 ** 32, 2 ** 63, UMAX]
    for op, left, right in product(('addw', 'mulw'), values, values):
        assignment = _assign(op, _c(left), _c(right))
        assignment.outputs.append(SSAVar('f.teal', 1, 2))
        low, high = map(_val, try_fold_outputs(assignment))
        assert high * 2 ** 64 + low == (left + right if op == 'addw' else left * right)
        assert 0 <= low <= UMAX and 0 <= high <= UMAX
        assert try_fold_assignment(assignment) is None  # single-output API remains unambiguous


def test_wide_folding_refuses_invalid_or_unknown_inputs_and_output_layouts():
    from tealql.tealtools.ssa.const_fold import try_fold_outputs
    for bad in (_c(-1), _c(2 ** 64), Const('bytes', '0x00'), SSAVar('f.teal', 2, 1)):
        assignment = _assign('mulw', bad, _c(3))
        assignment.outputs.append(SSAVar('f.teal', 1, 2))
        assert try_fold_outputs(assignment) is None
    for inputs, outputs in ((1, 2), (2, 1), (2, 3)):
        assignment = _assign('mulw', *[_c(3)] * inputs)
        assignment.outputs = [SSAVar('f.teal', 1, index + 1) for index in range(outputs)]
        assert try_fold_outputs(assignment) is None


class TestDispatch:
    def test_bitwise_routed(self):
        assert _val(try_fold_assignment(_assign("&", _c(0xFF), _c(0x0F)))) == 0x0F
        # `shl`/`shr` are the real AVM mnemonics (NOT `<<`/`>>`); dispatch on the
        # wrong token silently left every static shift unfolded.
        assert _val(try_fold_assignment(_assign("shl", _c(1), _c(4)))) == 16
        assert _val(try_fold_assignment(_assign("shr", _c(256), _c(4)))) == 16
        # directional: `A shr B` is `A // 2^B`, not `B // 2^A` (2 shr 256 != 256 shr 2)
        assert _val(try_fold_assignment(_assign("shr", _c(256), _c(2)))) == 64
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
