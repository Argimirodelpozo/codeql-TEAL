"""Unit tests for the pre-IR operand accessors ``operands`` (read) and
``map_operands`` (rewrite-in-place) plus ``blocks`` — the single place that knows
where each node's Value operands live, so every lift pass shares one spelling of
the Op/ControlOp/Phi dispatch.

These build real ``pre_ir`` nodes (no CodeQL DB), but importing the pre-IR
package eagerly pulls in the lift, which needs ``puya`` — so the module
skip-gates on puya being importable, matching the fixture-skip pattern elsewhere.

The load-bearing case is ``map_operands``'s ``copy_source`` flag: a bare-Value
copy source must be rewritten under substitution but left alone under
trivial-phi collapse (forwarding a copy into a removed register corrupted
``large_box_operations`` + ``with_reentrancy`` until the flag was added). The
parity test pins that ``operands`` and ``map_operands`` visit identical
positions, so a pass that reads via one and writes via the other stays in sync.
"""
import pytest

pytest.importorskip("puya")  # pre_ir package __init__ eagerly imports the lift

from tealtools.lift.pre_ir import (  # noqa: E402
    Assert,
    Assignment,
    BasicBlock,
    ConditionalBranch,
    Fail,
    Goto,
    GotoNth,
    Intrinsic,
    IntrinsicOp,
    Phi,
    PhiArgument,
    Program,
    ProgramExit,
    Register,
    Subroutine,
    SubroutineReturn,
    Switch,
    ValueTuple,
    blocks,
    map_operands,
    operands,
)


def _r(name, version=0, ir_type="uint64"):
    return Register(name, version, ir_type)


# --------------------------------------------------------------------------
# operands — read each Value operand
# --------------------------------------------------------------------------


def test_operands_assignment_intrinsic_source():
    a, b = _r("a"), _r("b")
    asn = Assignment([_r("c")], Intrinsic("+", [], [a, b]))
    assert list(operands(asn)) == [a, b]


def test_operands_assignment_bare_copy_source():
    a = _r("a")
    asn = Assignment([_r("c")], a)            # let c = a  (a copy)
    assert list(operands(asn)) == [a]


def test_operands_assignment_value_tuple_source():
    a, b = _r("a"), _r("b")
    asn = Assignment([_r("c"), _r("d")], ValueTuple([a, b]))
    assert list(operands(asn)) == [a, b]


def test_operands_phi():
    a, b = _r("a"), _r("b")
    ph = Phi(_r("p"), [PhiArgument(a, 0), PhiArgument(b, 1)])
    assert list(operands(ph)) == [a, b]


def test_operands_statement_and_control_ops():
    a, b = _r("a"), _r("b")
    assert list(operands(IntrinsicOp(Intrinsic("log", [], [a])))) == [a]
    assert list(operands(Assert(a))) == [a]
    assert list(operands(ConditionalBranch(a, 1, 2))) == [a]
    assert list(operands(Switch(a, [("0u", 1)], 2))) == [a]
    assert list(operands(GotoNth(a, [1, 2], 3))) == [a]
    assert list(operands(SubroutineReturn([a, b]))) == [a, b]
    assert list(operands(ProgramExit(a))) == [a]


def test_operands_empty_for_operandless():
    assert list(operands(Goto(1))) == []
    assert list(operands(Fail())) == []
    assert list(operands(None)) == []


# --------------------------------------------------------------------------
# map_operands — rewrite in place
# --------------------------------------------------------------------------


def test_map_operands_rewrites_intrinsic_args():
    a, b, z = _r("a"), _r("b"), _r("z")
    asn = Assignment([_r("c")], Intrinsic("+", [], [a, b]))
    map_operands(asn, lambda v: z if v is a else v)
    assert asn.source.args == [z, b]


def test_map_operands_rewrites_phi_args():
    a, b, z = _r("a"), _r("b"), _r("z")
    ph = Phi(_r("p"), [PhiArgument(a, 0), PhiArgument(b, 1)])
    map_operands(ph, lambda v: z if v is b else v)
    assert [arg.value for arg in ph.args] == [a, z]


def test_map_operands_copy_source_true_rewrites_bare_source():
    a, z = _r("a"), _r("z")
    asn = Assignment([_r("c")], a)
    map_operands(asn, lambda v: z, copy_source=True)      # the substitution default
    assert asn.source is z


def test_map_operands_copy_source_false_preserves_bare_source():
    # the bug fix: trivial-phi collapse must NOT forward a copy into a register
    # it just removed, so a bare-Value source is left untouched.
    a, z = _r("a"), _r("z")
    asn = Assignment([_r("c")], a)
    map_operands(asn, lambda v: z, copy_source=False)
    assert asn.source is a


def test_map_operands_copy_source_false_still_rewrites_structured_source():
    # copy_source guards ONLY a bare-Value source; a structured source (Intrinsic
    # args, tuple values) is always rewritten regardless of the flag.
    a, z = _r("a"), _r("z")
    asn = Assignment([_r("c")], Intrinsic("!", [], [a]))
    map_operands(asn, lambda v: z, copy_source=False)
    assert asn.source.args == [z]


def test_operands_and_map_operands_visit_same_positions():
    # operands (read) and map_operands (write, identity fn) must traverse the
    # exact same operand positions in the same order — else a substitution pass
    # reading one set and rewriting another would silently desync.
    a, b = _r("a"), _r("b")
    nodes = [
        Assignment([_r("c")], Intrinsic("+", [], [a, b])),
        Assignment([_r("c")], a),                          # bare copy source
        Assignment([_r("c"), _r("d")], ValueTuple([a, b])),
        Phi(_r("p"), [PhiArgument(a, 0), PhiArgument(b, 1)]),
        IntrinsicOp(Intrinsic("log", [], [a])),
        Assert(a),
        ConditionalBranch(a, 1, 2),
        Switch(a, [("0u", 1)], 2),
        GotoNth(a, [1, 2], 3),
        SubroutineReturn([a, b]),
        ProgramExit(a),
        Goto(1),
        Fail(),
    ]
    for node in nodes:
        expected = list(operands(node))
        seen = []
        map_operands(node, lambda v: seen.append(v) or v)   # record + identity
        assert seen == expected


# --------------------------------------------------------------------------
# blocks — flatten a Program / iterable of Subroutines
# --------------------------------------------------------------------------


def test_blocks_yields_main_then_subroutines():
    bm, bs0, bs1 = BasicBlock(0), BasicBlock(1), BasicBlock(2)
    main = Subroutine("main", [], [], [bm], is_main=True)
    sub = Subroutine("s", [], [], [bs0, bs1])
    prog = Program(main=main, subroutines=[sub])
    assert list(blocks(prog)) == [bm, bs0, bs1]
    # also accepts a bare iterable of subroutines, in the given order
    assert list(blocks([sub, main])) == [bs0, bs1, bm]
