"""Adversarial contracts for the representation boundaries.

These are intentionally not opcode-feature tests.  They pin information and
identity while objects are replaced or cloned: graph/preliminary SSA -> private
stack SSA -> public SSA -> mutable pre-IR.  A rendered program can look correct
while an id()-keyed analysis sees an undefined clean value, so object identity is
part of the contract here.
"""
from __future__ import annotations

import pytest

from tealql.security._itxn_taint import ir_lifter
from tealql.tealtools.errors import LiftError
from tealql.tealtools.graph import load_graph
from tealql.tealtools.lift import build_lifter, pre_ir
from tealql.tealtools.lift.lift import _Lifter, lift
from tealql.tealtools.ssa import PySSA, SSAProgram


def test_private_ssa_replacement_preserves_assignment_constants():
    prog = SSAProgram.from_text(
        "#pragma version 8\n"
        "bytecblock 0xdeadbeef\n"
        "bytec_0\n"
        "pop\n"
        "pushint 1\n"
        "return\n",
        name="const.teal",
    )
    bytec = next(a for a in prog if a.op == "bytec_0")
    assert bytec.const is not None and bytec.const.value == "0xdeadbeef"

    # These passes deliberately consume Assignment.const, not only the output's
    # const_value; before the boundary fix both exact facts disappeared.
    prog.propagate_byte_lengths()
    prog.propagate_bytemath_ranges()
    ty = bytec.outputs[0].type
    assert ty is not None and ty.byte_length == 4
    assert ty.int_value_range is not None
    assert (ty.int_value_range.lo, ty.int_value_range.hi) == (0xDEADBEEF, 0xDEADBEEF)


def test_exported_pyssa_rebuild_preserves_program_metadata():
    prog = SSAProgram.from_text(
        "#pragma version 8\n"
        "pushint 1\n"
        "bnz at_end\n"
        "pushint 0\n"
        "return\n"
        "at_end:\n",
        name="metadata.teal",
    )
    rebuilt = PySSA.build(prog)

    assert rebuilt.off_end_exits == prog.off_end_exits
    assert rebuilt.edge_polarity == prog.edge_polarity
    assert rebuilt.unknown_ops == prog.unknown_ops
    assert rebuilt.parse_diagnostics == prog.parse_diagnostics


_POLYMORPHIC_GET = """#pragma version 8
pushbytes 0x61
callsub get
pushint 1
+
pop
pushbytes 0x62
callsub get
len
pop
pushint 1
return
get:
proto 1 1
frame_dig -1
app_global_get
retsub
"""


def test_specialization_keeps_program_and_lifter_views_identical():
    prog = SSAProgram.from_text(_POLYMORPHIC_GET, name="poly.teal")
    lifter = _Lifter(prog)
    ir = lifter.build()

    assert ir.pass_stats["specialize_returns"] == 1
    assert lifter.subs == [ir.main, *ir.subroutines]
    assert lifter.name2sub == {s.id: s for s in ir.subroutines}
    assert not pre_ir.structural_errors(ir)

    clone = next(s for s in ir.subroutines if "__" in s.id)
    param = clone.parameters[0].register
    uses = [
        value
        for bb in clone.body
        for node in (*bb.phis, *bb.ops, bb.terminator)
        for value in pre_ir.operands(node)
        if isinstance(value, pre_ir.Register) and value.local_id == param.local_id
    ]
    assert uses and all(value is param for value in uses)
    assert lifter.register_sources[id(param)], "clone parameter lost its SSA provenance"


def test_pre_ir_validator_rejects_an_undefined_register_lookalike():
    declared = pre_ir.Register("p%0", 0, "bytes")
    lookalike = pre_ir.Register("p%0", 0, "bytes")
    sub = pre_ir.Subroutine(
        id="broken",
        parameters=[pre_ir.Parameter(declared)],
        returns=[],
        body=[pre_ir.BasicBlock(
            id=1,
            ops=[pre_ir.IntrinsicOp(pre_ir.Intrinsic("log", [], [lookalike]))],
            terminator=pre_ir.SubroutineReturn([]),
        )],
    )
    main = pre_ir.Subroutine(
        id="main", parameters=[], returns=[], is_main=True,
        body=[pre_ir.BasicBlock(
            id=0, terminator=pre_ir.ProgramExit(pre_ir.UInt64Constant(1)),
        )],
    )
    program = pre_ir.Program(main, [sub])

    errors = pre_ir.structural_errors(program)
    assert any("uses undefined p%0#0" in e for e in errors), errors
    with pytest.raises(ValueError, match="malformed pre-IR"):
        pre_ir.assert_well_formed(program)


def test_legacy_negative_frame_read_becomes_an_implicit_parameter():
    prog = SSAProgram.from_text(
        "#pragma version 8\n"
        "pushint 9\n"
        "callsub legacy\n"
        "pop\n"
        "pop\n"
        "pushint 1\n"
        "return\n"
        "legacy:\n"
        "pushint 42\n"
        "frame_dig -1\n"
        "retsub\n",
        name="legacy-frame.teal",
    )
    lifter = _Lifter(prog)
    ir = lifter.build()
    legacy = next(s for s in ir.subroutines if s.id == "legacy")

    assert len(legacy.parameters) == 1
    returned = [
        value
        for bb in legacy.body
        if isinstance(bb.terminator, pre_ir.SubroutineReturn)
        for value in bb.terminator.result
    ]
    assert any(value is legacy.parameters[0].register for value in returned)
    assert not pre_ir.structural_errors(ir)


def test_multi_file_lift_projects_one_independent_program():
    prog = SSAProgram.from_graph(load_graph({
        "a.teal": (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\n"
            "log\n"
            "pushint 1\n"
            "return\n"
        ),
        "b.teal": "#pragma version 8\npushint 1\nreturn\n",
    }))
    assert prog.source_files == ("a.teal", "b.teal")

    # One pre-IR Program has one main entry and cannot truthfully represent two
    # independent AVM executions.
    with pytest.raises(LiftError, match="exactly one AVM program"):
        lift(prog)

    a = build_lifter(prog, file="a.teal")
    b = build_lifter(prog, file="b.teal")
    assert a is not None and b is not None and a is not b
    assert a.prog.source_files == ("a.teal",)
    assert b.prog.source_files == ("b.teal",)
    assert build_lifter(prog, file="a.teal") is a       # per-file cache
    assert ir_lifter(prog, file="a.teal") is a          # shared detector cache
    assert ir_lifter(prog, file="b.teal") is b
    assert {x.location.file for x in a.prog.assignments} == {"a.teal"}
    assert {x.location.file for x in b.prog.assignments} == {"b.teal"}
