"""Contracts spanning mutable SSA, functional cleanup, lifting, and caches."""
from __future__ import annotations

import pytest

from tealql.tealtools.errors import TealParseError
from tealql.tealtools.lift import build_lifter, lift, pre_ir
from tealql.tealtools.passes import run_all_passes
from tealql.tealtools.ssa import BasicBlock, Phi, SSAProgram, SSAVar


def _prog(body: str, name: str = "p.teal") -> SSAProgram:
    return SSAProgram.from_text(f"#pragma version 8\n{body}\n", name=name)


def _exit(ir):
    exits = [bb.terminator for bb in ir.main.body
             if isinstance(bb.terminator, pre_ir.ProgramExit)]
    assert len(exits) == 1
    return exits[0].result


def test_return_owns_approval_operand_and_survives_cleanup():
    prog = _prog("int 1\nreturn")
    ret = next(a for a in prog.assignments if a.op == "return")
    assert len(ret.inputs) == 1
    run_all_passes(prog)
    assert isinstance(_exit(lift(prog)), pre_ir.UInt64Constant)
    assert _exit(lift(prog)).value == 1


@pytest.mark.parametrize("body, required", [
    ("txn Sender\ntxn Sender\n==\nreturn", ("txn", "==")),
    ("txna ApplicationArgs 0\nstore 0\nload 0\nlen\nreturn",
     ("store", "load", "len")),
    ("int 1\ndup\n+\nreturn", ("+",)),
])
def test_lift_uses_canonical_stream_after_functional_cleanup(body, required):
    prog = _prog(body)
    run_all_passes(prog)
    rendered = lift(prog).render()
    assert all(token in rendered for token in required), rendered
    assert len(prog.stack_assignments) >= len(prog.assignments)


def test_lifter_cache_is_revision_scoped():
    prog = _prog("txn Sender\ntxn Sender\n==\nreturn")
    first = build_lifter(prog)
    first_revision = prog.revision
    assert first is not None
    run_all_passes(prog)
    assert prog.revision > first_revision
    second = build_lifter(prog)
    assert second is not None and second is not first
    assert prog._ir_lifter_revision == prog.revision


def test_phi_user_cache_is_invalidated_by_supported_rewrite():
    prog = _prog(
        "txn NumAppArgs\nbz left\n"
        "txn Sender\nb join\nleft:\ntxn Sender\njoin:\nlen\nreturn"
    )
    phi = next(p for p in prog.phis.values() if len(p.args) >= 2)
    old_args = tuple(phi.args)
    assert prog.phi_users(old_args[0])
    prog.propagate_inputs()
    assert getattr(prog, "_phi_users_index", None) is None
    assert len({id(a) for a in phi.args}) == 1
    assert prog.phi_users(phi.args[0]) == [phi]


def test_strict_projection_cannot_return_a_partial_program():
    prog = SSAProgram.from_text(
        "#pragma version 8\nint 1\nnot_a_real_opcode\nreturn\n",
        name="partial.teal",
        strict=False,
    )
    assert prog.for_file("partial.teal", strict=False) is prog
    with pytest.raises(TealParseError):
        prog.for_file("partial.teal", strict=True)


@pytest.mark.parametrize("obj, attr, value", [
    (SSAVar("f", 1, 1), "line", 2),
    (Phi("f", 1, 1), "stack_index", 2),
    (BasicBlock("f", 1, 2), "first_line", 3),
])
def test_hashed_model_identity_is_immutable(obj, attr, value):
    before = hash(obj)
    with pytest.raises(AttributeError):
        setattr(obj, attr, value)
    assert hash(obj) == before
