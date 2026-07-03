"""Unit test for ``to_puya_ir._duplicate_shared_epilogues`` — tail-duplication of
a compiler-shared exit block reached by direct branches from more than one
routine.

Puya requires each block to belong to exactly one subroutine, so a shared
``exit 0`` reject block that BOTH main and a subroutine jump to fails Puya's
Subroutine validator ("predecessor block(s) outside of list"). Since such a
sink carries no value (no phis/ops, terminal, no register operands), each
routine can safely get its own identical copy. Regression for the v5 mainnet
liftfail app_448399719 (a shared reject epilogue branched to from ~30 main
handlers and a subroutine's entry).
"""
import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import pre_ir as P  # noqa: E402
from tealql.tealtools.lift.to_puya_ir import (  # noqa: E402
    _duplicate_shared_epilogues,
    _term_targets,
)


def _exit0():
    return P.ProgramExit(result=P.UInt64Constant(value=0))


def _cross_group_edges(lifted):
    groups = [lifted.main, *lifted.subroutines]
    owner = {bb.id: g for g in groups for bb in g.body}
    edges = []
    for g in groups:
        for bb in g.body:
            for succ in _term_targets(bb.terminator):
                if owner.get(bb.id) is not owner.get(succ):
                    edges.append((bb.id, succ))
    return edges


def test_shared_sink_is_duplicated_per_routine():
    # main block 0 --goto--> 2 ; sub block 1 --goto--> 2 ; block 2 = shared exit 0
    shared = P.BasicBlock(id=2, phis=[], ops=[], terminator=_exit0())
    main = P.Subroutine(id="main", parameters=[], returns=[],
                        body=[P.BasicBlock(id=0, terminator=P.Goto(target=2))],
                        is_main=True)
    sub = P.Subroutine(id="sub", parameters=[], returns=[],
                       body=[P.BasicBlock(id=1, terminator=P.Goto(target=2)), shared])
    prog = P.Program(main=main, subroutines=[sub])

    assert _cross_group_edges(prog) == [(0, 2)]      # main(0) -> shared(2) in sub
    _duplicate_shared_epilogues(prog)

    # the shared original is gone; no edge crosses a routine boundary now
    all_ids = [bb.id for g in (prog.main, *prog.subroutines) for bb in g.body]
    assert 2 not in all_ids
    assert _cross_group_edges(prog) == []
    # each routine kept its branch and now targets its OWN exit-0 clone
    for g in (prog.main, sub):
        brancher = next(bb for bb in g.body if isinstance(bb.terminator, P.Goto))
        tgt = next(bb for bb in g.body if bb.id == brancher.terminator.target)
        assert isinstance(tgt.terminator, P.ProgramExit)
        assert tgt.terminator.result.value == 0


def test_value_carrying_block_is_left_untouched():
    # a sink that returns a REGISTER must NOT be duplicated (needs phi splitting)
    reg = P.Register(name="v", version=0, ir_type="uint64")
    shared = P.BasicBlock(id=2, phis=[], ops=[], terminator=P.ProgramExit(result=reg))
    main = P.Subroutine(id="main", parameters=[], returns=[],
                        body=[P.BasicBlock(id=0, terminator=P.Goto(target=2))],
                        is_main=True)
    sub = P.Subroutine(id="sub", parameters=[], returns=[],
                       body=[P.BasicBlock(id=1, terminator=P.Goto(target=2)), shared])
    prog = P.Program(main=main, subroutines=[sub])
    _duplicate_shared_epilogues(prog)
    all_ids = [bb.id for g in (prog.main, *prog.subroutines) for bb in g.body]
    assert 2 in all_ids                              # untouched
