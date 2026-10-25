"""`analysis.stack_depth`: an upper bound on the AVM stack depth (eval.go maxStackDepth).

The bound is what lets a consumer say "no execution of this program can overflow" for
the overflows the lift does not check (a callee's frame over its caller's residual,
recursion, depth-merging joins). Each case states the depth the AVM reaches."""
from __future__ import annotations

from tealql.tealtools.analysis.stack_depth import MAX_STACK_DEPTH, stack_depth_bound
from tealql.tealtools.ssa import SSAProgram


def _bound(tmp_path, teal: str):
    p = tmp_path / "prog.teal"
    p.write_text(teal.strip() + "\n")
    return stack_depth_bound(SSAProgram(str(p), strict=True))


def test_straight_line_depth_is_exact(tmp_path):
    assert _bound(tmp_path, "#pragma version 8\nint 1\nint 2\n+").bound == 2


def test_a_call_adds_the_callers_residual(tmp_path):
    # f's frame: its argument plus three pushes = 4, over an empty residual
    b = _bound(tmp_path, "#pragma version 8\npushint 1\ncallsub f\nreturn\nf:\nproto 1 1\n"
                         "pushint 2\npushint 3\npushint 4\npopn 3\nretsub")
    assert b.bound == 4 and not b.may_overflow
    # the same callee under 5 more values reaches 9
    b = _bound(tmp_path, "#pragma version 8\npushint 0\ndupn 4\npushint 1\ncallsub f\npopn 6\n"
                         "pushint 1\nreturn\nf:\nproto 1 1\npushint 2\npushint 3\npushint 4\n"
                         "popn 3\nretsub")
    assert b.bound == 9


_MAIN_600 = ("#pragma version 8\npushint 1\ndupn 255\ndupn 255\ndupn 89\ncallsub f\n"
             "popn 255\npopn 255\npopn 89\nreturn\nf:\nproto 0 0\npushint 1\n")


def test_neither_routine_overflows_alone_but_the_call_does(tmp_path):
    """600 values in main, 500 more in the callee: 1100 on chain ("stack overflow" --
    checked on go-algorand), though each routine's own depth stays under 1000. With 400
    in the callee the peak is exactly 1000, and the chain accepts."""
    b = _bound(tmp_path, _MAIN_600 + "dupn 255\ndupn 244\npopn 255\npopn 245\nretsub")
    assert b.may_overflow and b.bound is None
    b = _bound(tmp_path, _MAIN_600 + "dupn 255\ndupn 144\npopn 255\npopn 145\nretsub")
    assert b.bound == MAX_STACK_DEPTH and not b.may_overflow


def test_recursion_that_keeps_a_value_per_level_is_unbounded(tmp_path):
    b = _bound(tmp_path, "#pragma version 8\npushint 5\ncallsub f\nreturn\nf:\nproto 1 1\n"
                         "frame_dig -1\nbz done\nframe_dig -1\npushint 1\n-\ncallsub f\n"
                         "frame_bury -1\ndone:\nframe_dig -1\nretsub")
    assert b.may_overflow


def test_recursion_that_keeps_nothing_is_bounded(tmp_path):
    b = _bound(tmp_path, "#pragma version 8\nb main\nf:\nproto 0 0\npushint 0\nbz skip\n"
                         "callsub f\nskip:\nretsub\nmain:\ncallsub f\nint 1")
    assert b.bound == 1


def test_a_join_takes_the_deeper_arm(tmp_path):
    # one arm leaves 3 values, the other 1; after the join the bound is the deeper arm
    b = _bound(tmp_path, "#pragma version 8\ntxn NumAppArgs\nbz short\nint 1\nint 2\nint 3\n"
                         "b join\nshort:\nint 1\njoin:\nint 9\nreturn")
    assert b.bound == 4


def test_a_loop_that_grows_the_stack_is_unbounded(tmp_path):
    b = _bound(tmp_path, "#pragma version 8\nint 0\nloop:\nint 1\nint 1\nbnz loop\nreturn")
    assert b.may_overflow


def test_the_limit_itself_is_not_an_overflow(tmp_path):
    """Exactly 1000 values is allowed (eval.go fails `> maxStackDepth`); 1001 is not."""
    teal = ("#pragma version 8\npushint 1\ndupn 255\ndupn 255\ndupn 255\ndupn 234\n"
            "popn 255\npopn 255\npopn 255\npopn 234\nreturn")
    b = _bound(tmp_path, teal)
    assert b.bound == MAX_STACK_DEPTH and not b.may_overflow
    b = _bound(tmp_path, teal.replace("234", "235"))
    assert b.may_overflow
