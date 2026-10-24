"""Pins for the lift defects avm-prover's go-algorand test-suite replay found (2026-10-24).

Each program is a scenario from go-algorand's own `data/transactions/logic` tests where
the lifted program disagreed with the chain. The chain's verdict is cited per case
(eval.go / frames.go at go-algorand 3490087555c5); the assertion is on the lifted
program's reachable exits: a program the chain always rejects with a panic must lift to
`Fail` on every path, and one the chain can approve must keep a reachable `ProgramExit`.

- F4: the final stack must hold exactly one uint64 ("stack len is N instead of 1",
  "stack finished with bytes not int"); the lift exited with the top cell, or 0.
- F5: more than 1000 stack values fail ("stack overflow").
- F6: `proto` outside a subroutine fails ("proto was executed without a callsub").
- F10: a branch to the program's END (a label after the last instruction, or a
  conditional's fall-through when it is the last instruction) lost its edge; a
  `callsub` as the last instruction exited with 0 (the callee returns into the end of
  the program, whose stack then holds its results).
- F11: frame access is bounds-checked (frames.go): main has no frame, and no access
  reaches at or above the stack top.
- F12: constant blocks take effect when EXECUTED (opIntConstBlock); the lowering read
  the last block above the load in the text.
"""
from __future__ import annotations

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import pre_ir  # noqa: E402
from tealql.tealtools.lift.lift import lift  # noqa: E402
from tealql.tealtools.ssa import SSAProgram  # noqa: E402


def _lifted(tmp_path, teal: str):
    p = tmp_path / "prog.teal"
    p.write_text(teal.strip() + "\n")
    return lift(SSAProgram(str(p)))


def _main_exits(pre) -> list:
    """The terminators of main's blocks reachable from its entry block."""
    body = {b.id: b for b in pre.main.body}
    seen, todo, out = set(), [pre.main.body[0].id], []
    while todo:
        bid = todo.pop()
        if bid in seen or bid not in body:
            continue
        seen.add(bid)
        term = body[bid].terminator
        out.append(term)
        todo.extend(pre_ir.succ_ids(term))
    return out


def _exit_values(pre) -> list:
    return [t.result for t in _main_exits(pre) if isinstance(t, pre_ir.ProgramExit)]


def _fail_messages(pre) -> list:
    return [t.error_message for t in _main_exits(pre) if isinstance(t, pre_ir.Fail)]


ALWAYS_PANIC = {
    "F4_empty_final_stack": ("#pragma version 14\nint 1\nint 1\npop\npop",
                             "stack len is 0 instead of 1"),
    "F4_two_values_left": ("#pragma version 14\nint 1\nint 1",
                           "stack len is 2 instead of 1"),
    "F4_callsub_leaves_two": ("#pragma version 14\nb main\nsub:\npushint 4\nretsub\n"
                              "main:\ncallsub sub\npushint 1", "stack len is 2 instead of 1"),
    "F4_bytes_result": ("#pragma version 14\npushbytes 0x01",
                        "stack finished with bytes not int"),
    "F5_stack_overflow": ("#pragma version 2\nint 1\nint 2\n" + "dup2\n" * 510
                          + "pop\nint 1", None),
    "F6_proto_without_callsub": ("#pragma version 14\nproto 0 0\npushint 1", None),
    "F11_frame_op_in_main": ("#pragma version 14\nframe_dig 0\npushint 1", None),
    "F11_frame_bury_above_stack": ("#pragma version 14\nb main\nsub:\nproto 2 1\npushint 0\n"
                                   "dupn 2\npushint 4\nframe_bury 3\nretsub\nmain:\n"
                                   "pushint 8\npushint 2\ncallsub sub\npushint 1", None),
    "F12_intc_before_any_block": ("#pragma version 14\nintc_1\nintcblock 3", None),
    "F12_bytec_past_the_executed_block": ("#pragma version 14\nbytecblock 0x2222\nb l\n"
                                          "bytecblock 0x11 0x12\nl:\nbytec_1\nlen", None),
    "F10_eof_callsub_leaves_two": ("#pragma version 8\nb main\nf:\nproto 1 2\nframe_dig -1\n"
                                   "dup\nretsub\nmain:\npushint 3\ncallsub f",
                                   "stack len is 2 instead of 1"),
}


@pytest.mark.parametrize("name", sorted(ALWAYS_PANIC))
def test_a_program_the_chain_always_fails_lifts_to_fail_on_every_path(tmp_path, name):
    teal, message = ALWAYS_PANIC[name]
    pre = _lifted(tmp_path, teal)
    assert not _exit_values(pre), [t.render() for t in _main_exits(pre)]
    assert _fail_messages(pre), "no reachable Fail: the lift lost the panicking path"
    if message is not None:
        assert message in _fail_messages(pre), _fail_messages(pre)


ACCEPTS = {
    "F10_bnz_to_a_label_at_eof": "#pragma version 14\npushint 1\npushint 1\nbnz l2\nerr\nl2:",
    "F10_switch_to_a_label_at_eof": "#pragma version 14\npushint 1\ndup\nswitch l1 l2\nl1:\nerr\nl2:",
    "F10_match_to_a_label_at_eof": ("#pragma version 14\npushint 1\npushint 99\npushint 100\n"
                                    "pushint 100\nmatch l1 l2\nl1:\nerr\nl2:"),
    "F10_loop_falling_off_the_end": ("#pragma version 14\nint 0\nloop:\nint 1\n+\ndup\n"
                                     "pushint 3\n<\nbnz loop"),
    "F12_dead_second_block": ("#pragma version 14\nbytecblock 0x2222\nb l\nbytecblock 0x11\n"
                              "l:\nbytec_0\nbytec_0\nconcat\nlen\npushint 4\n=="),
    "F10_eof_callsub_returns_the_result": ("#pragma version 8\nb main\nf:\nproto 1 1\n"
                                           "frame_dig -1\nretsub\nmain:\npushint 3\ncallsub f"),
    # controls: the depth rule does not touch an ordinary one-value exit
    "control_one_value": "#pragma version 14\nint 1",
    "control_return_from_a_deeper_stack": "#pragma version 14\nint 7\nint 1\nreturn",
}


@pytest.mark.parametrize("name", sorted(ACCEPTS))
def test_a_program_the_chain_can_approve_keeps_a_reachable_exit(tmp_path, name):
    pre = _lifted(tmp_path, ACCEPTS[name])
    assert _exit_values(pre), [t.render() for t in _main_exits(pre)]
    assert not any(isinstance(v, pre_ir.Undefined) for v in _exit_values(pre))


def test_an_eof_branch_arm_is_its_own_exit(tmp_path):
    """`bnz l2` with `l2:` at EOF: the TAKEN arm exits (with the one remaining value);
    the fall-through reaches `err`. Before, the branch lifted to a `goto` of the `err`."""
    pre = _lifted(tmp_path, ACCEPTS["F10_bnz_to_a_label_at_eof"])
    body = {b.id: b for b in pre.main.body}
    branch = next(t for t in _main_exits(pre) if isinstance(t, pre_ir.ConditionalBranch))
    assert isinstance(body[branch.non_zero].terminator, pre_ir.ProgramExit)
    assert isinstance(body[branch.zero].terminator, pre_ir.Fail)


def test_the_executed_constant_block_is_the_one_a_load_reads(tmp_path):
    """`bytec_0` after `b l` skips the second `bytecblock`: it reads 0x2222 (line 2),
    not the textually-later block's 0x11."""
    pre = _lifted(tmp_path, ACCEPTS["F12_dead_second_block"])
    assert set(pre.const_block_lines.values()) == {2}, pre.const_block_lines
    assert pre.pass_stats.get("eof_arms") == 0 and pre.pass_stats.get("bytes_exits") == 0


def test_a_load_whose_block_differs_by_path_is_not_resolved(tmp_path):
    """Two blocks reach the load on different paths: no single constant, so the lift
    leaves it unknown rather than picking either."""
    pre = _lifted(tmp_path, "#pragma version 14\ntxn NumAppArgs\nbnz b\nintcblock 5\nb l\n"
                            "b:\nintcblock 6\nl:\nintc_0\npushint 5\n==")
    assert not pre.const_block_lines
    assert _exit_values(pre)
