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
- F21 (2026-10-25): a program may END inside a subroutine (eval.go checks the data
  stack, never the call stack). Such exits were refused, and a `callsub` as the last
  instruction of a subroutine RETURNED to its caller. The whole stack is the frame's
  height (the caller's depth at the `callsub`) plus what the body holds, which also
  decides a legacy frame's floor ("frame_dig below stack"). A `proto` frame's `retsub`
  checks need only the frame; `retsub` in main and a `proto` short of arguments fail.
- F22 (2026-10-25): a stack shuffle short of operands in main was dropped, not failed.
- F23 (2026-10-26): `bitlen` takes either type (a byteslice is a big-endian number); the
  lift typed its operand uint64, so `byte 0x01; bitlen` lifted with an unknown operand.
- F24 (2026-10-26): a CONSTANT of the wrong AVM type at an operand the chain checks fails
  there (step(): "+ arg 0 wanted uint64 but got []byte"; opEq: "cannot compare"; a uint64
  `itxn_field` setter: "... is not a uint64"). The lift made the constant an unknown.
- F25 (2026-10-26): the grammar rejected `#pragma autosalt` (v13) and a `match` or
  `switch` with no labels, and dropped the span.
- F26 (2026-10-26): `match` arms no key can take (opMatch skips keys of the other type
  than the matched value) kept a join the lowering could not type; dead blocks are now
  pruned before lowering.
- F27 (2026-10-26): a recursive legacy subroutine's arity walk followed its `retsub`
  into its own call's continuation, at the depth after the return: go's factorial
  (TestSubroutine) took two arguments for one.
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
    return _exits(pre.main)


def _exits(sub) -> list:
    """The terminators of ``sub``'s blocks reachable from its entry block."""
    body = {b.id: b for b in sub.body}
    seen, todo, out = set(), [sub.body[0].id], []
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
    # a stack underflow in main ("stack underflow in =="): straight-line (the entry
    # block's dip check already failed it -- a control), and after a branch, which
    # TestAppReadLocalState hit: the lift built a one-operand `==` there
    "F4_stack_underflow": ("#pragma version 14\npushint 1\n==", None),
    "F4_stack_underflow_after_a_branch": ("#pragma version 14\npushint 1\nbnz l\nerr\nl:\n"
                                          "pushint 1\n==", None),
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
    # the exit sits at the END of the program: the line after the last instruction
    # (`err`, line 5), which no source block starts at -- not the lowering's default 1
    assert body[branch.non_zero].comment == "L6"


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


def test_every_synthetic_block_has_a_source_line(tmp_path):
    """Blocks the lift adds (an EOF exit, the Fail a doomed edge is retargeted to) carry
    a line: the lowering otherwise defaults them to line 1, which a consumer that maps
    blocks onto source (avm-prover's exact budget schedule) refuses, or double-charges
    where line 1 is an instruction. The Fail for a doomed edge takes the failing block's."""
    pre = _lifted(tmp_path, ALWAYS_PANIC["F4_stack_underflow_after_a_branch"][0])
    body = {b.id: b for b in pre.main.body}
    fails = [b for b in body.values() if isinstance(b.terminator, pre_ir.Fail) and not b.ops
             and b.terminator.error_message == "stack underflow on this path"]
    assert fails and all(b.comment == "L5" for b in fails), [(b.id, b.comment) for b in fails]
    assert all(b.comment for b in pre.main.body), [b.id for b in pre.main.body if not b.comment]



# --- F21: ending inside a subroutine ----------------------------------------------------
# name -> (source, the subroutine that ends the program, what its exits must be): a Fail
# message (the chain panics there), "exit" (a ProgramExit of a known value), or
# "refused" (a ProgramExit of Undefined: the depth is not known, so nothing is guessed).
# Chain verdicts: go-algorand 3490087555c5 (the first two are TestProtoChecks programs).

SUB_EXITS = {
    "ends_inside_a_subroutine": ("#pragma version 8\ncallsub label1\nlabel1:\nproto 0 0\n"
                                 "pushint 1", "label1", "exit"),
    "ends_inside_a_subroutine_over_a_residual": ("#pragma version 8\nint 9\ncallsub f\nf:\n"
                                                 "proto 0 0\nint 1", "f",
                                                 "stack len is 2 instead of 1"),
    "ends_inside_a_subroutine_with_its_argument": ("#pragma version 8\nint 3\ncallsub f\nf:\n"
                                                   "proto 1 0\nframe_dig -1", "f",
                                                   "stack len is 2 instead of 1"),
    "a_legacy_subroutine_ends_on_its_arguments": ("#pragma version 8\nint 5\nint 6\n"
                                                  "callsub f\nf:\n+", "f", "exit"),
    "a_branch_to_the_end_inside_a_subroutine": ("#pragma version 8\ncallsub f\nf:\nproto 0 0\n"
                                                "int 1\nint 1\nbnz end\nerr\nend:", "f", "exit"),
    "a_last_callsub_inside_a_subroutine": ("#pragma version 8\ncallsub outer\npushint 1\n"
                                           "return\ninner:\nretsub\nouter:\ncallsub inner",
                                           "outer", "stack len is 0 instead of 1"),
    "a_nested_last_callsub_ends_on_its_result": ("#pragma version 8\ncallsub f\ng:\n"
                                                 "proto 0 1\nint 7\nretsub\nf:\nproto 0 0\n"
                                                 "callsub g", "f", "exit"),
    "two_calls_at_one_depth": ("#pragma version 8\nint 1\nbnz x\ncallsub f\nx:\ncallsub f\n"
                               "f:\nproto 0 0\nint 1", "f", "exit"),
    # not knowable from one frame: refused, as before
    "two_calls_at_different_depths": ("#pragma version 8\nint 1\nbnz x\nint 4\ncallsub f\n"
                                      "x:\ncallsub f\nf:\nproto 0 0\nint 1", "f", "refused"),
    "the_one_value_is_the_callers": ("#pragma version 8\nint 1\ncallsub f\nf:\nproto 0 0",
                                     "f", "refused"),
    "recursion": ("#pragma version 8\nint 2\ncallsub f\nf:\nproto 1 0\nframe_dig -1\n"
                  "bz done\nframe_dig -1\nint 1\n-\ncallsub f\ndone:\nint 1", "f", "refused"),
}


@pytest.mark.parametrize("name", sorted(SUB_EXITS))
def test_a_program_may_end_inside_a_subroutine(tmp_path, name):
    teal, where, want = SUB_EXITS[name]
    pre = _lifted(tmp_path, teal)
    sub = next(s for s in pre.subroutines if s.id == where)
    exits = [t.result for t in _exits(sub) if isinstance(t, pre_ir.ProgramExit)]
    fails = [t.error_message for t in _exits(sub) if isinstance(t, pre_ir.Fail)]
    if want == "refused":
        assert exits and all(isinstance(v, pre_ir.Undefined) for v in exits), exits
    elif want == "exit":
        assert exits and not any(isinstance(v, pre_ir.Undefined) for v in exits), exits
    else:
        assert not exits and want in fails, (exits, fails)
    assert pre.pass_stats.get("frame_exits", 0) == (0 if want == "refused" else 1)


# Frame panics the lift now decides (they lifted to Undefined values, which the consumer
# refused): main's every path fails, or the named subroutine's exits are all `Fail`.
FRAME_PANICS = {
    # go: TestFrameAccessBelowStack -- a legacy frame's floor is its caller's depth
    "frame_dig_below_the_stack": ("#pragma version 8\npushint 1\ncallsub label1\nlabel1:\n"
                                  "frame_dig -10", None, None),
    "frame_bury_below_the_stack": ("#pragma version 8\npushint 1\ncallsub label1\nlabel1:\n"
                                   "frame_bury -10", None, None),
    # go: TestSubroutine
    "retsub_in_main": ("#pragma version 5\npushint 1\nretsub", None,
                       "retsub with empty callstack"),
    # go: TestProtoChecks, TestForgetReturn -- opRetSub on a proto frame
    "retsub_below_the_frame": ("#pragma version 8\npushint 5\npushint 10\ncallsub label1\n"
                               "pushint 1\nreturn\nlabel1:\nproto 2 1\n+\nretsub", "label1",
                               "retsub executed with stack below frame. Did you pop args?"),
    "retsub_with_no_returns": ("#pragma version 8\npushint 5\npushint 10\ncallsub label1\n"
                               "pushint 1\nreturn\nlabel1:\nproto 2 1\nretsub", "label1",
                               "retsub executed with no return values on stack. proto declared 1"),
    "retsub_short_of_returns": ("#pragma version 11\nb label1\nlabel2:\nproto 0 3\npushint 1\n"
                                "pushint 2\nretsub\nlabel1:\ncallsub label2\n!", "label2",
                                "retsub executed with 2 return values on stack. proto declared 3"),
    # go: TestProtoChecks -- "callsub to proto that requires 10 args with stack height 0"
    "a_call_short_of_proto_args": ("#pragma version 8\ncallsub toodeep\ntoodeep:\nproto 10 1\n"
                                   "pushint 1\nreturn", None, None),
}


@pytest.mark.parametrize("name", sorted(FRAME_PANICS))
def test_a_frame_panic_lifts_to_fail(tmp_path, name):
    teal, where, message = FRAME_PANICS[name]
    pre = _lifted(tmp_path, teal)
    sub = pre.main if where is None else next(s for s in pre.subroutines if s.id == where)
    terms = _exits(sub)
    fails = [t.error_message for t in terms if isinstance(t, pre_ir.Fail)]
    assert fails and not any(isinstance(t, (pre_ir.ProgramExit, pre_ir.SubroutineReturn))
                             for t in terms), [t.render() for t in terms]
    if message is not None:
        assert message in fails, fails


def test_a_shuffle_short_of_operands_in_main_fails(tmp_path):
    """F22. After `int 1; bnz x` the stack is empty at `x`, so `swap` underflows on chain
    ("stack underflow in swap"); the lift dropped the shuffle and exited with the 1."""
    pre = _lifted(tmp_path, "#pragma version 8\nint 1\nbnz x\nerr\nx:\nswap\nint 1")
    assert not _exit_values(pre), [t.render() for t in _main_exits(pre)]
    assert "stack underflow on this path" in _fail_messages(pre), _fail_messages(pre)


# F24: a constant the op cannot take. (TEAL, go-algorand's error).
TYPE_PANICS = {
    # go: TestWrongStackTypeRuntime2 -- eval.go step()
    "plus_on_bytes": ("#pragma version 10\npushbytes 0x1234\npushint 1\n+",
                      "+ arg 0 wanted uint64 but got []byte"),
    # go: TestAssert (v14: the op table stops at v13; v14 changes no operand type)
    "assert_on_bytes": ("#pragma version 14\npushbytes 0x6a6f686e\nassert\npushint 1",
                        "assert arg 0 wanted uint64 but got []byte"),
    # go: TestEqMismatch / TestNeqMismatch -- opEq
    "eq_across_types": ("#pragma version 14\npushbytes 0x1234\npushint 1\n==",
                        "cannot compare ([]byte to uint64)"),
    "neq_across_types_from_constant_blocks": (
        "#pragma version 1\nintcblock 1\nbytecblock 0x1234\nbytec_0\nintc_0\n!=",
        "cannot compare ([]byte to uint64)"),
    # go: TestWrongStackTypeRuntime -- the model dropped this panic ("type-collapse")
    "sha256_on_uint64": ("#pragma version 12\npushint 1\nsha256\nlen",
                         "sha256 arg 0 wanted []byte but got uint64"),
    # go: TestCurrentInnerTypes -- stackIntoTxnField reads sv.uint()
    "uint64_itxn_field_given_bytes": (
        "#pragma version 14\nitxn_begin\npushbytes 0x706179\nitxn_field TypeEnum\n"
        "itxn_submit\npushint 1", "[]byte{0x70, 0x61, 0x79} is not a uint64"),
    "switch_on_bytes": ("#pragma version 9\npushbytes 0x01\nswitch\npushint 1",
                        "switch arg 0 wanted uint64 but got []byte"),
    # before v4 `balance` takes an Accounts index only
    "v3_balance_of_an_address": ("#pragma version 3\npushbytes 0x" + "00" * 32 + "\nbalance",
                                 "balance arg 0 wanted uint64 but got []byte"),
    "constant_moved_by_a_shuffle": ("#pragma version 10\npushint 1\npushbytes 0x01\nswap\n"
                                    "concat\nlen", "concat arg 1 wanted []byte but got uint64"),
}


@pytest.mark.parametrize("name", sorted(TYPE_PANICS))
def test_a_constant_the_op_cannot_take_fails_there(tmp_path, name):
    teal, message = TYPE_PANICS[name]
    pre = _lifted(tmp_path, teal)
    assert not _exit_values(pre), [t.render() for t in _main_exits(pre)]
    assert message in _fail_messages(pre), _fail_messages(pre)
    assert pre.pass_stats["type_panics"] == 1


# Controls: the chain does not fail on a type here, or the lift cannot know it does.
NO_TYPE_PANIC = {
    # from v4 `balance` takes an address or an index
    "v4_balance_of_an_address": "#pragma version 4\npushbytes 0x" + "00" * 32 + "\nbalance",
    # a byteslice field takes a uint64's nil bytes: `Note` is then empty
    "uint64_into_a_bytes_itxn_field": ("#pragma version 14\nitxn_begin\npushint 5\n"
                                       "itxn_field Note\nitxn_submit\npushint 1"),
    # a register's type is recovered, not certain: no claim
    "register_operand": "#pragma version 10\ntxna ApplicationArgs 0\npushint 1\n+",
    "same_type_compare": "#pragma version 10\npushbytes 0x01\npushbytes 0x01\n==",
    "match_keys_of_another_type": ("#pragma version 8\npushbytes 0x30\npushint 1\nmatch l1\n"
                                   "pushint 1\nreturn\nl1:\nerr"),
}


@pytest.mark.parametrize("name", sorted(NO_TYPE_PANIC))
def test_no_type_panic_is_claimed_where_the_chain_does_not_fail_or_cannot_be_known(
        tmp_path, name):
    pre = _lifted(tmp_path, NO_TYPE_PANIC[name])
    assert pre.pass_stats["type_panics"] == 0
    assert not any("wanted" in m or "cannot compare" in m or "is not a uint64" in m
                   for m in _fail_messages(pre)), _fail_messages(pre)


def test_the_type_check_reads_no_version_past_the_one_checked():
    """v14 is read off the v13 table (checked against go-algorand's v14 op by op); a later
    version could widen an operand, as v4 did `balance`'s, so it makes no claim."""
    from tealql.tealtools.lift.lift import _type_panic
    ops = [pre_ir.BytesConstant("0x01"), pre_ir.UInt64Constant(1)]
    assert _type_panic("+", "", ops, 14) == "+ arg 0 wanted uint64 but got []byte"
    assert _type_panic("+", "", ops, 15) is None
    assert _type_panic("+", "", ops, None) is None


def test_bitlen_of_a_byteslice_keeps_its_operand(tmp_path):
    """F23. go: TestBitLen -- `bitlen` of 0x0100 is 9 (eval.go opBitLen)."""
    pre = _lifted(tmp_path, "#pragma version 10\npushbytes 0x0100\nbitlen\npushint 9\n==")
    ops = [op for b in pre.main.body for op in b.ops]
    text = " ".join(op.render() for op in ops)
    assert "(bitlen 0x0100)" in text and "undefined" not in text, text
    assert _exit_values(pre)


GRAMMAR_GAPS = {
    # F25. go: TestMatch / TestSwitchInt / every v13+ disassembly of a LogicSig
    "zero_label_match": ("#pragma version 8\npushint 0\nmatch\npushint 1", True),
    "zero_label_switch": ("#pragma version 9\npushint 0\nswitch \npushint 1", True),
    "zero_label_match_short_of_its_value": ("#pragma version 11\nmatch \npushint 1", False),
    "zero_label_switch_short_of_its_index": ("#pragma version 9\nswitch\npushint 1", False),
    "autosalt_pragma": ("#pragma version 14\n#pragma autosalt false\npushint 1", True),
}


@pytest.mark.parametrize("name", sorted(GRAMMAR_GAPS))
def test_valid_teal_the_grammar_rejected_parses(tmp_path, name):
    from tealql.tealtools.ast.parse import parse_nodes
    teal, approves = GRAMMAR_GAPS[name]
    diags: list = []
    parse_nodes({"prog.teal": teal + "\n"}, diagnostics=diags)
    assert not diags, diags
    pre = _lifted(tmp_path, teal)
    if approves:
        assert [v.value for v in _exit_values(pre)] == [1], [t.render() for t in _main_exits(pre)]
    else:
        assert not _exit_values(pre) and _fail_messages(pre)


def test_match_arms_no_key_can_take_are_dead(tmp_path):
    """F26. go: TestMatch -- an integer never matches byteslice keys, so the arms and the
    join only they feed are dead; the lowering failed on that join ("unexpected any
    type"). The program falls through to `return 1`."""
    from tealql.tealtools.lift.to_puya_ir import render
    teal = ("#pragma version 10\nintcblock 1 0\npushbytes 0x30\npushbytes 0x31\nintc_0\n"
            "match label1 label2\nintc_0\nreturn\nlabel1:\nintc_1\nlabel2:\nintc_1\n")
    pre = _lifted(tmp_path, teal)
    assert [v.value for v in _exit_values(pre)] == [1]
    assert pre.pass_stats["unreachable_blocks"] >= 2
    p = tmp_path / "prog.teal"
    assert "exit 1u" in render(SSAProgram(str(p)))


def test_a_match_keeps_the_keys_that_can_match(tmp_path):
    """A byteslice value against keys 0x30 (bytes) and 7 (uint64): only 0x30 can match."""
    pre = _lifted(tmp_path, "#pragma version 8\npushbytes 0x30\npushint 7\npushbytes 0x30\n"
                            "match l1 l2\npushint 1\nreturn\nl1:\npushint 0\nreturn\n"
                            "l2:\npushint 2\nreturn")
    sw = pre.main.body[0].terminator
    assert isinstance(sw, pre_ir.Switch) and [k for k, _ in sw.cases] == ["0x30"], sw.render()


RECURSIVE_LEGACY = {
    # go: TestSubroutine -- fact(5) == 120
    "factorial": ("#pragma version 5\nb label1\nlabel3:\ndup\npushint 2\n<\nbz label2\nretsub\n"
                  "label2:\ndup\npushint 1\n-\ncallsub label3\n*\nretsub\nlabel1:\npushint 5\n"
                  "callsub label3\npushint 120\n==", "label3"),
    # the same shape with the base case falling through first: f(n) = f(n-1), f(0) = 0
    "drops_its_saved_value": ("#pragma version 5\nint 3\ncallsub f\nint 0\n==\nreturn\nf:\n"
                              "dup\nbnz rec\nretsub\nrec:\ndup\nint 1\n-\ncallsub f\nswap\n"
                              "pop\nretsub", "f"),
}


@pytest.mark.parametrize("name", sorted(RECURSIVE_LEGACY))
def test_a_recursive_legacy_subroutine_takes_one_argument(tmp_path, name):
    """F27. A `retsub` leaves the subroutine: its CFG successors are its callers'
    continuations, which the walk must not enter (as the SSA's `stacksim._isucc` does not).
    Through its own recursive call's continuation, `*` (or `swap`) dipped two below."""
    teal, sub = RECURSIVE_LEGACY[name]
    pre = _lifted(tmp_path, teal)
    s = next(s for s in pre.subroutines if s.id == sub)
    assert (len(s.parameters), len(s.returns)) == (1, 1)
