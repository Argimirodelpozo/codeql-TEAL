"""Pins for the 2026-10-10 lift taint + guard engine review (`lift/guards.py`,
`lift/fund_flow.py`). One test per defect, controls folded in; the verdict
shapes themselves are benchmark fixtures (`tests/benchmark/tainted-fund-flow`),
these pin what the benchmark cannot express — WHICH guard credited, the
canonical input-slot keys, the post-sink guard kinds, and the engine-level
rules behind the fixtures."""
from __future__ import annotations

from pathlib import Path

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.lift import build_lifter, fund_flow, guards, pre_ir
from tealql.tealtools.lift.fund_flow import tainted_fund_flows, tainted_state_writes

_BENCH = Path(__file__).resolve().parent / "benchmark"
_PAY_ACCT1 = ("itxn_begin\nint pay\nitxn_field TypeEnum\ntxna Accounts 1\n"
              "itxn_field Receiver\nint 1000\nitxn_field Amount\nitxn_submit\n")
_PAY_AMOUNT = ("itxn_begin\nint pay\nitxn_field TypeEnum\nglobal CreatorAddress\n"
               "itxn_field Receiver\nitxn_field Amount\nitxn_submit\n")


def _lifter(teal: str, tmp_path: Path, name: str = "prog.teal"):
    p = tmp_path / name
    p.write_text(teal)
    prog = SSAProgram(str(p))
    prog.propagate_constants()
    return build_lifter(prog)


def _flows(teal: str, tmp_path: Path, name: str = "prog.teal"):
    return tainted_fund_flows(_lifter(teal, tmp_path, name))


def _bench(det: str, kind: str, name: str):
    prog = SSAProgram(str(_BENCH / det / kind / name))
    prog.propagate_constants()
    return build_lifter(prog)


def _verdict(flows) -> dict:
    """``{field: guarded}`` — every sink must be present (a lost SINK is not a
    guarded one)."""
    return {f.field: f.guarded for f in flows}


def _input_guards(flows, field):
    return [g for f in flows if f.field == field for g in f.guards if g.checks_input]


def test_guard_credit_is_coverage_of_every_tainted_leaf(tmp_path):
    """Finding 2. `Amount = btoi(arg0) + btoi(arg1)` under `assert(btoi(arg0)
    <= 100)`: the assert DOES check one tainted register, so per-guard credit
    read the sink as guarded while arg1 stayed free. The verdict is now
    coverage: every guard reports WHAT it constrains (`Guard.regs`/`keys`) and
    the sink needs every tainted leaf covered. The partial check's input credit
    is withdrawn (the finding shows no `tainted-input` guard at all); the sum
    bound credits the root and covers both leaves; the interprocedural twin's
    callee sink gets no `caller` credit."""
    one = tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "two_tainted_terms_one_bounded.teal"))
    assert _verdict(one) == {"Amount": False}
    assert not _input_guards(one, "Amount"), "a partial check must not read as a value guard"

    both = tainted_fund_flows(_bench("tainted-fund-flow", "safe", "sum_of_two_inputs_bounded.teal"))
    assert _verdict(both) == {"Amount": True}
    (g,) = _input_guards(both, "Amount")
    assert g.kind == "assert" and g.regs, "the sum register is what the bound covers"
    assert g.keys == {("txn", "ApplicationArgs", "0"), ("txn", "ApplicationArgs", "1")}, \
        "below the comparison both operands of the sum are constrained"

    inter = tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "two_tainted_terms_interproc.teal"))
    assert _verdict(inter) == {"Amount": False}
    assert not any(g.kind == "caller" and g.checks_input for f in inter for g in f.guards)
    assert not any(f.param_derived for f in inter), "pay() is called: the caller was inspected"


def test_input_slot_keys_are_canonical_over_spelling_and_stack_index(tmp_path):
    """Findings 5 + 11. `txn ApplicationArgs 1` and `txna ApplicationArgs 1`
    are one slot; `gtxna 0 ApplicationArgs 1` and `int 0; gtxnsa
    ApplicationArgs 1` are one slot; a stack index that is not a constant
    carries NO key (the read falls back to register identity), so txn 0's arg
    cannot credit txn 1's."""
    lf = _lifter("#pragma version 10\ntxn ApplicationArgs 1\ntxna ApplicationArgs 1\n"
                 "gtxna 0 ApplicationArgs 1\nint 0\ngtxnsa ApplicationArgs 1\n"
                 "int 1\ngtxnsa ApplicationArgs 1\ntxn GroupIndex\ngtxnsa ApplicationArgs 1\n"
                 "int 1\ntxnas ApplicationArgs\nint 0\nint 1\ngtxnsas ApplicationArgs\n"
                 "pop\npop\npop\npop\npop\npop\npop\npop\nint 1\nreturn\n", tmp_path)
    reads = [o.source for b in pre_ir.blocks(lf.subs) for o in b.ops
             if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic)
             and guards.source_label(o.source) is not None]
    keys = {(r.op, tuple(str(i) for i in r.immediates), tuple(str(a) for a in r.args)): guards._input_key(r)
            for r in reads}
    k = {spelling[0] + (" " + " ".join(spelling[2]) if spelling[2] else ""): v for spelling, v in keys.items()}
    assert k["txn"] == k["txna"] == ("txn", "ApplicationArgs", "1")
    assert k["gtxna"] == k["gtxnsa 0u"] == ("gtxn", "0", "ApplicationArgs", "1")
    assert k["gtxnsa 1u"] == ("gtxn", "1", "ApplicationArgs", "1") != k["gtxnsa 0u"]
    assert k["txnas 1u"] == k["txn"], "a constant stack index folds into the slot"
    assert k["gtxnsas 1u 0u"] == ("gtxn", "0", "ApplicationArgs", "1"), "TOP-FIRST: array index above txn index"
    # A COMPUTED index keys on its register: the same register is the same
    # slot (`txnas Assets i` in a guard and in the sink), another register —
    # or a constant — is not.
    dynamic = [v for s, v in keys.items() if s[0] == "gtxnsa" and s[2] and not s[2][0].endswith("u")]
    assert len(dynamic) == 1 and dynamic[0][0] == "gtxn" and dynamic[0][1][0] == "reg"
    assert dynamic[0] not in (k["gtxnsa 0u"], k["gtxnsa 1u"]), "a computed txn index must not share a constant key"
    same = _lifter("#pragma version 10\ntxn NumAppArgs\ndup\ntxnas Assets\npop\ntxnas Assets\npop\n"
                   "txn NumAppArgs\ntxnas Assets\npop\nint 1\nreturn\n", tmp_path, "same.teal")
    dyn = [guards._input_key(o.source) for b in pre_ir.blocks(same.subs) for o in b.ops
           if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic)
           and o.source.op == "txnas"]
    assert dyn[0] == dyn[1] is not None and dyn[2] != dyn[0], "same index register = same slot; a fresh read is not"

    # The verdicts the keys decide: same slot credits, colliding slot does not.
    assert _verdict(tainted_fund_flows(_bench("tainted-fund-flow", "safe", "txn_vs_txna_same_slot.teal"))) == {"Amount": True}
    assert _verdict(tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "gtxnsa_stack_index_collision.teal"))) == {"Amount": False}


def test_post_sink_exit_and_forced_branch_gate_the_submit(tmp_path):
    """Findings 9 + 10. After the submit, a non-constant `exit v` is `assert
    v`, and a branch whose other edge reaches ONLY failing exits is forced;
    both revert the inner txn when the sender check fails. The same assert in
    the CALLER, post-dominating the `callsub`, pins the callee's sink. Control:
    a post-sink branch whose other edge SUCCEEDS proves nothing."""
    exit_cmp = tainted_fund_flows(_bench("tainted-fund-flow", "safe", "post_sink_return_verdict.teal"))
    assert _verdict(exit_cmp) == {"Receiver": True}
    assert [g.kind for f in exit_cmp for g in f.guards if g.checks_sender] == ["exit-after"]

    branch_err = tainted_fund_flows(_bench("tainted-fund-flow", "safe", "post_sink_branch_to_err.teal"))
    assert _verdict(branch_err) == {"Receiver": True}
    assert [(g.kind, g.polarity) for f in branch_err for g in f.guards if g.checks_sender] == [("branch-after", "true")]

    caller = tainted_fund_flows(_bench("tainted-fund-flow", "safe", "post_call_assert_in_caller.teal"))
    assert _verdict(caller) == {"Receiver": True}
    assert [g.kind for f in caller for g in f.guards if g.checks_sender] == ["caller"]

    selects = ("#pragma version 10\n" + _PAY_ACCT1 + "txn Sender\nglobal CreatorAddress\n==\n"
               "bnz ok\nint 1\nreturn\nok:\nint 1\nreturn\n")
    assert _verdict(_flows(selects, tmp_path)) == {"Receiver": False}, \
        "a post-sink branch with a succeeding other edge is not a guard"


def test_dead_itxn_field_write_is_not_a_sink(tmp_path):
    """Finding 12. The AVM keeps the LAST value set before `itxn_submit`: an
    attacker Receiver overwritten unconditionally in the same window never
    reaches the submit. Controls: attacker LAST stays a finding at its own
    line; an overwrite on another path (conditional) leaves the first write
    live; a submit between the two writes makes both live."""
    assert tainted_fund_flows(_bench("tainted-fund-flow", "safe", "receiver_overwritten_before_submit.teal")) == []
    last = tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "receiver_overwritten_by_attacker.teal"))
    assert [(f.field, f.line, f.guarded) for f in last] == [("Receiver", 9, False)]

    conditional = ("#pragma version 10\nitxn_begin\nint pay\nitxn_field TypeEnum\n"
                   "txna Accounts 1\nitxn_field Receiver\ntxn NumAppArgs\nint 2\n==\nbz submit\n"
                   "global CurrentApplicationAddress\nitxn_field Receiver\nsubmit:\n"
                   "int 1000\nitxn_field Amount\nitxn_submit\nint 1\nreturn\n")
    assert _verdict(_flows(conditional, tmp_path)) == {"Receiver": False}
    two_itxns = ("#pragma version 10\nitxn_begin\nint pay\nitxn_field TypeEnum\n"
                 "txna Accounts 1\nitxn_field Receiver\nint 1000\nitxn_field Amount\nitxn_submit\n"
                 "itxn_begin\nint pay\nitxn_field TypeEnum\nglobal CurrentApplicationAddress\n"
                 "itxn_field Receiver\nint 1\nitxn_field Amount\nitxn_submit\nint 1\nreturn\n")
    assert [f.line for f in _flows(two_itxns, tmp_path)] == [6]


def test_input_pin_against_own_state_needs_authority_for_addresses(tmp_path):
    """Finding 1 (a07). `assert(Accounts[1] == app_global_get "payee")` pins
    the payee to state ANYONE can set — no guard. The same pin with a
    creator-guarded writer is one (the storage-authority rule the sender pins
    already use). Scope: ADDRESS-typed pins only — `assert(key ==
    app_global_get "allowed_key")` on a bytes key stays credited even though
    the program's own dynamic-key write leaves the slot unprovable."""
    anyone = tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "input_eq_state_unguarded_writer.teal"))
    assert _verdict(anyone) == {"Receiver": False}
    assert not _input_guards(anyone, "Receiver")

    guarded_writer = (
        '#pragma version 10\ntxna ApplicationArgs 0\nbyte "set"\n==\nbnz set_payee\n'
        'txna Accounts 1\nbyte "payee"\napp_global_get\n==\nassert\n' + _PAY_ACCT1 +
        'int 1\nreturn\nset_payee:\ntxn Sender\nglobal CreatorAddress\n==\nassert\n'
        'byte "payee"\ntxna Accounts 1\napp_global_put\nint 1\nreturn\n')
    assert _verdict(_flows(guarded_writer, tmp_path)) == {"Receiver": True}

    key_pin = tainted_state_writes(_bench("tainted-state-write", "safe", "checked_key.teal"))
    assert key_pin and all(f.guarded for f in key_pin)


def test_scratch_round_trip_needs_the_unique_reaching_store(tmp_path):
    """Finding 14. A second `store 0` in a dead-end branch cannot run between
    the dominating store and the load, so the round-trip still proves the
    guard. Controls: a second store on a path that REACHES the load (the
    attacker picks that path) and a subroutine call between store and load
    (a callee may write the slot) both keep the refusal."""
    assert _verdict(tainted_fund_flows(_bench("tainted-fund-flow", "safe", "guard_via_scratch_dead_end_store.teal"))) == {"Receiver": True}
    assert _verdict(tainted_fund_flows(_bench("tainted-fund-flow", "vuln", "guard_via_scratch_overwritten_on_path.teal"))) == {"Receiver": False}
    call_between = ("#pragma version 10\ntxn Sender\nglobal CreatorAddress\n==\nstore 0\n"
                    "callsub noop\nload 0\nassert\n" + _PAY_ACCT1 + "int 1\nreturn\n"
                    "noop:\nproto 0 0\nint 1\nstore 0\nretsub\n")
    assert _verdict(_flows(call_between, tmp_path)) == {"Receiver": False}


def test_nonzero_checks_are_exclusions_not_value_guards(tmp_path):
    """Finding 7. `assert(x)`, `assert(x > 0)` and `assert(x >= 1)` are the
    predicate `x != 0`, which the engine already refuses as a value guard; the
    three spellings now agree. Control: `x >= 2` and `x <= 100` are bounds."""
    def prog(check):
        return ("#pragma version 10\ntxna ApplicationArgs 0\nbtoi\ndup\n" + check + "\n"
                + _PAY_AMOUNT + "int 1\nreturn\n")

    for check in ("assert", "int 0\n>\nassert", "int 1\n>=\nassert", "int 0\n!=\nassert"):
        assert _verdict(_flows(prog(check), tmp_path)) == {"Amount": False}, check
    for check in ("int 2\n>=\nassert", "int 100\n<=\nassert"):
        assert _verdict(_flows(prog(check), tmp_path)) == {"Amount": True}, check


def test_returned_parameter_routes_to_the_call_site_argument(tmp_path):
    """Finding 8. `clamp(x)` asserts `p <= 100` and returns `p`: the result's
    def-walk continues into the call site's `x`, where the callee-side
    transfer credits it. Control: a pass-through helper WITHOUT the assert
    stays a finding, and so does a helper that asserts a DIFFERENT param."""
    ok = tainted_fund_flows(_bench("tainted-fund-flow", "safe", "sanitizer_returns_param.teal"))
    assert _verdict(ok) == {"Amount": True}
    assert [g.kind for g in _input_guards(ok, "Amount")] == ["callee"]

    def prog(callee):
        return ("#pragma version 10\ntxna ApplicationArgs 1\nbtoi\nint 5\ncallsub f\n"
                + _PAY_AMOUNT + "int 1\nreturn\nf:\nproto 2 1\n" + callee + "frame_dig -2\nretsub\n")

    assert _verdict(_flows(prog(""), tmp_path)) == {"Amount": False}
    assert _verdict(_flows(prog("frame_dig -1\nint 100\n<=\nassert\n"), tmp_path)) == {"Amount": False}
    assert _verdict(_flows(prog("frame_dig -2\nint 100\n<=\nassert\n"), tmp_path)) == {"Amount": True}


def test_classify_cache_is_keyed_on_the_taint_oracle(tmp_path):
    """The comparison's other-operand rule (finding 3) reads the taint map, so
    a `_GuardDefinitions` memo must not serve a verdict computed under a
    different taint view: with the bound's register tainted the credit is
    refused, with it clean the same comparison credits."""
    lf = _lifter("#pragma version 10\ntxna ApplicationArgs 0\nbtoi\ndup\n"
                 "txna ApplicationArgs 1\nbtoi\n<=\nassert\n" + _PAY_AMOUNT + "int 1\nreturn\n",
                 tmp_path)
    defs = fund_flow._def_map(lf)
    ops = [o for b in pre_ir.blocks(lf.subs) for o in b.ops
           if isinstance(o, pre_ir.Assignment) and isinstance(o.source, pre_ir.Intrinsic)]
    cmp = next(o for o in ops if o.source.op == "<=")

    def _reads_slot(reg, slot):
        src = defs[id(reg)].source                     # the btoi
        read = defs[id(src.args[0])].source            # the txna
        return [str(i) for i in read.immediates] == ["ApplicationArgs", slot]

    amount = next(a for a in cmp.source.args if _reads_slot(a, "0"))
    bound = next(a for a in cmp.source.args if _reads_slot(a, "1"))
    both_tainted = {id(amount): {"ApplicationArgs"}, id(bound): {"ApplicationArgs"}}
    only_amount = {id(amount): {"ApplicationArgs"}}
    refused = fund_flow._classify("assert", None, cmp.targets[0], defs, {id(amount)}, set(),
                                  None, both_tainted)
    assert not refused.checks_input
    credited = fund_flow._classify("assert", None, cmp.targets[0], defs, {id(amount)}, set(),
                                   None, only_amount)
    assert credited.checks_input and credited.regs == {id(amount)}
