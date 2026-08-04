"""Regression tests for representation fixes in the TEAL->Puya-IR lift
(2026-07-23 lift-representation review):

  * `sink_mixed_phi_scratch_stores` must NOT sink a scratch store into a merge
    block's predecessors unless the store is UNCONDITIONALLY reached from the
    merge (post-dominance) — otherwise the sunk store runs on a path the original
    never did, changing the slot's final value a cross-group `gload` observes.
  * `avm()` / `_BYTES_FAMILY` must agree that `string` is bytes-backed, so a phi
    join of two genuinely-bytes types can't cross the divide and default to uint64.
  * `_unify_comparison_operands` retypes a cross-family `==` operand ONLY on HARD
    (const / field / typed-op) evidence, never on a REFINED/BASE guess that might
    itself be the mistyped side.
"""
import pytest

pytest.importorskip("puya")  # pre_ir package __init__ eagerly imports the lift

from tealql.tealtools.avm import avm, _multi_out_type  # noqa: E402
from tealql.tealtools.lift.type_recovery import (  # noqa: E402
    _avm_join,
    _unify_comparison_operands,
)
from tealql.tealtools.lift.transforms import sink_mixed_phi_scratch_stores  # noqa: E402
from tealql.tealtools.lift import pre_ir  # noqa: E402


def _r(name, ir_type="uint64"):
    return pre_ir.Register(name, 0, ir_type)


def _store(slot, val):
    return pre_ir.IntrinsicOp(pre_ir.Intrinsic("store", [slot], [val]))


# --------------------------------------------------------------------------
# sink transform — post-dominance guard
# --------------------------------------------------------------------------


def _mixed_phi_block(bid, preds, va, vb, term):
    """Merge block `bid` with a mixed-AVM-type phi p = φ(va@preds[0], vb@preds[1])."""
    p = _r("p", "uint64")   # phi register; the ARG types make it mixed
    phi = pre_ir.Phi(p, [pre_ir.PhiArgument(va, preds[0]),
                         pre_ir.PhiArgument(vb, preds[1])])
    return pre_ir.BasicBlock(id=bid, phis=[phi], ops=[], terminator=term), p


def test_sink_refuses_when_store_not_post_dominated():
    """B branches (cond) — the store lives on only ONE arm. Sinking would append
    the store to B's predecessors, running it on BOTH arms and corrupting the
    other arm's slot value. The transform must decline to sink."""
    va, vb, cond = _r("va", "uint64"), _r("vb", "bytes"), _r("cond", "uint64")
    B, p = _mixed_phi_block(2, [0, 1], va, vb,
                            pre_ir.ConditionalBranch(cond, 3, 4))
    body = [
        pre_ir.BasicBlock(0, [], [], pre_ir.Goto(2)),            # P_a
        pre_ir.BasicBlock(1, [], [], pre_ir.Goto(2)),            # P_b
        B,                                                       # merge, branches
        pre_ir.BasicBlock(3, [], [], pre_ir.Goto(5)),            # C -> sb
        pre_ir.BasicBlock(4, [], [], pre_ir.Fail("d")),          # D skips sb
        pre_ir.BasicBlock(5, [], [_store(7, p)],                 # sb: store 7 p
                          pre_ir.ProgramExit(pre_ir.UInt64Constant(1))),
    ]
    sub = pre_ir.Subroutine("t", [], [], body)
    n = sink_mixed_phi_scratch_stores([sub])
    assert n == 0, "must not sink a conditionally-reached store"
    assert len(B.phis) == 1, "the mixed phi must be left intact"
    assert any(o for o in body[5].ops), "the original store must stay in place"


def test_sink_applies_when_store_post_dominated():
    """B unconditionally reaches the store (single successor chain) — sinking is
    safe and the mixed phi is eliminated."""
    va, vb = _r("va", "uint64"), _r("vb", "bytes")
    B, p = _mixed_phi_block(2, [0, 1], va, vb, pre_ir.Goto(3))
    body = [
        pre_ir.BasicBlock(0, [], [], pre_ir.Goto(2)),            # P_a
        pre_ir.BasicBlock(1, [], [], pre_ir.Goto(2)),            # P_b
        B,                                                       # merge -> sb only
        pre_ir.BasicBlock(3, [], [_store(7, p)],                 # sb: store 7 p
                          pre_ir.ProgramExit(pre_ir.UInt64Constant(1))),
    ]
    sub = pre_ir.Subroutine("t", [], [], body)
    n = sink_mixed_phi_scratch_stores([sub])
    assert n == 1, "an unconditionally-reached store is sinkable"
    assert len(B.phis) == 0, "the mixed phi must be sunk away"
    # per-predecessor stores now carry the single-typed edge values.
    assert body[0].ops and body[1].ops, "each predecessor gets its edge store"


# --------------------------------------------------------------------------
# `string` is bytes-backed everywhere
# --------------------------------------------------------------------------


def test_string_is_bytes_backed():
    assert avm("string") == "b"


def test_vrf_verify_output_is_bytes():
    # vrf_verify pushes (64-byte output, verified-flag) — top-first the flag is
    # slot 0 (uint64), the 64-byte output is slot 1 (bytes). Previously slot 1
    # fell through to the uint64 default, mistyping the VRF output.
    assert _multi_out_type("vrf_verify", "VrfAlgorand", 0) == "uint64"
    assert _multi_out_type("vrf_verify", "VrfAlgorand", 1) == "bytes"


def test_string_phi_join_stays_bytes():
    # two genuinely-bytes types must not cross the divide and default to uint64.
    assert _avm_join({"string", "account"}) == "bytes"
    assert _avm_join({"string", "bytes"}) == "bytes"
    # a real cross-divide set is still unresolved (sound).
    assert _avm_join({"string", "uint64"}) is None


# --------------------------------------------------------------------------
# `_unify_comparison_operands` — HARD evidence only
# --------------------------------------------------------------------------


def _cmp_prog(op, a0, a1):
    blk = pre_ir.BasicBlock(0, [], [pre_ir.IntrinsicOp(pre_ir.Intrinsic(op, [], [a0, a1]))],
                            pre_ir.Fail("end"))
    return pre_ir.Program(pre_ir.Subroutine("m", [], [], [blk], is_main=True))


def test_unify_flips_soft_operand_on_hard_evidence():
    """A HARD operand (a uint64 constant) fixes the family; the SOFT bytes
    register on the other side of `==` is retyped to match."""
    soft = _r("x", "bytes")   # BASE strength, no producer
    prog = _cmp_prog("==", pre_ir.UInt64Constant(5), soft)
    _unify_comparison_operands(prog)
    assert soft.ir_type == "uint64", "HARD const evidence must drive the retype"


def test_unify_does_not_flip_on_a_refined_guess():
    """Neither operand has HARD evidence: an `account` (REFINED) vs a plain
    `uint64` register (BASE). The old code flipped the weaker one on the mere
    strength gap; now, with no unimpeachable evidence, NEITHER is retyped — the
    conflict is left for the encoder to flag rather than minting a wrong family."""
    acct = _r("a", "account")   # REFINED (strength 3), family bytes
    u = _r("b", "uint64")       # BASE (strength 2), family uint64
    prog = _cmp_prog("==", acct, u)
    _unify_comparison_operands(prog)
    assert acct.ir_type == "account", "correct operand must not be flipped"
    assert u.ir_type == "uint64", "correct operand must not be flipped"


# ---------------------------------------------------------------------------
# _fix_langspec_operand_types: the AVM's own operand types beat a lowering
# default (2026-07-30 ssa/+lift review, finding 22)
# ---------------------------------------------------------------------------


def test_langspec_use_corrects_a_lowering_default():
    """A register the recovery gave the WRONG concrete type must be corrected by
    a langspec-forced operand position.

    The fixpoint is monotone `?` -> concrete, so nothing downstream could undo a
    wrong label — and two passes hand them out by design: an unresolved return
    position becomes "uint64" (_reconcile_return_arity's lowering default) and
    _realign_call_returns re-pins the caller's result register to it. An address
    arriving that way stayed uint64 into `itxn_field Receiver`, losing the
    arc4.Address recovery and emitting an op puya reports as type-invalid.
    Measured over 30 mainnet probes: 18 of 99 recipient operands mistyped, 36
    puya arg-type errors, 18 lost address guesses — all now zero."""
    from tealql.tealtools.lift.type_recovery import _fix_langspec_operand_types

    R = pre_ir.Register
    wrong = R("r", 0, "uint64")            # a lowering default, not real evidence
    put = pre_ir.IntrinsicOp(pre_ir.Intrinsic(
        op="itxn_field", args=[wrong], immediates=["Receiver"]))
    main = pre_ir.Subroutine(
        id="main", parameters=[], returns=[], is_main=True,
        body=[pre_ir.BasicBlock(id=1, phis=[], ops=[put],
                                terminator=pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))])
    _fix_langspec_operand_types(pre_ir.Program(main=main, subroutines=[]))
    assert wrong.ir_type == "bytes", "itxn_field Receiver forces a bytes operand"


def test_avm_fixed_producer_is_never_relabelled():
    """The producer wins when the AVM fixes it. `txn Sender` is an account
    however it is consumed, so a use-side disagreement means the error is
    elsewhere — relabelling the result just moves puya's complaint from the
    argument to the return, which is exactly what the corpus tier caught when
    this pass first shipped without the guard."""
    from tealql.tealtools.lift.type_recovery import _fix_langspec_operand_types

    R = pre_ir.Register
    sender = R("s", 0, "account")
    read = pre_ir.Assignment([sender], pre_ir.Intrinsic(
        op="txn", args=[], immediates=["Sender"]))
    # A uint64-forced position (bzero's length) consuming it: contradictory.
    use = pre_ir.Assignment([R("z", 0, "bytes")], pre_ir.Intrinsic(
        op="bzero", args=[sender], immediates=[]))
    main = pre_ir.Subroutine(
        id="main", parameters=[], returns=[], is_main=True,
        body=[pre_ir.BasicBlock(id=1, phis=[], ops=[read, use],
                                terminator=pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))])
    _fix_langspec_operand_types(pre_ir.Program(main=main, subroutines=[]))
    assert sender.ir_type == "account", "an AVM-fixed producer must not be relabelled"


@pytest.mark.parametrize("probe", ["app_1050027265.teal", "app_104988925.teal"])
def test_no_recipient_operand_lowers_as_uint64(probe):
    """End-to-end on real contracts: every inner-txn address field operand must
    carry a bytes-family type. A uint64 there is the mistype above, and it costs
    the register its arc4.Address guess — which box_recovery's _addr_label and
    abi_address_fund_flows both read."""
    import logging
    from pathlib import Path

    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift import to_puya_ir
    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp

    path = Path(__file__).resolve().parent / "mainnet-random-probes" / probe
    if not path.exists():
        pytest.skip(f"{probe} not present")
    logging.getLogger("puya").setLevel(logging.CRITICAL)
    main, subs = to_puya_ir.to_puya(SSAProgram(str(path)))
    fields = {"Receiver", "AssetReceiver", "CloseRemainderTo", "AssetCloseTo"}
    for sub in [main, *subs]:
        for bb in sub.body:
            for o in bb.ops:
                src = o.source if isinstance(o, M.Assignment) else o
                if not (isinstance(src, M.Intrinsic) and src.op == AVMOp.itxn_field):
                    continue
                if not src.args or str(src.immediates[0]) not in fields:
                    continue
                t = getattr(src.args[0].ir_type, "name", None)
                assert t != "uint64", (
                    f"{probe}: itxn_field {src.immediates[0]} operand typed uint64")


# ---------------------------------------------------------------------------
# backend: the AVM version probe must read past a header comment
# ---------------------------------------------------------------------------


def test_pragma_below_a_header_comment_is_honoured(tmp_path):
    """The recompiled TEAL must carry the SOURCE's AVM version.

    The probe used to read only the first four lines and to let the last file's
    answer win, so a licence header pushed the pragma out of the window and the
    version silently floored to 10 — at which point a v11 field in the body makes
    the recompiled program unassemblable, the exact failure the probe exists to
    prevent."""
    from tealql.tealtools.lift import lift_to_teal

    src = tmp_path / "hdr.teal"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "// generated by something with a chatty banner\n"
        "//\n"
        "// still going\n"
        "#pragma version 11\n"
        "intcblock 0 1\n"
        "intc_1\n"
        "return\n"
    )
    teal = lift_to_teal(str(src))
    first = teal.splitlines()[0].strip()
    assert first == "#pragma version 11", (
        f"recompiled with {first!r}: the source pragma sits below a header, so a "
        "fixed-window probe misses it and floors the version to 10")


#: Corpus contracts whose lift does not survive RECOMPILATION (lift -> IR ->
#: destructure -> MIR -> TEAL). A CEILING at today's measurement; 0 is both the
#: target and the current value, so any regression fails immediately.
_RECOMPILE_FAILURES = 0

#: How many distinct probes the gate below recompiles. Bounded for runtime; the
#: probes are taken in name order so the set is deterministic.
_RECOMPILE_SAMPLE = 60

#: Probes the gate ALWAYS includes, whatever the sample window catches. A
#: name-ordered prefix is deterministic but blind to which contracts exercise
#: the interesting paths: these are the ones whose frame reads are answered by
#: the bottom-anchored band plan, and the divergent-legacy subs — exactly the
#: shapes whose lift shape has moved recently, and none of them fall in the
#: first 60 by name.
_RECOMPILE_ALWAYS = (
    "app_2645463331.teal", "app_2300200702.teal", "app_2694165644.teal",
    "app_2500525325.teal",
)


@pytest.mark.slow
def test_the_corpus_still_recompiles():
    """Every corpus contract that recompiles must KEEP recompiling.

    The behavioural differential (``tests.behavioral_lift``) cannot see this:
    it dryruns the lifted program against the original, so a contract whose
    lift no longer reaches TEAL at all is reported as a SKIP — "did not lift"
    — and a skip is not a failure. That blind spot let a real regression
    through on 2026-08-04: splicing a divergent legacy subroutine into its
    caller produced IR the MIR backend could not lower ("l-stack too small for
    store 71"), on the ONE contract the splice reached, and every suite plus
    the behavioural gate stayed green. Recompilation is therefore gated here,
    directly.

    Not a behaviour check — ``lift_to_teal`` merely has to produce assemblable
    TEAL. Faithfulness on top of that is the behavioural gate's job."""
    from pathlib import Path

    from tealql.tealtools.lift.backend import lift_to_teal

    probes = Path(__file__).resolve().parent / "mainnet-random-probes"
    if not probes.is_dir():
        pytest.skip("probe corpus not present")
    seen: set = set()
    targets: list = []
    for p in sorted(probes.glob("*.teal")):
        h = hash(p.read_text())          # content dedup: templates repeat
        if h in seen:
            continue
        seen.add(h)
        targets.append(p)
        if len(targets) >= _RECOMPILE_SAMPLE:
            break
    for name in _RECOMPILE_ALWAYS:
        extra = probes / name
        if extra.is_file() and extra not in targets:
            targets.append(extra)
    failures: list = []
    for p in targets:
        try:
            lift_to_teal(str(p))
        except Exception as e:           # noqa: BLE001 - any failure counts
            failures.append(f"{p.name}: {type(e).__name__}: {str(e)[:70]}")
    assert len(failures) <= _RECOMPILE_FAILURES, (
        f"{len(failures)} of {len(targets)} corpus contracts no longer "
        f"recompile (ceiling {_RECOMPILE_FAILURES}) — the lift emits IR the "
        "backend cannot lower, which the behavioural gate reports only as a "
        "skip:\n  " + "\n  ".join(failures[:8]))
