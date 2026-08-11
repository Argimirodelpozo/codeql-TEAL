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

from tealql.tealtools.language.avm import avm, _multi_out_type  # noqa: E402
from tealql.tealtools.lift.type_recovery import (  # noqa: E402
    _avm_join,
    _reconcile_mixed_phis,
    _stamp_undefined_operands,
    _unify_comparison_operands,
)
from tealql.tealtools.lift.transforms import (  # noqa: E402
    sink_mixed_phi_scratch_stores,
    split_mixed_phis,
)
from tealql.tealtools.lift import pre_ir  # noqa: E402


def _r(name, ir_type="uint64"):
    return pre_ir.Register(name, 0, ir_type)


def _store(slot, val):
    return pre_ir.IntrinsicOp(pre_ir.Intrinsic("store", [slot], [val]))


def test_phi_live_in_seed_is_type_evidence():
    """A typed parameter feeding a phi is live even without an assignment.

    The control web contains only zero/empty coarse-SSA placeholders and should
    retain the deliberate dead-web uint64 fallback.
    """
    seed = _r("arg", "bytes")
    live = _r("live", "bytes")
    dead = _r("dead", "bytes")
    live_phi = pre_ir.Phi(
        live,
        [
            pre_ir.PhiArgument(seed, 0),
            pre_ir.PhiArgument(pre_ir.BytesConstant(""), 1),
        ],
    )
    dead_phi = pre_ir.Phi(
        dead,
        [
            pre_ir.PhiArgument(pre_ir.UInt64Constant(0), 0),
            pre_ir.PhiArgument(pre_ir.BytesConstant(""), 1),
        ],
    )
    body = [
        pre_ir.BasicBlock(0, [], [], pre_ir.Goto(2)),
        pre_ir.BasicBlock(1, [], [], pre_ir.Goto(2)),
        pre_ir.BasicBlock(
            2, [live_phi, dead_phi], [], pre_ir.SubroutineReturn([live])
        ),
    ]
    sub = pre_ir.Subroutine(
        "echo", [pre_ir.Parameter(seed)], ["bytes"], body, is_main=True
    )

    _reconcile_mixed_phis(pre_ir.Program(main=sub))

    assert live.ir_type == "bytes"
    assert live_phi.args[0].value is seed
    assert dead.ir_type == "uint64"
    assert isinstance(dead_phi.args[1].value, pre_ir.UInt64Constant)


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


def test_byte_switch_demands_the_bytes_arm_of_a_mixed_phi():
    """A pre-IR ``Switch`` represents keyed ``match`` and is polymorphic.

    Its case keys, not the positional ``switch`` opcode's uint64 rule, decide
    which family survives mixed-phi splitting.
    """
    bytes_arm, uint_arm, selector = (
        _r("bytes-arm", "bytes"), _r("uint-arm", "uint64"), _r("selector", "?")
    )
    phi = pre_ir.Phi(selector, [
        pre_ir.PhiArgument(bytes_arm, 0),
        pre_ir.PhiArgument(uint_arm, 1),
    ])
    term = pre_ir.Switch(selector, [("0x61", 3)], 4)
    body = [
        pre_ir.BasicBlock(0, [], [], pre_ir.Goto(2)),
        pre_ir.BasicBlock(1, [], [], pre_ir.Goto(2)),
        pre_ir.BasicBlock(2, [phi], [], term),
        pre_ir.BasicBlock(3, [], [], pre_ir.ProgramExit(pre_ir.UInt64Constant(1))),
        pre_ir.BasicBlock(4, [], [], pre_ir.ProgramExit(pre_ir.UInt64Constant(0))),
    ]
    program = pre_ir.Program(pre_ir.Subroutine("m", [], [], body, is_main=True))

    assert split_mixed_phis(program) == 1
    assert isinstance(term.value, pre_ir.Register)
    assert term.value.ir_type == "bytes"


def test_source_fallback_keeps_spaced_byte_encodings_atomic():
    """The source fallback must not split ``b64 DATA`` into two constants.

    Multi-push and bytecblock recovery use these tokens when the parser cannot
    retain a source operand; shifting one token shifts every later constant.
    """
    from tealql.tealtools.lift.to_puya_ir import _Translator

    translator = _Translator({
        "p.teal": [
            "pushbytess b64 YQ== b64 Yg==",
            "bytecblock b64 Yw== b64 ZA==",
        ]
    })
    assert translator._operands_at(1) == ["b64 YQ==", "b64 Yg=="]
    assert translator._const_block("bytec", 2) == ["b64 Yw==", "b64 ZA=="]


# --------------------------------------------------------------------------
# `string` is bytes-backed everywhere
# --------------------------------------------------------------------------


def test_string_is_bytes_backed():
    assert avm("string") == "b"


def test_vrf_verify_output_is_bytes():
    # vrf_verify pushes (64-byte output, verified-flag) — top-first the flag is
    # slot 0 (bool), the 64-byte output is slot 1 (bytes). Previously slot 1 fell
    # through to the uint64 default, mistyping the VRF output.  The flag became
    # the more precise `bool` when all multi-output existence/verification flags
    # were normalized; keep this assertion in step with that public metadata.
    assert _multi_out_type("vrf_verify", "VrfAlgorand", 0) == "bool"
    assert _multi_out_type("vrf_verify", "VrfAlgorand", 1) == "bytes"


def test_string_phi_join_stays_bytes():
    # two genuinely-bytes types must not cross the divide and default to uint64.
    assert _avm_join({"string", "account"}) == "bytes"
    assert _avm_join({"string", "bytes"}) == "bytes"
    # a real cross-divide set is still unresolved (sound).
    assert _avm_join({"string", "uint64"}) is None


def test_a_refused_bytes_operand_is_typed_for_its_use():
    unknown = pre_ir.Undefined()
    intrinsic = pre_ir.Intrinsic("extract", [113, 8], [unknown])
    program = pre_ir.Program(main=pre_ir.Subroutine(
        "main", [], [], [pre_ir.BasicBlock(
            0, [], [pre_ir.IntrinsicOp(intrinsic)],
            pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))], is_main=True))
    _stamp_undefined_operands(program)
    assert isinstance(intrinsic.args[0], pre_ir.Undefined)
    assert intrinsic.args[0].ir_type == "bytes"


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


def test_guarded_derived_view_keeps_exact_byte_lengths_during_lowering(caplog, tmp_path):
    """Reusing a fully annotated read-only view must be a no-op, not a failed
    mutation.  The unsized control is Puya's ordinary type for ``extract``;
    the SSA length bridge is what refines this particular result to bytes[4].
    """
    import logging

    import puya.ir.models as M
    from puya.ir.avm_ops import AVMOp

    from tealql.tealtools.analysis import DerivedProfile, derived_program
    from tealql.tealtools.lift import lift_to_teal, to_puya_ir
    from tealql.tealtools.ssa import SSAProgram

    source = tmp_path / "sized.teal"
    source.write_text(
        "#pragma version 10\ntxn TxID\nextract 0 4\nlog\nint 1\nreturn\n"
    )
    prog = SSAProgram(str(source))
    view = derived_program(prog, DerivedProfile.GUARDED)
    with caplog.at_level(logging.WARNING, logger="tealql.tealtools.lift"):
        main, _subs = to_puya_ir.to_puya(view)

    extract = next(
        op for block in main.body for op in block.ops
        if isinstance(op, M.Assignment)
        and isinstance(op.source, M.Intrinsic)
        and op.source.op == AVMOp.extract
    )
    result_type = extract.targets[0].ir_type
    assert type(result_type).__name__ == "SizedBytesType"
    assert result_type.num_bytes == 4
    assert "const-propagation FAILED" not in caplog.text
    assert "sized-bytes bridge FAILED" not in caplog.text
    assert "extract 0 4" in lift_to_teal(str(source))


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


@pytest.mark.parametrize("name", _RECOMPILE_ALWAYS[:3])
def test_poisoned_frame_templates_use_position_phis_not_versioned_locals(name):
    """The three varying-height templates that once required ``l%N.version``
    must stay on the first-class FrameAnalysis -> pre-IR path.

    Five distinct loop-carried positions are recoverable. A second poisoned
    proto return is recovered from its dominating in-block bury even though its
    multi-entry region has no global anchor; pinning both numbers keeps
    precision and honest gaps visible instead of silently falling back to
    another frame implementation.
    """
    from pathlib import Path

    from tealql.tealtools.lift.lift import _Lifter
    from tealql.tealtools.ssa import SSAProgram

    path = Path(__file__).resolve().parent / "mainnet-random-probes" / name
    if not path.is_file():
        pytest.skip(f"{name} not present")
    ir = _Lifter(SSAProgram(str(path))).build()
    assert ir.pass_stats["frame_position_phis"] == 5
    assert ir.pass_stats["frame_slot_refusals"] == 0
    assert not any(reg.local_id.startswith("l%") for reg in pre_ir.registers(ir))


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
