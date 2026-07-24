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
