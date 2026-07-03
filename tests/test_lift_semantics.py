"""Semantic tests for the SSA -> Puya-IR lift (``lift``).

Rather than pin the rendered IR byte-for-byte -- brittle (breaks on cosmetic or
Puya-version changes) and silent on correctness -- these assert the *properties
that make the lift correct*, using oracles we already have:

  Tier 1 (validity): the lift lowers to genuine ``puya.ir.models`` and Puya's own
    optimiser runs to a fixpoint without rejecting it.

  Tier 2 (completeness): walk the pre-IR -- every block terminates, every
    ``InvokeSubroutine``'s arity matches its callee, and type recovery did not
    collapse (residual ``"?"`` registers, which lowering would silently default
    to uint64, stay a small fraction). The checker is exercised always-run on
    hand-built pre-IR, then applied to each real lift.

  Tier 3 (behavioural): lower the lifted IR through Puya's *real* backend --
    ``program_ir_to_mir`` (with the strict ``global_stack_allocation``) then
    ``mir_to_teal`` -- to actual TEAL ops. Far stricter than the IR optimiser:
    it asks whether our IR realises as a coherent AVM program, not merely that
    the optimiser tolerates it -- running Puya's own pre-MIR sequence (split
    ValueTuples -> ``destructure_ssa`` -> MIR -> TEAL). ``repro`` lowers fully
    (a real assertion). The remaining real-contract gap is the lift emitting
    registers *used but never defined* (the frame / dynamic-scratch value-loss),
    which ``destructure_ssa`` rejects; those stay TRACKED xfail (flip to xpass
    when fixed). The earlier ``itxn_field`` address-typing gap is fixed; the
    ``ValueTuple`` / residual-phi "gaps" were just the harness not running Puya's
    destructure. OPT-IN, OFF by default; set ``LIFT_SEMANTICS_BACKEND=1`` to run.

Per-DB tests are skip-gated on the (gitignored, locally-built) CodeQL DB
fixtures + puya. ``LIFT_SEMANTICS_CORPUS=1`` also sweeps the puya corpus through
Tiers 1-2; ``LIFT_SEMANTICS_BACKEND=1`` runs the Tier-3 backend harness.
"""
import contextlib
import functools
import logging
import os
from pathlib import Path

import pytest

pytest.importorskip("puya")

from tealql.tealtools.lift import pre_ir  # noqa: E402

_ROOT = Path(__file__).resolve().parent
_REAL_CONTRACT_DIR = _ROOT / "contracts"
_CORPUS_DIR = _ROOT / "experimental_IR_lift" / "puya"
_EXPLORER_DIR = _ROOT / "experimental_IR_lift" / "explorer"
# A residual-"?" fraction this high means type recovery has collapsed (a coarse
# net -- the strong guards are terminator/arity/backend). Observed max ~11%.
_MAX_UNKNOWN_FRACTION = 0.25


# --------------------------------------------------------------------------
# contract discovery (skip-gated: fixtures are gitignored / locally built)
# --------------------------------------------------------------------------


def _has_source(d: Path) -> bool:
    # source-bearing fixture dir: holds a slimmed `.teal` source
    return bool(list(d.glob("*.teal"))) or (d / "src.zip").exists()


def _real_contracts():
    names = ("xgov", "folks-consensus-v2", "folks-consensus-v3",
             "folks-xgov-registry", "repro")
    return [(n, _REAL_CONTRACT_DIR / n) for n in names if _has_source(_REAL_CONTRACT_DIR / n)]


def _corpus_contracts():
    if not _CORPUS_DIR.exists():
        return []
    return [(p.name, p / "src") for p in sorted(_CORPUS_DIR.iterdir())
            if _has_source(p / "src")]


def _all_contracts():
    out = _real_contracts()
    if os.environ.get("LIFT_SEMANTICS_CORPUS"):
        out += _corpus_contracts()
    return out


_NO_FIXTURES = [pytest.param(None, id="no-fixtures",
                             marks=pytest.mark.skip(reason="no lift fixtures present"))]

_CONTRACT_PARAMS = [pytest.param(str(d), id=n) for n, d in _all_contracts()] or _NO_FIXTURES

# Full-backend lowering (Tier 3): lift -> split ValueTuples -> destructure SSA ->
# MIR -> TEAL, exactly Puya's own pre-MIR sequence. ALL 5 real contracts now lower
# fully (re-simulating every sub recovered the interprocedural stack survivors the
# fat-frame band lost), so each is a real assertion guarding against regression.
# Any sub that re-introduces a used-but-never-defined register would fail here.
# OPT-IN via LIFT_SEMANTICS_BACKEND=1 so the default suite keeps to the Tier-1/2 bar.
_BACKEND_LOWERS = {"repro", "folks-consensus-v2", "folks-consensus-v3",
                   "folks-xgov-registry", "xgov"}    # all 5 real contracts lower
_XFAIL_BACKEND = pytest.mark.xfail(
    reason="lift emits a used-but-never-defined register that destructure_ssa rejects",
    strict=False, raises=Exception)
_BACKEND_PARAMS = (
    [pytest.param(str(d), id=n, marks=() if n in _BACKEND_LOWERS else (_XFAIL_BACKEND,))
     for n, d in _real_contracts()]
    if os.environ.get("LIFT_SEMANTICS_BACKEND") and _real_contracts()
    else [pytest.param(None, id="backend-gated",
                       marks=pytest.mark.skip(reason="set LIFT_SEMANTICS_BACKEND=1"))])


# --------------------------------------------------------------------------
# Lift + lower once per contract, shared across the per-contract tier tests
# --------------------------------------------------------------------------


@contextlib.contextmanager
def _quiet_puya():
    log = logging.getLogger("puya")
    prev = log.level
    log.setLevel(logging.ERROR)               # the backend logs every MIR op at debug
    try:
        yield
    finally:
        log.setLevel(prev)


def _lower_to_teal(main, subs):
    """Lower lifted Puya IR through Puya's *real* backend to a TealProgram,
    replicating Puya's own pre-MIR sequence: split ValueTuples
    (``_split_parallel_copies``) -> destructure SSA / remove phis
    (``destructure_ssa``) -> ``program_ir_to_mir`` -> ``mir_to_teal``. The lift's
    own undefined-register catch-retry (typed-zero orphan definition) is applied
    at the MIR boundary, mirroring what ``to_puya_ir.optimize`` does at the
    IR-optimiser boundary."""
    import re

    import puya.ir.models as M
    from puya.context import ArtifactCompileContext, CompiledProgramProvider
    from puya.errors import InternalError
    from puya.ir.destructure.main import destructure_ssa
    from puya.ir.models import ProgramKind, SlotAllocation, SlotAllocationStrategy
    from puya.ir.optimize.main import _split_parallel_copies
    from puya.mir.main import program_ir_to_mir
    from puya.options import PuyaOptions
    from puya.teal.main import mir_to_teal
    from tealql.tealtools.lift.to_puya_ir import _define_named_orphan

    try:
        provider = CompiledProgramProvider()
    except Exception:
        provider = object.__new__(CompiledProgramProvider)   # Protocol: bare stub, never called
    ctx = ArtifactCompileContext(
        options=PuyaOptions(), compilation_set={}, sources_by_path={},
        compiled_program_provider=provider, output_path_provider=None)
    groups = [main, *subs]
    program = M.Program(
        kind=ProgramKind.approval, main=main, subroutines=list(subs), avm_version=10,
        slot_allocation=SlotAllocation(reserved=frozenset(), strategy=SlotAllocationStrategy.none))
    with _quiet_puya():
        for s in groups:
            _split_parallel_copies(ctx, s)       # ValueTuple sources -> per-value copies
        destructure_ssa(ctx, program)            # phis -> predecessor-edge copies (out of SSA)
        for _ in range(50):
            try:
                return mir_to_teal(ctx, program_ir_to_mir(ctx, program))
            except InternalError as e:
                m = re.search(r"[Uu]ndefined register: ([^#\s]+)#(\d+)", str(e))
                if not (m and _define_named_orphan(groups, m.group(1), int(m.group(2)))):
                    raise
        raise RuntimeError("backend lowering did not converge")


@functools.lru_cache(maxsize=None)
def _process(contract: str):
    """(pre_ir Program, lowered main Subroutine, [lowered subs]). Lift + Puya's
    own IR optimiser only -- the Tier-1/2 bar. Raises if the lift/optimise fails
    (that is itself the Tier-1 signal). The backend (Tier 3) runs lazily so the
    expected-fail, slower lowering doesn't burden Tiers 1-2."""
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift import to_puya_ir
    from tealql.tealtools.lift.lift import lift
    with _quiet_puya():
        prog = SSAProgram(contract)
        pre = lift(prog)                                   # pre-IR for Tier 2
        main, subs = to_puya_ir.to_puya(prog)              # genuine puya.ir.models
        to_puya_ir.optimize([main, *subs])                # Puya's own IR optimiser
    return pre, main, list(subs)


# --------------------------------------------------------------------------
# Pre-IR well-formedness checker (shared by always-run units + per-contract tests)
# --------------------------------------------------------------------------


def _violations(pre) -> list:
    """Structural well-formedness violations of a lifted pre-IR program."""
    out = []
    arity = {s.id: len(s.parameters) for s in (pre.main, *pre.subroutines)}
    for bb in pre_ir.blocks(pre):
        if bb.terminator is None:
            out.append(f"block@{bb.id}: no terminator")
        for op in bb.ops:
            if isinstance(op, pre_ir.Assignment) and isinstance(op.source, pre_ir.InvokeSubroutine):
                inv = op.source
                want = arity.get(inv.target)
                if want is not None and len(inv.args) != want:
                    out.append(f"call {inv.target}: {len(inv.args)} args vs {want} params")
    return out


def _unknown_registers(pre):
    """(unknown, total) register-occurrence counts -- a register left ``"?"`` is
    a type-recovery gap that lowering silently defaults to uint64."""
    total = unknown = 0
    for bb in pre_ir.blocks(pre):
        regs = [ph.register for ph in bb.phis]
        for op in bb.ops:
            if isinstance(op, pre_ir.Assignment):
                regs += op.targets
        for node in (*bb.phis, *bb.ops, bb.terminator):
            regs += [v for v in pre_ir.operands(node) if isinstance(v, pre_ir.Register)]
        total += len(regs)
        unknown += sum(1 for r in regs if r.ir_type == "?")
    return unknown, total


# --------------------------------------------------------------------------
# Tier 2 — the checker itself, always-run on hand-built pre-IR (no fixture/puya lift)
# --------------------------------------------------------------------------


def _mk_prog(*, terminated=True, call_args=None):
    main_blk = pre_ir.BasicBlock(
        id=0, terminator=pre_ir.ProgramExit(pre_ir.UInt64Constant(1)) if terminated else None)
    subs = []
    if call_args is not None:
        # subroutine 'foo' takes exactly one parameter
        foo = pre_ir.Subroutine(
            "foo", [pre_ir.Parameter(pre_ir.Register("p", 0, "uint64"))], [],
            [pre_ir.BasicBlock(id=1, terminator=pre_ir.SubroutineReturn([]))])
        subs.append(foo)
        main_blk.ops.append(pre_ir.Assignment(
            [pre_ir.Register("r", 0, "uint64")], pre_ir.InvokeSubroutine("foo", list(call_args))))
    main = pre_ir.Subroutine("main", [], [], [main_blk], is_main=True)
    return pre_ir.Program(main=main, subroutines=subs)


def test_checker_passes_well_formed():
    assert _violations(_mk_prog()) == []


def test_checker_flags_missing_terminator():
    assert any("no terminator" in v for v in _violations(_mk_prog(terminated=False)))


def test_checker_flags_call_arity_mismatch():
    a = pre_ir.Register("a", 0, "uint64")
    assert any("args vs" in v for v in _violations(_mk_prog(call_args=[a, a])))   # 2 vs 1


def test_checker_passes_matching_call_arity():
    assert _violations(_mk_prog(call_args=[pre_ir.Register("a", 0, "uint64")])) == []   # 1 vs 1


# --------------------------------------------------------------------------
# Per-contract tier tests (skip-gated; _process cached so each contract lifts once)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("contract", _CONTRACT_PARAMS)
def test_lifts_and_optimises(contract):
    """Tier 1: SSA lifts to genuine Puya IR and Puya's optimiser accepts it."""
    pre, main, _subs = _process(contract)
    assert pre is not None and main is not None


@pytest.mark.parametrize("contract", _CONTRACT_PARAMS)
def test_pre_ir_well_formed(contract):
    """Tier 2: completeness invariants on the lifted pre-IR."""
    pre, _main, _subs = _process(contract)
    assert _violations(pre) == []
    unknown, total = _unknown_registers(pre)
    assert unknown <= _MAX_UNKNOWN_FRACTION * total, \
        f"type recovery collapsed: {unknown}/{total} registers unresolved"


@pytest.mark.parametrize("contract", _BACKEND_PARAMS)
def test_lowers_through_puya_backend(contract):
    """Tier 3 (tracked/xfail): the lifted IR lowers through Puya's real MIR
    stack-allocator + TEAL backend to actual ops. Currently surfaces the lift's
    not-yet-backend-clean gaps on production contracts; flips to xpass when fixed."""
    _pre, main, subs = _process(contract)
    teal = _lower_to_teal(main, subs)
    assert sum(len(b.ops) for b in teal.main.blocks) > 0    # produced real TEAL ops


# --------------------------------------------------------------------------
# Regression: `match` arm pairing (single multi-push vs individual pushes)
# --------------------------------------------------------------------------


@pytest.mark.skipif(
    not _has_source(_EXPLORER_DIR / "app_3543081435"),
    reason="app_3543081435 explorer fixture not present",
)
def test_match_arm_pairing_individual_pushes():
    """A `match` whose case keys come from SEPARATE `intc` pushes must pair
    label[i] with the deepest-first key (SSA inputs are top-first, so the keys
    arrive reversed -- the fix uses ins[n-i], not ins[i+1] which is only right
    for a single multi-push `pushbytess`/`pushints`).

    app_3543081435's no-arg OnCompletion router is
    ``intc 0; intc 4; txn OnCompletion; match label9 label10`` where
    0->label9 (`txn ApplicationID; !; return`, NoOp) and 4->label10 (creator
    assert, UpdateApplication). Getting it wrong swaps the two and flips the
    approve/reject outcome (behaviourally confirmed). Assert the routing:
    case "0" goes to the block with the `!`/Not op; case "4" does not."""
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift.lift import lift

    prog = SSAProgram(
        str(_EXPLORER_DIR / "app_3543081435"))
    pre = lift(prog)
    blocks = {b.id: b for b in pre_ir.blocks(pre)}

    sw = next(
        (b.terminator for b in blocks.values()
         if isinstance(b.terminator, pre_ir.Switch)
         and {str(k) for k, _ in b.terminator.cases} == {"0", "4"}),
        None,
    )
    assert sw is not None, "no-arg OnCompletion match Switch not found"
    cases = {str(k): bid for k, bid in sw.cases}

    def has_not(bid):
        return any("op='!'" in str(o) for o in blocks[bid].ops)

    assert has_not(cases["0"]), "case 0 (NoOp) must route to the `!`/AppID block"
    assert not has_not(cases["4"]), "case 4 (Update) must NOT route to the NoOp block"


# --------------------------------------------------------------------------
# Regression: `frame_bury` of a `callsub` return value
# --------------------------------------------------------------------------


_FRAME_BURY_CALLSUB_RETURN_TEAL = """#pragma version 8
intcblock 0 1
txn ApplicationID
bz main_create
callsub outer
intc_1
return
main_create:
intc_1
return
outer:
proto 0 0
intc_0
callsub inner
frame_bury 0
pushbytes 0x151f7c75
frame_dig 0
itob
concat
log
retsub
inner:
proto 0 1
intc_1
retsub
"""


def test_frame_bury_of_callsub_return(tmp_path):
    """A `frame_bury` of a `callsub` RETURN must version the slot so a later
    `frame_dig` reads the return. `callsub` has 0 SSA outputs (the resim threads
    the return), so the bury's base-SSA inputs are empty; frame_resolution used
    to skip it (`and a.inputs`), leaving the slot unversioned, so the `frame_dig`
    was misclassified as a *pushed* local and routed to the stack-band value --
    here `itob` on the bytes `0x151f7c75` (AVM type error -> reject). Confirmed
    on mainnet app_3000142226 et al. (UpdateApplication flipped to reject).

    Assert no `itob` in the lifted program operates on a bytes constant."""
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift.lift import lift

    p = tmp_path / "frame_bury_callsub_return.teal"
    p.write_text(_FRAME_BURY_CALLSUB_RETURN_TEAL)
    pre = lift(SSAProgram(str(p)))
    itobs = [op for bb in pre_ir.blocks(pre) for op in bb.ops if "op='itob'" in str(op)]
    assert itobs, "synthetic did not produce an itob (test no longer exercises the path)"
    for op in itobs:
        assert "BytesConstant" not in str(op), (
            "itob on a bytes constant — frame_bury-of-callsub-return regression "
            f"(frame_dig misrouted): {op}")


_FRAME_BURY_RETURN_TEAL = """#pragma version 10
    pushint 5
    callsub make
    len
    pushint 5
    ==
    return
make:
    proto 1 1
    pushbytes 0x
    pushint 7
    frame_dig -1
    bzero
    frame_bury 0
    retsub
"""


def test_frame_bury_return_slot(tmp_path):
    """A `proto A R` retsub returns frame slots 0..R-1 (the first R locals), NOT
    the top R of the stack. `make` buries its bytes return in slot 0 while a
    uint64 working local (`pushint 7`) sits ABOVE it on the stack, so the old
    resim path's `rsx[-R:]` returned that uint64 instead of the slot-0 bytes --
    the caller's `len` then sees uint64. Verified on a live localnet:
    `len(make(5)) == 5` PASSES only when slot-0 bytes is returned (diverge=0);
    `make(5)` typed uint64 fails `cannot compare []byte to uint64`.

    Assert the lifted `make` returns bytes, not uint64."""
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift.lift import lift

    p = tmp_path / "frame_bury_return.teal"
    p.write_text(_FRAME_BURY_RETURN_TEAL)
    pre = lift(SSAProgram(str(p)))
    subs = [s for s in pre.subroutines if not s.is_main]
    assert subs, "synthetic produced no subroutine"
    make = subs[0]
    assert make.returns == ["bytes"], (
        "proto retsub returned the wrong frame slot — expected the slot-0 bytes "
        f"(bzero result), got returns={make.returns} (the uint64 stack top)")


def test_specialize_polymorphic_return_clone():
    """A generic accessor sub called with conflicting result AVM types is cloned
    per return type. Mirrors a hand-written `get(app, key)` state reader called
    for a uint64 key and a bytes (address) key: one Puya return type can't be
    both, so the bytes callsite must route to a bytes-returning CLONE while the
    uint64 callsite keeps the original. (Real cases: app_3400287920 /
    app_3000142939 -- `incompatible types on assignment: source = (uint64),
    target = (bytes)` before specialization.)"""
    from tealql.tealtools.lift import transforms

    R = pre_ir.Register
    rv = R("rv", 0, "uint64")                       # callee's returned value
    acc = pre_ir.Subroutine(
        id="acc", parameters=[pre_ir.Parameter(R("p", 0, "bytes"))],
        returns=["uint64"],
        body=[pre_ir.BasicBlock(id=10, phis=[], ops=[],
                                terminator=pre_ir.SubroutineReturn(result=[rv]))])
    u, b = R("cu", 0, "uint64"), R("cb", 0, "bytes")
    inv_u = pre_ir.Assignment([u], pre_ir.InvokeSubroutine("acc", [pre_ir.BytesConstant("0x01")]))
    inv_b = pre_ir.Assignment([b], pre_ir.InvokeSubroutine("acc", [pre_ir.BytesConstant("0x02")]))
    main = pre_ir.Subroutine(
        id="main", parameters=[], returns=[], is_main=True,
        body=[pre_ir.BasicBlock(id=1, phis=[], ops=[inv_u, inv_b],
                                terminator=pre_ir.SubroutineReturn(result=[]))])
    prog = pre_ir.Program(main=main, subroutines=[acc])

    made = transforms.specialize_polymorphic_returns(prog)
    assert made == 1, "expected exactly one clone for the bytes callsite"
    assert inv_u.source.target == "acc", "uint64 callsite must keep the original"
    assert inv_b.source.target != "acc", "bytes callsite must reroute to the clone"
    clone = next(s for s in prog.subroutines if s.id == inv_b.source.target)
    assert clone.returns == ["bytes"]
    assert clone.body[0].id != 10, "clone must get a fresh (global-unique) block id"
    ret = clone.body[0].terminator.result[0]
    assert ret.ir_type == "bytes" and ret is not rv, "clone return reg retyped + fresh"
    assert acc.returns == ["uint64"] and rv.ir_type == "uint64", "original untouched"


def test_duplicate_cross_subroutine_shared_tail():
    """A block reached from two subroutines (a shared `retsub` tail one sub owns
    and another `b`-es into) is privatized: the consuming sub gets its own clone
    with a fresh block id, the cross-subroutine edge is gone, and the owner keeps
    the original. (Real case: app_2200207295 -- a shared retsub branched into from
    sibling subroutines -> Puya "predecessor block(s) outside of list".)"""
    from tealql.tealtools.lift import transforms
    from tealql.tealtools.lift.transforms import _succ_ids

    B = pre_ir.BasicBlock
    shared = B(id=50, phis=[], ops=[], terminator=pre_ir.SubroutineReturn(result=[]))
    subA = pre_ir.Subroutine(
        id="A", parameters=[], returns=[],
        body=[B(id=40, phis=[], ops=[], terminator=pre_ir.Goto(50)), shared])
    b0 = B(id=60, phis=[], ops=[], terminator=pre_ir.Goto(50))   # cross-edge into A
    subB = pre_ir.Subroutine(id="B", parameters=[], returns=[], body=[b0])
    main = pre_ir.Subroutine(
        id="main", parameters=[], returns=[], is_main=True,
        body=[B(id=1, phis=[], ops=[],
                terminator=pre_ir.ProgramExit(pre_ir.UInt64Constant(1)))])
    prog = pre_ir.Program(main=main, subroutines=[subA, subB])

    made = transforms.duplicate_cross_subroutine_blocks(prog)
    assert made >= 1
    sub_of = {b.id: s.id for s in [prog.main, *prog.subroutines] for b in s.body}
    for s in [prog.main, *prog.subroutines]:           # no cross-subroutine edges remain
        for b in s.body:
            for t in _succ_ids(b.terminator):
                assert sub_of.get(t) == s.id, f"{s.id} blk{b.id} -> blk{t}({sub_of.get(t)})"
    assert any(b.id == 50 for b in subA.body), "owner keeps the original block"
    assert b0.terminator.target != 50, "consumer edge redirected to its private clone"
    assert sub_of[b0.terminator.target] == "B"


_SWITCH_ARM_RETSUB_TEAL = """#pragma version 8
pushint 0
store 0
callsub dispatch
pushint 1
return
dispatch:
load 0
switch arm0 arm1
err
arm0:
pushint 0
store 0
retsub
arm1:
pushint 1
store 0
retsub
"""


def test_switch_arm_retsub_continuation(tmp_path):
    """A subroutine that dispatches `load N; switch a b` to arms that each
    `retsub` must still have those arm-retsubs attributed to it, so `callsub
    dispatch`'s continuation (the line after the call) stays reachable. The
    aux closure used to follow only the switch fall-through, orphaning the
    arm-retsubs -> the continuation got pruned and the lift mis-routed it
    (app_3100133227's nested-call reachability cascade). Assert the line after
    the callsub is reachable as a block."""
    from tealql.tealtools.ssa import SSAProgram

    p = tmp_path / "switch_arm_retsub.teal"
    p.write_text(_SWITCH_ARM_RETSUB_TEAL)
    prog = SSAProgram(str(p))
    callsub_line = _SWITCH_ARM_RETSUB_TEAL.splitlines().index("callsub dispatch") + 1
    cont_line = callsub_line + 1                    # `pushint 1` — the continuation
    assert any(b.first_line <= cont_line <= b.last_line for b in prog.blocks.values()), (
        "callsub continuation was pruned — switch-arm retsubs not attributed to the sub")


def test_materialize_phi_const_coerces_cross_family():
    """A phi merging a constant on some edge gets that constant materialized as
    `let pc: <phi-type> = <const>`. When the const's AVM family disagrees with the
    phi type (a dead coarse-SSA placeholder -- e.g. empty `""` on a uint64 phi
    edge), it must be COERCED, else Puya rejects `let pc: uint64 = <bytes>`.
    (Surfaced by a v11 mainnet probe, app_3550180073.)"""
    from tealql.tealtools.lift import transforms

    R = pre_ir.Register
    reg = R("tmp%9", 0, "uint64")                  # phi resolves uint64
    ph = pre_ir.Phi(register=reg, args=[
        pre_ir.PhiArgument(R("v", 0, "uint64"), 1),
        pre_ir.PhiArgument(pre_ir.BytesConstant(""), 2),   # empty-bytes placeholder
    ])
    b1 = pre_ir.BasicBlock(id=1, phis=[], ops=[], terminator=pre_ir.Goto(3))
    b2 = pre_ir.BasicBlock(id=2, phis=[], ops=[], terminator=pre_ir.Goto(3))
    b3 = pre_ir.BasicBlock(id=3, phis=[ph], ops=[],
                           terminator=pre_ir.SubroutineReturn(result=[]))
    main = pre_ir.Subroutine(id="main", parameters=[], returns=[], is_main=True,
                             body=[b1, b2, b3])
    prog = pre_ir.Program(main=main, subroutines=[])

    transforms.materialize_phi_consts(prog)
    # the materialized op on b2 must assign a uint64 const, not the bytes one
    mat = [o for o in b2.ops if isinstance(o, pre_ir.Assignment)]
    assert mat, "empty-bytes phi arg was not materialized"
    src = mat[0].source
    assert isinstance(src, pre_ir.UInt64Constant), (
        f"cross-family placeholder not coerced: {type(src).__name__} into uint64 target")
    assert mat[0].targets[0].ir_type == "uint64"


def test_canon_shuffle_arity():
    """`_canon_shuffle` gives a shuffle's TRUE arity + mapping from the opcode,
    independent of a (possibly fat-band-clamped) Assignment.inputs. The resim
    relies on this: the SSA's fat-band sim can under-count a shuffle's inputs on a
    shallow model stack (e.g. dup2 recorded with 1 input), which made the resim
    drop the op and lose stack depth -- starving a downstream callsub's args
    (app_3550180073's l-stack). Assert the canonical shapes."""
    from tealql.tealtools.ssa import _canon_shuffle
    assert _canon_shuffle("dup2", "") == (2, [0, 1, 0, 1])
    assert _canon_shuffle("swap", "") == (2, [1, 0])
    assert _canon_shuffle("dup", "") == (1, [0, 0])
    assert _canon_shuffle("dupn", "6") == (1, [0] * 7)
    assert _canon_shuffle("dig", "2") == (3, [2, 0, 1, 2])
    assert _canon_shuffle("cover", "2") == (3, [1, 2, 0])
    assert _canon_shuffle("uncover", "2") == (3, [2, 0, 1])
    assert _canon_shuffle("frame_dig", "0")[1] is None       # band-dependent: opt out


def test_resim_shuffle_canonical_lifts_v11(tmp_path):
    """End-to-end: a v11 contract whose resim under-counted a `dup2` (1 input)
    starved a `callsub` of its arg -> "l-stack too small". The canonical-arity
    resim fixes the depth so the callsub args reconstruct. app_3550180073 lifts +
    lowers + is behaviourally faithful once the resim uses the true shuffle arity."""
    probe = (Path(__file__).resolve().parent / "mainnet-random-probes"
             / "app_3550180073.teal")
    if not probe.exists():
        import pytest
        pytest.skip("probe not present")
    from tealql.tealtools.ssa import SSAProgram
    from tealql.tealtools.lift.lift import lift
    from tealql.tealtools.lift import pre_ir
    ir = lift(SSAProgram(str(probe)))
    # every callsub to a 1-param sub must carry exactly 1 arg (no starved 0-arg call)
    for s in ir.subroutines:
        if len(s.parameters) != 1:
            continue
        for b in pre_ir.blocks(ir):
            for o in b.ops:
                inv = (o.intrinsic if isinstance(o, pre_ir.IntrinsicOp)
                       and isinstance(o.intrinsic, pre_ir.InvokeSubroutine) else
                       getattr(o, "source", None))
                if isinstance(inv, pre_ir.InvokeSubroutine) and inv.target == s.id:
                    assert len(inv.args) == 1, f"callsub {s.id} starved: {len(inv.args)} args"


def test_pseudo_ops_normalized_and_recovered(tmp_path):
    """The tree-sitter grammar parses `byte`/`method`/`addr` as ERROR nodes and
    drops them (starving consumers -- the old folks ABI-dispatch gap). The source
    chokepoint normalizes them to the canonical push the assembler emits, so they
    survive as real opcodes with const values. Assert the rewrite is exact and the
    lift recovers the constants."""
    from tealql.tealtools.graph import _normalize_pseudo_ops
    n = _normalize_pseudo_ops(
        b'#pragma version 8\nbyte 0x4142\nmethod "transfer(uint64)void"\nint 1\n').decode()
    assert "pushbytes 0x4142" in n                 # byte literal -> pushbytes
    assert "pushbytes 0x25e350cf" in n             # method selector sha512_256[:4]
    assert "\nint 1\n" in n                        # int is grammar-native, untouched

    from tealql.tealtools.ssa import SSAProgram
    p = tmp_path / "pseudo.teal"
    p.write_text('#pragma version 8\nmethod "foo()void"\ntxna ApplicationArgs 0\n==\nreturn\n')
    prog = SSAProgram(str(p))
    consts = [getattr(o, "const_value", None) for a in prog.assignments
              if a.op == "pushbytes" for o in a.outputs]
    assert any(getattr(c, "value", None) == "0x84467aff" for c in consts if c), (
        "method selector not recovered as a pushbytes constant")
