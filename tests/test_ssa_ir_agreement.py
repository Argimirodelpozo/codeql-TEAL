"""The SSA and the lifted IR must name the SAME value for an op's operands.

The SSA simulates the stack once (``ssa.stacksim``) for the SSA-level analyses;
the lift re-simulates in its OWN register space (``_resim``), and 100% of the
IR's emitted operands come from that re-simulation — the SSA's wiring is not
consulted — so nothing forces the two to agree. (It used to be worse: the SSA
half was itself two models, Braun plus a fat-band block sim, and they could
disagree with each other as well. Those are gone.)

``test_frame_base_alignment`` pins the SSA's phis against its own exit stacks.
Nothing pinned SSA against the lift ACROSS the boundary, and a real bug lived
there: a
block that appeared in five subroutine bodies was re-simulated in four that could
not reach it, so it started on an empty stack and ``frame_dig 0`` — which resolves
by absolute index — read whatever was pushed next. The ARC-4 return-logging idiom
``callsub; frame_bury 0; pushbytes 0x151f7c75; frame_dig 0; itob`` lifted to
``(itob 0x151f7c75)``: the prefix, not the returned value. It sat in the corpus
until puya happened to object to the one instance that crossed a type boundary —
the same mis-wire between two bytes values would have been silent.

MEASURE THROUGH EVERY RENAMING LAYER or this reports representation, not
correctness (the metric was wrong twice before it was right):

* compare on the EMITTED IR, not ``resim_args`` — that map is keyed by assignment
  id, so the correct owner's re-simulation overwrites it and the artifact is
  invisible there;
* a SHUFFLE output IS ``inputs[m[i]]``, and the lift routes consumers to the
  source without emitting the shuffle (raw identity: 803 false hits);
* a ``frame_dig`` output is an opaque SSA handle that the lift resolves to the
  value buried in that slot.
"""
import glob
import random
from pathlib import Path

import pytest

from tealql.tealtools.lift import pre_ir
from tealql.tealtools.lift.lift import _Lifter
from tealql.tealtools.passes.frame_flow import frame_value_sources
from tealql.tealtools.ssa import SSAProgram, SSAVar
from tealql.tealtools.ssa.models import _shuffle_mapping

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"

#: Rewritten by design (frame band, stack shuffles) or carrying their own calling
#: convention — the two models describe these differently on purpose.
_SKIP = frozenset({"frame_dig", "frame_bury", "dup", "dup2", "dupn", "swap",
                   "cover", "uncover", "dig", "bury", "callsub", "retsub",
                   "proto", "intcblock", "bytecblock"})

#: Residual on the sampled probes, all register/phi aliasing and lift-side const
#: folding the SSA's own propagation did not reach. A CEILING, not a target: the
#: point is that it must not climb, because a climb means the two halves of the
#: pipeline have started describing different programs.
_CEILING = 20


def _leaf(v, depth=0):
    """Follow the shuffle renaming to the source (``outputs[i] == inputs[m[i]]``)."""
    seen: set = set()
    while isinstance(v, SSAVar) and depth < 64:
        d = v.defined_by
        if d is None or id(v) in seen:
            break
        seen.add(id(v))
        m = _shuffle_mapping(d)
        if m is None:
            break
        try:
            i = d.outputs.index(v)
        except ValueError:
            break
        if i >= len(m) or m[i] >= len(d.inputs):
            break
        nxt = d.inputs[m[i]]
        if not isinstance(nxt, SSAVar):
            break
        v, depth = nxt, depth + 1
    return v


def _disagreements(path):
    """``(compared, [case])`` over one contract's emitted IR."""
    prog = SSAProgram(str(path))
    prog.propagate_constants()
    frame_src = {id(k): list(v) for k, v in frame_value_sources(prog).items()}
    lifter = _Lifter(prog)
    ir = lifter.build()
    reg2var = {id(r): sv for sv, r in lifter.regs.items()}
    compared = 0
    cases: list = []
    for sub in [ir.main] + list(ir.subroutines):
        for b in sub.body:
            for o in b.ops:
                intr = (o.source if isinstance(o, pre_ir.Assignment) else
                        o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
                if not isinstance(intr, pre_ir.Intrinsic) or not intr.line:
                    continue
                a = intr.origin
                if (a is None or a.op in _SKIP or a.op != intr.op
                        or len(intr.args) != len(a.inputs)):
                    continue
                for i, (ir_v, ssa_v) in enumerate(zip(intr.args, a.inputs)):
                    if not isinstance(ssa_v, SSAVar):
                        continue
                    tgt = _leaf(ssa_v)
                    fs = frame_src.get(id(tgt)) or frame_src.get(id(ssa_v))
                    if fs and len(fs) == 1:
                        tgt = _leaf(fs[0])
                    if isinstance(ir_v, pre_ir.Register):
                        sv = reg2var.get(id(ir_v))
                        if sv is None:
                            continue
                        compared += 1
                        if _leaf(sv) is not tgt:
                            cases.append(f"{path.name} [{sub.id}] L{intr.line} "
                                         f"{intr.op} arg[{i}]: ssa={ssa_v!r} ir={sv!r}")
                    elif isinstance(ir_v, (pre_ir.UInt64Constant,
                                           pre_ir.BytesConstant)):
                        compared += 1
                        if getattr(tgt, "const_value", None) is None:
                            cases.append(f"{path.name} [{sub.id}] L{intr.line} "
                                         f"{intr.op} arg[{i}]: ssa={ssa_v!r} "
                                         f"ir=CONST {ir_v}")
    return compared, cases


def _sample(n=10):
    files = sorted(glob.glob(str(PROBES / "*.teal")))
    if len(files) < n:
        pytest.skip("probe corpus not present")
    random.Random(4).shuffle(files)
    return [Path(f) for f in files[:n]]


def test_the_two_stack_models_name_the_same_operands():
    total = 0
    found: list = []
    for probe in _sample():
        try:
            compared, cases = _disagreements(probe)
        except Exception:
            continue                  # a contract that does not lift is not this test's subject
        total += compared
        found.extend(cases)
    assert total > 1000, f"metric went vacuous ({total} operands compared)"
    assert len(found) <= _CEILING, (
        f"{len(found)} operand(s) are named differently by the SSA and by the "
        f"lifted IR (ceiling {_CEILING}) — the two stack models have started "
        f"describing different programs:\n  " + "\n  ".join(found[:10]))


def test_a_recursive_call_returns_a_value_not_a_hole(tmp_path):
    """A recursive subroutine's result must be EXPRESSED, not refused.

    `count_len(b) = b=="" ? 0 : 1 + count_len(b[1:])`. A cycle has no
    callee-first order, so when the simulator reaches the inner `callsub` the
    callee's own `retsub` blocks have not run — and pushing None there is not
    "honest unknown": the value is DEFINED IN TERMS OF ITSELF, which is what a
    phi is for. The call site mints the phi and fills it once every routine has
    run, giving φ(0, φ+1).

    Nothing here covered this, so 4072 green tests and a behaviourally identical
    localnet dryrun all missed it — the recompiled program still ran correctly;
    what was lost was structure only an IR-level consumer sees. avm-prover
    caught it: it proves `r == len(arg0)` by k-induction over this exact
    program, and with a None there the invariant vanished and the proof came
    back `counterexample` in a fifth of the time.
    """
    teal = tmp_path / "rec.teal"
    teal.write_text(
        "#pragma version 10\n"
        "txna ApplicationArgs 0\ncallsub count_len\npop\npushint 1\nreturn\n"
        "count_len:\nproto 1 1\nframe_dig -1\nlen\npushint 0\n==\nbnz base\n"
        "frame_dig -1\npushint 1\nframe_dig -1\nlen\npushint 1\n-\nextract3\n"
        "callsub count_len\npushint 1\n+\nretsub\n"
        "base:\npushint 0\nretsub\n")
    prog = SSAProgram(str(teal))

    calls = [a for a in prog.assignments if a.op == "callsub"]
    assert len(calls) == 2, f"expected an outer and a recursive call, got {calls}"

    # The `+` that consumes the recursive result must HAVE that operand.
    plus = [a for a in prog.assignments if a.op == "+"]
    assert len(plus) == 1 and len(plus[0].inputs) == 2, (
        "the add after the recursive call lost an operand — the call result was "
        f"refused: {plus}")
    add_out = plus[0].outputs[0]

    # …and that operand must be a phi over BOTH returns: the base case and the
    # cycle. Self-reference is the point — a phi whose only argument is the base
    # case would describe a function that never recurses.
    result = plus[0].inputs[1]
    args = [str(a) for a in getattr(result, "args", [])]
    assert args, f"the recursive call's result is not a merge: {result!r}"
    assert str(add_out) in args, (
        f"the phi does not close the cycle — it must stand for the `+` result "
        f"({add_out}) as well as the base case, got {args}")
    assert len(set(args)) == 2, (
        f"expected exactly the base value and the recursive value, got {args}")

    # It must also lift; a phi that no consumer can lower is not an answer.
    ir = _Lifter(prog).build()
    assert any("count_len" in s.id for s in ir.subroutines), ir.subroutines


def test_a_block_lifted_by_a_group_that_cannot_reach_it_is_caught():
    """The metric must catch the bug it exists for.

    app_1850858495 has a block that the continuation heuristic put in five
    bodies; four cannot reach it. Before the group filter those four emitted
    ``(itob 0x151f7c75)`` for it. This asserts the contract is clean now AND
    that the check is looking at that contract at all — a metric that skipped
    it would pass vacuously."""
    probe = PROBES / "app_1850858495.teal"
    if not probe.exists():
        pytest.skip("app_1850858495 not present")
    compared, cases = _disagreements(probe)
    assert compared > 100, f"only {compared} operands compared — check went vacuous"
    assert not cases, "\n  ".join(cases)


def test_bottom_position_phi_is_shared_across_ssa_pre_ir_and_return():
    """A height-divergent join has no valid top-index for ``frame_dig 0``.

    SSA already represents the two exact bottom cells as a position phi. The
    lift must lower THAT merge at the region entry, use it for both the dig and
    proto return, and expose the SSA/pre-IR identity through the annotation
    bridge. Versioned ``l%`` locals would be a second frame semantics here.
    """
    prog = SSAProgram.from_text(
        "#pragma version 8\n"
        "callsub s\npop\nint 1\nreturn\n"
        "s:\nproto 0 1\ntxn NumAppArgs\nbnz two\n"
        "int 7\nb join\ntwo:\nint 9\nint 8\n"
        "join:\nframe_dig 0\nretsub\n",
        name="position-phi.teal",
    )
    dig = next(a for a in prog.assignments if a.op == "frame_dig")
    assert dig.inputs and getattr(dig.inputs[0], "args", None), (
        "fixture no longer has SSA's bottom-position merge")

    lifter = _Lifter(prog)
    ir = lifter.build()
    assert ir.pass_stats["frame_position_phis"] == 1
    assert ir.pass_stats["frame_slot_refusals"] == 0

    register = lifter.frame_map.get(dig.outputs[0])
    phis = [phi for sub in [ir.main, *ir.subroutines]
            for block in sub.body for phi in block.phis
            if phi.register is register]
    assert len(phis) == 1 and len(phis[0].args) == 2, (
        "the two exact predecessor cells must be one edge-correlated pre-IR phi")
    assert dig.inputs[0] in lifter.register_sources[id(register)], (
        "the SSA position phi and its pre-IR lowering lost their bridge")

    sub = ir.subroutines[0]
    returns = [block.terminator for block in sub.body
               if isinstance(block.terminator, pre_ir.SubroutineReturn)]
    assert len(returns) == 1 and returns[0].result == [register], (
        "proto retsub must read the same bottom-position phi as frame_dig")
    assert not any(reg.local_id.startswith("l%") for reg in pre_ir.registers(ir)), (
        "the removed versioned-frame fallback reappeared")


def test_a_shared_tail_is_counted_in_the_dip_that_reaches_it(tmp_path):
    """A legacy sub's arity is how far execution dips, NOT how far the OWNED
    body dips.

    A shared tail — one block that several routines `b` into, ending in
    `retsub` — belongs to exactly one of them under `pyblock_partition`. Measure
    the dip over the owned body and every other caller stops at the branch and
    under-counts, so the simulation consumes too few arguments and STRANDS the
    rest on the caller's stack. That shifts every later operand in the caller,
    which is silent: a too-DEEP stack yields wrong operands, not missing ones,
    so the operand-hole ratchet reads clean.

    Live case: app_1050006430 `label23` popped 1 over its one-block body while
    its call sites pushed FOUR, leaving three stranded. Here `t` pops one and
    branches into `tail`, which pops two more — so `t` takes three."""
    teal = tmp_path / "shared_tail.teal"
    teal.write_text(
        "#pragma version 8\n"
        "int 7\nint 8\nint 9\ncallsub u\n"
        "int 1\nint 2\nint 3\ncallsub t\n"
        "int 1\nreturn\n"
        "u:\npop\nb tail\n"
        "t:\npop\nb tail\n"
        "tail:\npop\npop\nretsub\n")
    prog = SSAProgram(str(teal))
    # BOTH routines must be called, or the second is unreachable and pruned —
    # and then the tail is not shared at all and the test is vacuous. `tail` is
    # owned by `u`, so `t` is the routine whose OWNED body stops at the branch.
    calls = sorted((a for a in prog.assignments if a.op == "callsub"),
                   key=lambda a: a.location.line)
    assert len(calls) == 2, calls
    for a in calls:
        assert len(a.inputs) == 3, (
            f"callsub@L{a.location.line} consumed {len(a.inputs)} of 3 — the dip "
            "stopped at the branch into the shared tail, so the rest stayed on "
            "the caller's stack")
