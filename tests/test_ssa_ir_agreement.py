"""The SSA and the lifted IR must name the SAME value for an op's operands.

There are two independent stack simulations in this pipeline. The SSA's serves
the SSA-level analyses; the lift's ``_resim`` serves the IR, because PySSA's
fat-band model and ``STACK_MAX`` cap produce operands Puya's ``destructure_ssa``
rejects. 100% of the IR's emitted operands come from the re-simulation — the SSA's
stack wiring is not consulted — so nothing forced the two to agree.

``test_frame_base_alignment`` pins Braun against phase 6c INSIDE the SSA. Nothing
pinned SSA against the lift ACROSS the boundary, and a real bug lived there: a
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
    by_line: dict = {}
    for a in prog.assignments:
        by_line.setdefault(a.location.line, a)

    compared = 0
    cases: list = []
    for sub in [ir.main] + list(ir.subroutines):
        for b in sub.body:
            for o in b.ops:
                intr = (o.source if isinstance(o, pre_ir.Assignment) else
                        o.intrinsic if isinstance(o, pre_ir.IntrinsicOp) else None)
                if not isinstance(intr, pre_ir.Intrinsic) or not intr.line:
                    continue
                a = by_line.get(intr.line)
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
