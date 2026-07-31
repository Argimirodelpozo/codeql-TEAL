"""One frame model, not two (2026-07-30 ssa/+lift review, finding 4).

``_try_expand_frame_op`` (phase 6c's fat-band expander) used to locate a frame
op's target BOTTOM-UP, at ``len(sub.entry_stack) + N``. Every other part of the
builder locates it TOP-DOWN, at top-first slot ``edepth(bb) - (nargs + N)`` —
``_phase_braun`` demands the read at exactly that slot, and
``_build_frame_exit_sim`` / ``_read_exit`` index by it.

The bottom-up anchor is wrong because Braun materialises only the entry slots
something demanded, so ``len(sub.entry_stack)`` is not ``nargs`` (shorter for 90
of 202 proto'd subs in the probe corpus) and ``local_stack`` holds only the TOP of
the routine band. The index therefore slid, and the two simulators disagreed:
a ``frame_dig`` read a neighbouring slot, which both broke value flow and left a
successor's slot-k phi unable to find its per-edge value at
``pred.exit_stack[-k]``.

Both tests here are OUTCOME tests on committed real contracts, because that is
what the divergence actually cost.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.models import Phi

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"


def _leaves(v, seen=None):
    """Transitive SSAVar leaves of a value, mirroring what
    ``_collapse_phi_args_to_leaves`` does to a public ``Phi.args``."""
    seen = set() if seen is None else seen
    if id(v) in seen:
        return set()
    seen.add(id(v))
    if isinstance(v, Phi):
        out = set()
        for a in v.args:
            out |= _leaves(a, seen)
        return out
    return {id(v)}


def _real_edge_violations(prog) -> int:
    """Phi-pred edges where ``pred.exit_stack[-k]`` shares NO leaf with the
    slot-k phi's args, i.e. the 6c simulator and Braun disagree about which
    VALUE flows on that edge.

    Leaf-aware on purpose. A strict identity check (`exit_stack[-k] in phi.args`)
    reports ~4x more, but most of that is by design: exit_stack legitimately
    holds an intermediate Phi whose leaves ARE the collapsed args. Counting
    those as violations is what made this look like an 18% problem when the real
    figure was 4%."""
    owner = {}
    for bb in prog.blocks.values():
        for ph in bb.phis:
            owner[id(ph)] = bb
    bad = 0
    for ph in prog.phis.values():
        if ph.kind != "DirectPhi":
            continue
        bb = owner.get(id(ph))
        if bb is None:
            continue
        k = ph.stack_index
        arg_leaves = set()
        for a in ph.args:
            arg_leaves |= _leaves(a)
        for pred in bb.predecessors:
            if len(pred.exit_stack) >= k and pred.exit_stack[-k] is not None:
                if not (_leaves(pred.exit_stack[-k]) & arg_leaves):
                    bad += 1
    return bad


#: Worst contract in the probe corpus for this divergence, and the ceiling the
#: top-down anchor achieves. Pre-fix it was 248; the remaining 107 are a
#: SEPARATE divergence (phase 6c seeds a single-pred block from its pred's
#: exit_stack, which can disagree with the Braun-resolved entry) and are the
#: follow-up. A ceiling, not an equality: the point is that it must never climb
#: back toward the bottom-anchored figure.
_WORST_PROBE = "app_3300088574.teal"
_MAX_REAL_VIOLATIONS = 110


def test_frame_base_keeps_the_two_simulators_agreeing():
    probe = PROBES / _WORST_PROBE
    if not probe.exists():
        pytest.skip(f"{_WORST_PROBE} not present")
    n = _real_edge_violations(SSAProgram(str(probe)))
    assert n <= _MAX_REAL_VIOLATIONS, (
        f"{_WORST_PROBE}: {n} phi-pred edges carry a value the slot's phi does "
        f"not contain (ceiling {_MAX_REAL_VIOLATIONS}, bottom-anchored was 248) "
        "— the frame simulators have diverged again")


def test_taint_survives_a_bury_dig_roundtrip_into_a_call():
    """A recovered FALSE NEGATIVE, and the clearest proof the slid index cost
    real analysis rather than tidiness.

    app_2450560800 label11 does:

        txna ApplicationArgs 1 ; frame_bury 1 ; frame_dig 1
        callsub label77 ; frame_bury 0 ; bytec 0x151f7c75 ; frame_dig 0
        concat ; log

    i.e. attacker input is parked in a frame slot, read back, passed through a
    `proto 1 1` callee and logged as the ARC-4 return. With the bottom-anchored
    index the `frame_dig 1` resolved to a neighbouring slot, the chain broke, and
    `ir-tainted-log` reported nothing on this contract."""
    from tealql.security import DETECTORS

    probe = PROBES / "app_2450560800.teal"
    if not probe.exists():
        pytest.skip("app_2450560800 not present")
    prog = SSAProgram(str(probe))
    prog.propagate_constants()
    vs = DETECTORS["ir-tainted-log"](prog, file=probe.name).detect()
    assert vs, ("attacker input reaching `log` through a frame-slot roundtrip "
                "went unreported — the frame target index has slid again")
