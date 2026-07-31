"""Where phase 6c locates a frame op's target (2026-07-30 ssa/+lift review, #4).

A frame op addresses an ABSOLUTE position in the routine band: ``nargs + N``
counted from the band's bottom. Phase 6c indexes ``local_stack``, which holds
only the TOP of that band, because Braun materialises just the entry slots
something demanded. So the index needs both halves:

    target_idx = nargs + N - (edepth(bb) - len(seed))

Each half has been wrong on its own, and each way silently corrupted values:

* Bottom-anchored with NO correction (``len(sub.entry_stack) + N``, the original)
  slides whenever the seed is short — and it is, ``len(sub.entry_stack)`` being
  shorter than ``nargs`` for 90 of 202 proto'd subs in the probe corpus. A
  ``frame_dig`` then read a neighbouring slot.
* Converting a TOP-first slot against ``len(local_stack)`` instead (the first
  attempt at fixing the above) only matches at a block's first op, since an
  entry-depth slot does not track the stack as ops push and pop. A
  ``frame_bury`` after a few pushes went out of range and fell back to the narrow
  path, where ``frame_bury`` is a bare pop with NO definition — losing the buried
  value outright.

Both failures show up as the 6c simulator and Braun disagreeing about which
value flows on an edge, which is what these tests measure — as outcomes on
committed real contracts, because that is what the divergence actually cost.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.models import Phi, _shuffle_mapping

PROBES = Path(__file__).resolve().parent / "mainnet-random-probes"


def _resolve(v, depth=0):
    """The values ``v`` can actually stand for, following BOTH renaming layers a
    naive comparison trips over: a phi fans out to its args, and a stack-shuffle
    output is by definition ``inputs[m[i]]`` (the fat frame expansion mints fresh
    band vars, so a frame op's result is NEVER the object it copied)."""
    if depth > 24 or v is None:
        return {id(v)}
    if isinstance(v, Phi):
        out = set()
        for a in v.args:
            out |= _resolve(a, depth + 1)
        return out
    d = getattr(v, "defined_by", None)
    if d is not None:
        m = _shuffle_mapping(d)
        if m is not None:
            try:
                i = d.outputs.index(v)
            except ValueError:
                i = None
            if i is not None and i < len(m) and m[i] < len(d.inputs):
                return _resolve(d.inputs[m[i]], depth + 1)
    return {id(v)}


def _real_edge_violations(prog) -> int:
    """Phi-pred edges where ``pred.exit_stack[-k]`` cannot stand for ANY of the
    slot-k phi's args, i.e. the 6c simulator and Braun genuinely disagree about
    which value flows on that edge.

    Both renaming layers must be resolved or this measures representation, not
    correctness. On the same 40-probe sample the three metrics read: strict
    identity 599, leaf-aware-only 134, fully resolved 2. The first two counted
    a value that IS the phi's arg — reached through a collapsed phi or a
    fat-band rename — as a disagreement, which made a 0.06% problem look like
    an 18% one."""
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
        arg_vals = set()
        for a in ph.args:
            arg_vals |= _resolve(a)
        for pred in bb.predecessors:
            if len(pred.exit_stack) >= k and pred.exit_stack[-k] is not None:
                if not (_resolve(pred.exit_stack[-k]) & arg_vals):
                    bad += 1
    return bad


#: The two contracts that carried essentially all of this divergence, and the
#: ceiling the corrected index achieves on each. A ceiling, not an equality: the
#: point is that it must never climb back. Measured on the 40-probe sample, total
#: fully-resolved violations went 34 -> 2 when the truncation correction landed.
_CEILINGS = {"app_3300088574.teal": 2, "app_2750067654.teal": 2}


@pytest.mark.parametrize("name,ceiling", sorted(_CEILINGS.items()))
def test_frame_base_keeps_the_two_simulators_agreeing(name, ceiling):
    probe = PROBES / name
    if not probe.exists():
        pytest.skip(f"{name} not present")
    n = _real_edge_violations(SSAProgram(str(probe)))
    assert n <= ceiling, (
        f"{name}: {n} phi-pred edges carry a value the slot's phi cannot stand "
        f"for (ceiling {ceiling}) — the frame simulators have diverged again")


def test_frame_bury_after_a_push_keeps_its_value():
    """The buried value must survive a ``frame_bury`` that happens once the block
    has already changed depth.

    app_2750067654 label39 is ``proto 0 0`` and does
    ``bytec_0 ; dupn 4 ; txn Sender ; frame_bury 0 ; intc_0 ; frame_bury 1``,
    so slot 1 holds the ``intc_0`` and the loop header at label46 phis it against
    the incremented value from label42. Locating the target by a TOP-first slot
    taken at block ENTRY put the index out of range here (the block is 6 deep by
    then), which fell through to the narrow path — where ``frame_bury`` is a bare
    pop with no definition — so the header saw a leftover ``dupn`` copy instead of
    the counter."""
    probe = PROBES / "app_2750067654.teal"
    if not probe.exists():
        pytest.skip("app_2750067654 not present")
    prog = SSAProgram(str(probe))
    pred = next((b for b in prog.blocks.values() if b.first_line == 806), None)
    header = next((b for b in prog.blocks.values() if b.first_line == 814), None)
    assert pred is not None and header is not None, "fixture shape changed"
    phi = next((p for p in header.phis if p.stack_index == 4), None)
    assert phi is not None, "no slot-4 phi at the loop header — shape changed"
    assert len(pred.exit_stack) >= 4
    arg_vals = set()
    for a in phi.args:
        arg_vals |= _resolve(a)
    assert _resolve(pred.exit_stack[-4]) & arg_vals, (
        "the frame_bury'd counter did not reach the loop header's slot-4 phi")


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
