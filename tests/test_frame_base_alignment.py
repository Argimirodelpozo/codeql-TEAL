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

The count must be taken in the PRIVATE PySSA representation (2026-07-31, the
callsub stack-model change). Two public-representation artifacts count phantom
disagreements:

* ``_build_assignments`` DROPS None inputs, so a fat frame op whose band holds
  an unmaterialised slot gets a shape-mismatched public input list —
  ``_shuffle_mapping`` refuses it and resolution stops at an intermediate var;
* the fat expansion re-mints ``op.outputs``, leaving equal-by-key twin PyVars
  (the phase-2 survivors Braun handed out) that an ``id()``-keyed resolver
  treats as distinct leaves.

Resolved over the None-preserving PyOps with key identity, main measured 0
violations — the historical "2" were both artifacts — and the call-aware stack
model keeps it at 0, so the ceilings pin ZERO.
"""
from pathlib import Path

import pytest

from tealql.tealtools.ssa import SSAProgram
from tealql.tealtools.ssa.models import Phi, _shuffle_mapping
from tealql.tealtools.ssa.ssa import PyPhi

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
    """Phi-pred edges where the predecessor's exit slot cannot stand for ANY of
    the slot-k phi's args, i.e. the 6c simulator and Braun genuinely disagree
    about which value flows on that edge.

    Measured in the PRIVATE PySSA representation (None-preserving fat-op
    mappings, ``(file, line, idx)`` key identity — see the module docstring for
    the two public-representation artifact classes this avoids). On a verified
    ``retsub`` edge into a paired continuation, a slot ``k > R`` carries the
    callsub block's exit slot ``k - R + A`` (the caller's pre-call band), which
    is what the builder's ``_read_edge`` threads there — the retsub block's own
    exit stack is the callee's frame and cannot express that per-edge value."""
    py = prog._pyssa
    pairs = getattr(py, "_call_pairs", {}) or {}
    withdrawn = getattr(py, "_value_unsafe_conts", set()) or set()
    prod = {}
    for b in py.blocks:
        for o in b.ops:
            for i, v in enumerate(o.outputs):
                prod[v.key()] = (o, i)
    memo = {}

    def _vkey(v):
        return ("phi",) + v.key() if isinstance(v, PyPhi) else v.key()

    def _res(v, stack=frozenset()):
        k = _vkey(v)
        if k in memo:
            return memo[k]
        if k in stack:
            return set()
        st = stack | {k}
        if isinstance(v, PyPhi):
            out = set()
            for a in v.args:
                if a is not None:
                    out |= _res(a, st)
        else:
            out = None
            d = prod.get(k)
            if d is not None:
                o, i = d
                m = _shuffle_mapping(o)
                if m is not None and i < len(m) and m[i] < len(o.inputs):
                    src = o.inputs[m[i]]
                    if src is not None:
                        out = _res(src, st)
            if out is None:
                out = {k}
        if not stack:
            memo[k] = out
        return out

    by_key = {b.key: b for b in py.blocks}
    bad = 0
    for ph in prog.phis.values():                  # live public phis only
        if ph.kind != "DirectPhi":
            continue
        pyph = prog._phi_to_pyphi.get(ph)
        if pyph is None:
            continue
        b = by_key.get(pyph.bb_key)
        if b is None:
            continue
        k = pyph.slot
        arg_vals = _res(pyph)
        pair = pairs.get(b.key)
        for pred in b.preds:
            if pair is not None and k > pair[2] and pred.key in pair[3]:
                if b.key in withdrawn:
                    continue        # builder REFUSES these; nothing to compare
                cs, slot = pair[0], k - pair[2] + pair[1]
                v = cs.exit_stack[-slot] if len(cs.exit_stack) >= slot else None
            else:
                v = pred.exit_stack[-k] if len(pred.exit_stack) >= k else None
            if v is not None and not (_res(v) & arg_vals):
                bad += 1
    return bad


#: The two contracts that carried essentially all of this divergence. ZERO is
#: not aspirational: main measured 0 under the artifact-free metric, and the
#: call-aware stack model must hold that — one half of the builder disagreeing
#: with the other is how silently wrong values ship.
_CEILINGS = {"app_3300088574.teal": 0, "app_2750067654.teal": 0}


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
    """The clearest proof the slid index cost real analysis rather than tidiness.

    app_2450560800 label11 does:

        txna ApplicationArgs 1 ; frame_bury 1 ; frame_dig 1
        callsub label77 ; frame_bury 0 ; bytec 0x151f7c75 ; frame_dig 0
        concat ; log

    i.e. attacker input is parked in a frame slot, read back, passed through a
    callee and logged as the ARC-4 return. With the bottom-anchored index the
    `frame_dig 1` resolved to a neighbouring slot and the chain broke, so the
    engine saw no flow here at all.

    Asserts the TAINT REACHES the sink, not that a vulnerability is reported.
    Those are different claims and this test used to conflate them: label77
    asserts the sender on its single return, so the flow is legitimately GUARDED
    and `.detect()` rightly says nothing. Pinning the verdict made this test fail
    the moment a callee-sender guard started being credited — for a fix that was
    correct. What the frame index owns is whether the value arrives at all."""
    from tealql.security.common import ir_lifter
    from tealql.tealtools.lift import fund_flow as FF

    probe = PROBES / "app_2450560800.teal"
    if not probe.exists():
        pytest.skip("app_2450560800 not present")
    prog = SSAProgram(str(probe))
    prog.propagate_constants()
    lifter = ir_lifter(prog)
    assert lifter is not None, "contract no longer lifts"

    def sink_of(s):
        return (("log", "MEDIUM", list(s.args)),) if s.op == "log" else ()

    flows = FF._tainted_sink_flows(lifter, sink_of)
    at_1442 = [f for f in flows if f.sub_id == "label11"]
    assert at_1442, (
        "attacker input no longer reaches the `log` in label11 through the "
        "frame-slot roundtrip — the frame target index has slid again")
    # And it is guarded for the RIGHT reason: the callee pins the sender.
    assert all(f.guarded for f in at_1442)
    assert any("sender" in g.describe() for f in at_1442 for g in f.guards)
