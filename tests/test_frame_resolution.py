"""Unit tests for ``tealtools.passes.frame_resolution.resolve_sub`` — the precise
frame-slot model the lift (and any opt-in consumer) reads instead of PySSA's
conservative fat-frame substrate.

``resolve_sub`` is a pure function of ``(blocks, nargs)``, so these run on
hand-built mock SSA — no CodeQL DB. They pin the contract the byte-identical
lift depends on: ``frame_dig -k`` -> param, other frame ops -> versioned local
(each ``frame_bury`` opens a version, each read takes the reaching one), plus
the fat-frame band passthrough.
"""
from tealtools.ssa import SSAVar
from tealtools.passes.frame_resolution import resolve_sub


def _v(line: int, idx: int = 1) -> SSAVar:
    return SSAVar("t.teal", line, idx)


class _Op:
    """Minimal stand-in for an SSA ``Assignment`` (only the fields resolve_sub reads)."""
    def __init__(self, op, imm="", inputs=(), outputs=()):
        self.op = op
        self.immediates = imm
        self.inputs = list(inputs)
        self.outputs = list(outputs)


class _Block:
    def __init__(self, *ops):
        self.assignments = list(ops)


def test_frame_dig_negative_reads_params():
    # nargs=2: dig -1 -> param nargs-1 = 1, dig -2 -> param 0. No locals.
    o1, o2 = _v(1), _v(2)
    res = resolve_sub([_Block(_Op("frame_dig", "-1", outputs=[o1]),
                              _Op("frame_dig", "-2", outputs=[o2]))], nargs=2)
    assert res.dig_param == {o1: 1, o2: 0}
    assert res.dig_local == {}
    assert res.bury == {}


def test_local_versioning_reaching_def():
    # bury 0 opens v0; the dig 0 after it reads v0; a second bury 0 opens v1;
    # the next dig 0 reads v1.
    b0 = _Op("frame_bury", "0", inputs=[_v(1)])
    d0 = _v(2)
    b1 = _Op("frame_bury", "0", inputs=[_v(3)])
    d1 = _v(4)
    res = resolve_sub([_Block(b0, _Op("frame_dig", "0", outputs=[d0]),
                              b1, _Op("frame_dig", "0", outputs=[d1]))], nargs=0)
    assert res.bury == {id(b0): (0, 0), id(b1): (0, 1)}
    assert res.dig_local == {d0: (0, 0), d1: (0, 1)}
    assert res.final == {0: 1}


def test_read_before_write_local_is_fresh_v0():
    d = _v(1)
    res = resolve_sub([_Block(_Op("frame_dig", "7", outputs=[d]))], nargs=0)
    assert res.dig_local == {d: (7, 0)}
    assert res.final == {7: 0}


def test_version_counters_are_per_slot():
    a = _Op("frame_bury", "0", inputs=[_v(1)])
    b = _Op("frame_bury", "1", inputs=[_v(2)])
    c = _Op("frame_bury", "0", inputs=[_v(3)])
    res = resolve_sub([_Block(a, b, c)], nargs=0)
    assert res.bury == {id(a): (0, 0), id(b): (1, 0), id(c): (0, 1)}
    assert res.final == {0: 1, 1: 0}


def test_fat_frame_band_passthrough():
    # dig: out[i] = in[i-1];  bury: out[i] = in[i+1].
    dug, p = _v(1), _v(2)
    i0 = _v(3)
    dig = _Op("frame_dig", "0", inputs=[i0], outputs=[dug, p])
    bp, ib0, ib1 = _v(4), _v(5), _v(6)
    bury = _Op("frame_bury", "0", inputs=[ib0, ib1], outputs=[bp])
    res = resolve_sub([_Block(dig, bury)], nargs=0)
    assert res.passthrough[p] is i0       # dig out[1] = in[0]
    assert res.passthrough[bp] is ib1     # bury out[0] = in[1]


def test_versioning_spans_blocks_in_order():
    # cur/version state carries across blocks in iteration order.
    b0 = _Op("frame_bury", "0", inputs=[_v(1)])
    d = _v(3)
    b1 = _Op("frame_bury", "0", inputs=[_v(2)])
    res = resolve_sub([_Block(b0), _Block(_Op("frame_dig", "0", outputs=[d]), b1)],
                      nargs=0)
    assert res.dig_local == {d: (0, 0)}   # reads v0 written in the first block
    assert res.bury[id(b1)] == (0, 1)


def test_pushed_local_with_band_routes_to_target_not_orphan():
    # A k>=0 pushed local never `frame_bury`-d, but its slot value is on the
    # simulated band (inputs top-first, so inputs[-1] = the deepest = the slot).
    # This is the `key in BoxMap` box-name pattern: the name is placed by a STACK
    # `bury`/`dup` (invisible to the frame_bury model) and read cross-block. It
    # must route out0 -> the band target, NOT mint an l%slot version no write
    # defines (the orphan that broke destructure / CHC).
    top, tgt, out0 = _v(1), _v(2), _v(3)
    dig = _Op("frame_dig", "0", inputs=[top, tgt], outputs=[out0])
    res = resolve_sub([_Block(dig)], nargs=0)
    assert res.passthrough[out0] is tgt          # dug value = band target (deepest in)
    assert out0 in res.pushed                    # flagged for the resim value() path
    assert out0 not in res.dig_local             # NOT an orphan versioned local


def test_negative_below_frame_read_stays_local_not_pushed():
    # A negative read that is NOT a param (k < -nargs: dig -2 with nargs=1, i.e.
    # below the frame base) keeps the prior dig_local behavior even with a band
    # present. The pushed-local routing is k>=0 ONLY: resolving a negative/param
    # read via its band target diverges from the IR construction path (it can
    # surface a bytes value into a u64 op -- the consensus_v3 regression).
    top, tgt, out0 = _v(1), _v(2), _v(3)
    dig = _Op("frame_dig", "-2", inputs=[top, tgt], outputs=[out0])
    res = resolve_sub([_Block(dig)], nargs=1)
    assert out0 not in res.pushed
    assert out0 not in res.passthrough
    assert res.dig_local.get(out0) == (-2, 0)    # prior behavior preserved


# --------------------------------------------------------------------------
# End-to-end regression: deep loop-invariant frame slot threading (commit
# ef1433e9). A frame slot kept at the working-stack BOTTOM across a loop and
# read only via `frame_dig N` (e.g. an address dug into `itxn_field Receiver`
# each lap) was silently lost to a zero constant -- the braun phi placement
# never demanded the deep slot's read, so phase 6a rebuilt a too-shallow
# entry_stack. Mainnet witness was app 3606534408 (itxn AssetReceiver/Sender
# -> 0). This is the minimal faithful repro: the lifted TEAL MUST carry the
# real 0x1111... address into the itxn field, never a zero.
_DEEP_FRAME_LOOP_REPRO = """#pragma version 10
  int 1
  int 2
  callsub helper
  pop
  int 1
  return
helper:
  proto 2 1
  byte 0x1111111111111111111111111111111111111111111111111111111111111111
  int 0
  b loop
loop:
  frame_dig 1
  int 2
  <
  bz done
  itxn_begin
  frame_dig 0
  dup
  itxn_field AssetReceiver
  itxn_field Sender
  int 1
  itxn_field TypeEnum
  int 0
  itxn_field Fee
  itxn_submit
  frame_dig 1
  int 1
  +
  frame_bury 1
  b loop
done:
  frame_dig -1
  frame_bury 0
  retsub
"""


def test_deep_loop_invariant_frame_slot_not_zeroed(tmp_path):
    import re
    from tests.behavioral_lift.compare import lift_to_teal

    src = tmp_path / "deep_frame_loop.teal"
    src.write_text(_DEEP_FRAME_LOOP_REPRO)
    lifted = lift_to_teal(str(src))

    # The address must survive into the inner-txn fields.
    assert "0x1111111111111111111111111111111111111111111111111111111111111111" in lifted, \
        "deep loop-invariant frame slot (the address) was dropped from the lift"
    # No itxn address field may be fed a zero constant.
    lines = lifted.splitlines()
    for i, ln in enumerate(lines):
        if re.search(r"itxn_field (AssetReceiver|Sender|Receiver)\b", ln):
            prev = lines[i - 1].strip()
            assert not re.match(r"(intc_0\b|int 0\b|pushint 0\b|bytec_0 // 0x0000)", prev), \
                f"itxn address field fed a zero constant ({prev!r}) -- frame slot lost"
