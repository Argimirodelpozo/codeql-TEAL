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
