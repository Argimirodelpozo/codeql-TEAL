"""Unit tests for byte-interval ("partial") taint — the standalone prototype
in ``tealtools.dataflow.byte_taint``.

Two layers: the pure :class:`Intervals` algebra (union / intersect / clip /
subtract / shift / overlaps / normalization), and the forward propagation
end-to-end over in-memory TEAL — proving the headline property: the clean
and attacker-controlled halves of a packed byte array are tracked
separately, including the byte-range -> scalar bridge (``getbyte`` /
``extract_uint*`` of a clean offset is NOT tainted).
"""
from tealtools.ssa import SSAProgram
from tealtools.dataflow.byte_taint import Intervals, byte_taint, INF


class TestIntervals:
    def test_normalize_merges_overlap_and_adjacency(self):
        assert Intervals([(0, 8), (8, 16)]).parts == ((0, 16),)      # adjacent
        assert Intervals([(0, 10), (5, 16)]).parts == ((0, 16),)     # overlap
        assert Intervals([(8, 16), (0, 4)]).parts == ((0, 4), (8, 16))  # sorted, disjoint
        assert Intervals([(5, 5)]).parts == ()                       # empty dropped

    def test_union_intersect(self):
        a, b = Intervals([(0, 8)]), Intervals([(4, 12)])
        assert a.union(b).parts == ((0, 12),)
        assert a.intersect(b).parts == ((4, 8),)
        assert Intervals([(0, 4)]).intersect(Intervals([(8, 12)])).parts == ()

    def test_clip_subtract_shift(self):
        a = Intervals([(0, 16)])
        assert a.clip(4, 12).parts == ((4, 12),)
        assert a.subtract(4, 8).parts == ((0, 4), (8, 16))
        assert a.shift(8).parts == ((8, 24),)

    def test_overlaps(self):
        a = Intervals([(8, INF)])
        assert not a.overlaps(0, 8)      # [8,inf) does NOT touch [0,8)
        assert a.overlaps(0, 9)
        assert a.overlaps(20, 21)

    def test_open_end(self):
        w = Intervals.whole()            # [0, INF)
        assert w.overlaps(1000, 1001)
        assert w.clip(0, 8).parts == ((0, 8),)
        assert w.shift(8).parts == ((8, INF),)


def _taint(teal):
    p = SSAProgram.from_text(teal, name="t")
    return p, byte_taint(p)


def _by_op(p, op, imm=None):
    return [a for a in p.assignments if a.op == op and (imm is None or a.immediates == imm)]


_PREFIX = "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\n"  # 8-byte clean ++ arg


class TestForwardPropagation:
    def test_application_args_is_source(self):
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\npop\nint 1\nreturn\n")
        arg = _by_op(p, "txna")[0].outputs[0]
        assert r.tainted_bytes(arg) == Intervals.whole()   # fully tainted, open length

    def test_concat_partitions_clean_prefix_from_tainted_suffix(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "pop\nint 1\nreturn\n")
        out = _by_op(p, "concat")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(8, INF)])  # bytes 0..7 clean

    def test_extract_clean_prefix_is_untainted(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "extract 0 8\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "0 8")[0].outputs[0]
        assert not r.tainted_bytes(out)                       # the validated selector

    def test_extract_tainted_region_carries_taint(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "extract 8 8\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "8 8")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(0, 8)])    # re-based to the slice

    def test_getbyte_bridge_offset_sensitive(self):
        clean = "#pragma version 8\n" + _PREFIX + "int 3\ngetbyte\npop\nint 1\nreturn\n"
        dirty = "#pragma version 8\n" + _PREFIX + "int 20\ngetbyte\npop\nint 1\nreturn\n"
        pc, rc = _taint(clean)
        pd, rd = _taint(dirty)
        assert not rc.is_scalar_tainted(_by_op(pc, "getbyte")[0].outputs[0])
        assert rd.is_scalar_tainted(_by_op(pd, "getbyte")[0].outputs[0])

    def test_extract_uint64_bridge_offset_sensitive(self):
        clean = "#pragma version 8\n" + _PREFIX + "int 0\nextract_uint64\npop\nint 1\nreturn\n"
        dirty = "#pragma version 8\n" + _PREFIX + "int 8\nextract_uint64\npop\nint 1\nreturn\n"
        pc, rc = _taint(clean)
        pd, rd = _taint(dirty)
        assert not rc.is_scalar_tainted(_by_op(pc, "extract_uint64")[0].outputs[0])
        assert rd.is_scalar_tainted(_by_op(pd, "extract_uint64")[0].outputs[0])

    def test_unknown_concat_length_is_conservative(self):
        # prefix length unknown (an arg ++ arg) -> whole-value taint, never a
        # false negative.
        teal = ("#pragma version 8\ntxna ApplicationArgs 0\ntxna ApplicationArgs 1\n"
                "concat\npop\nint 1\nreturn\n")
        p, r = _taint(teal)
        out = _by_op(p, "concat")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals.whole()


# assert(extract 0 8 X == const) then read the arg.
_VALIDATE = (
    "#pragma version 8\n"
    "txna ApplicationArgs 0\nextract 0 8\nbyte 0x0011223344556677\n==\nassert\n"
    "txna ApplicationArgs 0\nint {i}\ngetbyte\nreturn\n"
)


class TestValidationNarrowing:
    def _read(self, teal):
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        gb = [a for a in p.assignments if a.op == "getbyte"][-1]
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        return r, gb.outputs[0], arg

    def test_checked_prefix_clears_taint(self):
        # bytes 0..7 pinned to a const -> read of byte 3 is NOT tainted, and
        # the canonical arg's taint narrows to [8, INF).
        r, read, arg = self._read(_VALIDATE.format(i=3))
        assert not r.is_scalar_tainted(read)
        assert r.tainted_bytes(arg) == Intervals([(8, INF)])

    def test_read_outside_checked_range_stays_tainted(self):
        r, read, _ = self._read(_VALIDATE.format(i=20))
        assert r.is_scalar_tainted(read)

    def test_forward_only_does_not_clear(self):
        # without validate=True the checked prefix is NOT cleared.
        p = SSAProgram.from_text(_VALIDATE.format(i=3), name="t")
        r = byte_taint(p)  # validate defaults False
        gb = [a for a in p.assignments if a.op == "getbyte"][-1]
        assert r.is_scalar_tainted(gb.outputs[0])

    def test_bypassing_use_is_sound(self):
        # the validating assert is on ONE branch; a read at the merge is
        # reachable WITHOUT it, so taint must NOT be cleared (no false negative).
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\nint 5\ngetbyte\nbnz skip\n"
            "txna ApplicationArgs 0\nextract 0 8\nbyte 0x0011223344556677\n==\nassert\n"
            "skip:\n"
            "txna ApplicationArgs 0\nint 3\ngetbyte\nreturn\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        merge = [a for a in p.assignments if a.op == "getbyte" and a.location.line >= 12][0]
        assert r.is_scalar_tainted(merge.outputs[0])
