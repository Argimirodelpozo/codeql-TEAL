"""Unit tests for byte-interval ("partial") taint — the standalone prototype
in ``tealql.tealtools.dataflow.byte_taint``.

Two layers: the pure :class:`Intervals` algebra (union / intersect / clip /
subtract / shift / overlaps / normalization), and the forward propagation
end-to-end over in-memory TEAL — proving the headline property: the clean
and attacker-controlled halves of a packed byte array are tracked
separately, including the byte-range -> scalar bridge (``getbyte`` /
``extract_uint*`` of a clean offset is NOT tainted).
"""
from tealql.tealtools.ssa import SSAProgram, SSAVar, Phi
from tealql.tealtools.dataflow.byte_taint import (
    Intervals, byte_taint, byte_taint_view, _byte_strip, INF, AVM_MAX_BYTES,
)
from tealql.tealtools.lift.lift import _Lifter
from tealql.tealtools.lift import pre_ir
from tealql.tealtools.lift.taint import _intr


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
        a = Intervals([(8, AVM_MAX_BYTES)])
        assert not a.overlaps(0, 8)      # [8,inf) does NOT touch [0,8)
        assert a.overlaps(0, 9)
        assert a.overlaps(20, 21)

    def test_open_end(self):
        w = Intervals([(0, INF)])        # the algebra still tolerates an INF end
        assert w.overlaps(1000, 1001)
        assert w.clip(0, 8).parts == ((0, 8),)
        assert w.shift(8).parts == ((8, INF),)

    def test_whole_is_capped_at_avm_max(self):
        assert Intervals.whole().parts == ((0, AVM_MAX_BYTES),)   # no true ∞
        assert Intervals.whole(32).parts == ((0, 32),)


def _taint(teal):
    p = SSAProgram.from_text(teal, name="t")
    return p, byte_taint(p)


def _by_op(p, op, imm=None):
    return [a for a in p.assignments if a.op == op and (imm is None or a.immediates == imm)]


_PREFIX = "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\n"  # 8-byte clean ++ arg


class TestSoundnessNoFalseNegatives:
    """Regressions for the multi-agent review's byte_taint false-negative batch —
    each previously left an attacker-reachable value untainted."""

    def test_scratch_roundtrip_bridges_taint(self):
        # store N; load N used to drop byte taint (load has no def-use input).
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\nstore 5\n"
                      "load 5\nextract 2 4\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "2 4")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(0, 4)])

    def test_select_carries_bytes_taint(self):
        # select over a tainted bytes value and a clean one -> byte-tainted, so a
        # downstream extract still sees it (was: scalar taint -> empty byte map).
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\nbyte 0x0000\n"
                      "int 1\nselect\nextract 0 2\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "0 2")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(0, 2)])

    def test_divmodw_taints_every_output(self):
        # multi-result ops only tainted outputs[0] (top); the deeper quotient
        # words stayed clean -> an attacker-steered quotient was invisible.
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\nbtoi\n"
                      "int 0\nint 3\nint 0\ndivmodw\nreturn\n")
        outs = _by_op(p, "divmodw")[0].outputs
        assert all(r.is_scalar_tainted(o) for o in outs)

    def test_box_get_value_output_is_byte_tainted(self):
        # box_get leaves (value, did_exist); the value (output 1) is bytes and
        # must carry byte taint, not be left clean below the flag.
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\nbox_get\nreturn\n")
        outs = _by_op(p, "box_get")[0].outputs
        assert r.tainted_bytes(outs[1])          # value output byte-tainted


class TestForwardPropagation:
    def test_application_args_is_source(self):
        p, r = _taint("#pragma version 8\ntxna ApplicationArgs 0\npop\nint 1\nreturn\n")
        arg = _by_op(p, "txna")[0].outputs[0]
        assert r.tainted_bytes(arg) == Intervals.whole()   # fully tainted, open length

    def test_concat_partitions_clean_prefix_from_tainted_suffix(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "pop\nint 1\nreturn\n")
        out = _by_op(p, "concat")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(8, AVM_MAX_BYTES)])  # bytes 0..7 clean

    def test_extract_clean_prefix_is_untainted(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "extract 0 8\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "0 8")[0].outputs[0]
        assert not r.tainted_bytes(out)                       # the validated selector

    def test_extract_tainted_region_carries_taint(self):
        p, r = _taint("#pragma version 8\n" + _PREFIX + "extract 8 8\npop\nint 1\nreturn\n")
        out = _by_op(p, "extract", "8 8")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(0, 8)])    # re-based to the slice

    def test_extract3_const_offset_runtime_count_keeps_clean_prefix(self):
        # extract3 X 0 L with a RUNTIME count L: the byte mapping is still EXACT
        # (out[j] = X[j]) because the OFFSET is constant, so the clean 8-byte
        # prefix stays clean — where the old whole-value fallback (runtime count)
        # tainted the entire output. Relational/interval leverage over the bailout.
        teal = ("#pragma version 8\n" + _PREFIX +
                "int 0\ntxna ApplicationArgs 1\nbtoi\nextract3\npop\nint 1\nreturn\n")
        p, r = _taint(teal)
        out = _by_op(p, "extract3")[0].outputs[0]
        t = r.tainted_bytes(out)
        assert not t.overlaps(0, 8)      # clean prefix survives the runtime-count slice
        assert t.overlaps(8, 9)          # tainted suffix still tainted (sound, no FN)

    def test_extract3_const_offset_range_bounded_count_caps_taint(self):
        # extract3 X 4 L where L = btoi(arg) % 8 has IntRange [0,7]: byte_taint
        # now trips the range passes, and range_arith tracks `mod` (btoi seeded to
        # a full uint64 range so the divisor bounds the result). The tainted extent
        # is capped at 4+7=11 (rebased [4,7)) instead of running to the 4096 length
        # fallback — ranges tighten the const-offset slice past the length bound.
        teal = ("#pragma version 8\n" + _PREFIX +
                "int 4\ntxna ApplicationArgs 1\nbtoi\nint 8\n%\nextract3\n"
                "pop\nint 1\nreturn\n")
        p, r = _taint(teal)
        out = _by_op(p, "extract3")[0].outputs[0]
        assert r.tainted_bytes(out) == Intervals([(4, 7)])   # capped by L's range hi=7

    def test_extract3_const_offset_into_tainted_region_is_tainted(self):
        # Soundness counterpart: a runtime-count read STARTING in the tainted
        # suffix (const offset 8) carries taint, re-based to the slice.
        teal = ("#pragma version 8\n" + _PREFIX +
                "int 8\ntxna ApplicationArgs 1\nbtoi\nextract3\npop\nint 1\nreturn\n")
        p, r = _taint(teal)
        out = _by_op(p, "extract3")[0].outputs[0]
        assert r.tainted_bytes(out).overlaps(0, 1)   # tainted from byte 0

    def test_getbyte_bridge_offset_sensitive(self):
        clean = "#pragma version 8\n" + _PREFIX + "int 3\ngetbyte\npop\nint 1\nreturn\n"
        dirty = "#pragma version 8\n" + _PREFIX + "int 20\ngetbyte\npop\nint 1\nreturn\n"
        pc, rc = _taint(clean)
        pd, rd = _taint(dirty)
        assert not rc.is_scalar_tainted(_by_op(pc, "getbyte")[0].outputs[0])
        assert rd.is_scalar_tainted(_by_op(pd, "getbyte")[0].outputs[0])

    def test_getbyte_ranged_index_uses_window(self):
        # getbyte X (arg%8): the index is a RUNTIME value bounded to [0,7], so the
        # read can only touch the clean prefix — scalar result is clean, where the
        # old non-const fallback ("tainted iff X has any taint") flagged it.
        teal = ("#pragma version 8\n" + _PREFIX +
                "txna ApplicationArgs 1\nbtoi\nint 8\n%\ngetbyte\npop\nint 1\nreturn\n")
        p, r = _taint(teal)
        g = _by_op(p, "getbyte")[0].outputs[0]
        assert not r.is_scalar_tainted(g)            # clean prefix proven

    def test_getbyte_ranged_index_into_tainted_is_tainted(self):
        # Soundness: index in [8,15] reaches the tainted suffix -> tainted.
        teal = ("#pragma version 8\n" + _PREFIX +
                "txna ApplicationArgs 1\nbtoi\nint 8\n%\nint 8\n+\ngetbyte\npop\n"
                "int 1\nreturn\n")
        p, r = _taint(teal)
        g = _by_op(p, "getbyte")[0].outputs[0]
        assert r.is_scalar_tainted(g)

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


class TestInterproceduralFrameBridge:
    """Taint fed INTO a subroutine as an argument crosses the ``callsub`` /
    ``proto`` / ``frame_dig`` boundary via ``frame_param_sources`` — byte
    granularity preserved, no IR lift needed."""

    def test_param_read_inherits_caller_arg_taint(self):
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\ncallsub checker\nint 1\nreturn\n"
            "checker:\nproto 1 0\nframe_dig -1\nint 3\ngetbyte\npop\nretsub\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p)
        gb = [a for a in p.assignments if a.op == "getbyte"][0]
        assert r.is_scalar_tainted(gb.outputs[0])   # crossed the call boundary

    def test_interval_granularity_preserved_across_frame(self):
        # caller passes (8 clean bytes ++ arg); inside the sub, byte 3 is clean
        # and byte 12 is tainted — the partition survives the frame crossing.
        teal = (
            "#pragma version 8\n"
            "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\n"
            "callsub checker\nint 1\nreturn\n"
            "checker:\nproto 1 0\n"
            "frame_dig -1\nint 3\ngetbyte\npop\n"
            "frame_dig -1\nint 12\ngetbyte\npop\nretsub\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p)
        gbs = [a for a in p.assignments if a.op == "getbyte"]
        assert not r.is_scalar_tainted(gbs[0].outputs[0])   # byte 3: clean prefix
        assert r.is_scalar_tainted(gbs[1].outputs[0])       # byte 12: tainted suffix


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
        assert r.tainted_bytes(arg) == Intervals([(8, AVM_MAX_BYTES)])

    def test_read_outside_checked_range_stays_tainted(self):
        r, read, _ = self._read(_VALIDATE.format(i=20))
        assert r.is_scalar_tainted(read)

    def test_branch_to_reject_validates_like_assert(self):
        # `slice == const; bz reject` pins the bytes on the approval path just as
        # `assert` does -- recognised via path predicates, not only literal assert.
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\nextract 0 8\nbyte 0x0011223344556677\n==\nbz reject\n"
                "txna ApplicationArgs 0\nint 3\ngetbyte\nreturn\n"
                "reject:\nint 0\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        read = [a for a in p.assignments if a.op == "getbyte"][-1].outputs[0]
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        assert not r.is_scalar_tainted(read)                  # bytes 0..7 validated
        assert r.tainted_bytes(arg) == Intervals([(8, AVM_MAX_BYTES)])

    def test_match_router_validates_selector(self):
        # ABI router: `extract 0 4; match m_add m_sub` pins the selector to each
        # arm's method const, so bytes 0..3 clear (validated) while a non-selector
        # byte stays tainted -- validation via match, not assert or ==.
        teal = ("#pragma version 8\n"
                "method \"add()void\"\nmethod \"sub()void\"\n"
                "txna ApplicationArgs 0\nextract 0 4\nmatch m_add m_sub\nint 0\nreturn\n"
                "m_add:\ntxna ApplicationArgs 0\nint 2\ngetbyte\nreturn\n"
                "m_sub:\ntxna ApplicationArgs 0\nint 6\ngetbyte\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        gbs = [a for a in p.assignments if a.op == "getbyte"]
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        assert r.tainted_bytes(arg) == Intervals([(4, AVM_MAX_BYTES)])   # selector [0,4) cleared
        assert not r.is_scalar_tainted(gbs[0].outputs[0])      # selector byte: clean
        assert r.is_scalar_tainted(gbs[1].outputs[0])          # byte 6: tainted

    def test_forward_only_does_not_clear(self):
        # without validate=True the checked prefix is NOT cleared.
        p = SSAProgram.from_text(_VALIDATE.format(i=3), name="t")
        r = byte_taint(p)  # validate defaults False
        gb = [a for a in p.assignments if a.op == "getbyte"][-1]
        assert r.is_scalar_tainted(gb.outputs[0])

    def test_slice_eq_clean_derived_value_clears(self):
        # assert(extract 0 8 arg == itob(global LatestTimestamp)) — the RHS is
        # attacker-INDEPENDENT (a global through a pure op), so bytes 0..7 are
        # pinned to a value outside attacker control and clear, exactly as a
        # compile-time const would.
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\nextract 0 8\nglobal LatestTimestamp\nitob\n==\nassert\n"
            "txna ApplicationArgs 0\nint 3\ngetbyte\nreturn\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        read = [a for a in p.assignments if a.op == "getbyte"][-1].outputs[0]
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        assert not r.is_scalar_tainted(read)
        assert r.tainted_bytes(arg) == Intervals([(8, AVM_MAX_BYTES)])

    def test_slice_eq_attacker_slice_does_not_clear(self):
        # assert(extract 0 8 arg0 == extract 0 8 arg1) — BOTH sides are
        # attacker-controlled, so neither is clean and nothing clears (the
        # attacker just sets both args equal). Read of arg0 byte 3 stays tainted.
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\nextract 0 8\n"
            "txna ApplicationArgs 1\nextract 0 8\n==\nassert\n"
            "txna ApplicationArgs 0\nint 3\ngetbyte\nreturn\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        read = [a for a in p.assignments if a.op == "getbyte"][-1].outputs[0]
        assert r.is_scalar_tainted(read)

    def test_whole_value_eq_clean_clears_entirely(self):
        # assert(arg == global ZeroAddress) — the WHOLE arg is pinned to a clean
        # value (not just a slice of it), so ALL of its taint clears past the
        # assert. The equality-class case the per-slice rule missed.
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\ndup\nglobal ZeroAddress\n==\nassert\n"
            "int 3\ngetbyte\nreturn\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        assert not r.tainted_bytes(arg)                    # whole value cleared
        read = [a for a in p.assignments if a.op == "getbyte"][-1].outputs[0]
        assert not r.is_scalar_tainted(read)               # downstream read clean

    def test_whole_value_eq_attacker_does_not_clear(self):
        # assert(arg0 == arg1) — both attacker-controlled, neither clean, so the
        # whole-value rule clears nothing (the attacker just sets them equal).
        teal = (
            "#pragma version 8\n"
            "txna ApplicationArgs 0\ntxna ApplicationArgs 1\n==\nassert\n"
            "txna ApplicationArgs 0\nint 3\ngetbyte\nreturn\n"
        )
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p, validate=True)
        read = [a for a in p.assignments if a.op == "getbyte"][-1].outputs[0]
        assert r.is_scalar_tainted(read)                   # still tainted (sound)

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


def _log_arg_reg(lf):
    """The register operand of the (single) ``log`` op in the lifted IR."""
    for b in pre_ir.blocks(lf.subs):
        for o in b.ops:
            s = _intr(o)
            if s is not None and s.op == "log" and s.args:
                return s.args[0]
    return None


class TestIrCarryUp:
    """SSA byte-taint carried onto the lifted IR via ``byte_taint_view`` — the
    'compute low, consume high' bridge (``lifter.regs``)."""

    def test_carryup_faithful_to_ssa_for_covered_registers(self):
        # every covered register reports exactly the SSA byte-taint of its SSAVar.
        teal = ("#pragma version 8\n"
                "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\nlog\n"
                "int 1\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        lf = _Lifter(p); lf.build()
        view = byte_taint_view(lf)
        ssa = byte_taint(lf.prog, validate=True)     # same setting the view uses
        for sv, reg in lf.regs.items():
            if isinstance(sv, (SSAVar, Phi)):
                assert view.tainted_bytes(reg) == ssa.tainted_bytes(sv)
                assert view.is_covered(reg)

    def test_validated_range_clears_at_ir_sink(self):
        # assert(extract 0 8 arg == const) validates bytes 0..7; the VALIDATED
        # bytes then feed a sink. validate=True carry-up clears them at the IR
        # (the partial-taint precision); validate=False leaves them tainted.
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\nextract 0 8\nbyte 0x0011223344556677\n==\nassert\n"
                "txna ApplicationArgs 0\nextract 0 8\nlog\nint 1\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        lf = _Lifter(p); lf.build()
        reg = _log_arg_reg(lf)
        assert reg is not None
        assert byte_taint_view(lf, validate=False).tainted_bytes(reg) == Intervals([(0, 8)])
        assert byte_taint_view(lf, validate=True).tainted_bytes(reg) == Intervals.empty()

    def test_clean_prefix_partition_survives_to_ir(self):
        # concat(clean8, arg) logged: at the IR the log operand still carries the
        # [8, INF) partition -- byte granularity reached the sink.
        teal = ("#pragma version 8\n"
                "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\nlog\n"
                "int 1\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        lf = _Lifter(p); lf.build()
        view = byte_taint_view(lf)
        reg = _log_arg_reg(lf)
        assert reg is not None
        assert view.tainted_bytes(reg) == Intervals([(8, AVM_MAX_BYTES)])

    def test_interprocedural_param_sink_is_soundly_flagged(self):
        # arg passed INTO a sub and logged there. The IR log reads the sub's
        # PARAM register, which the lift synthesizes fresh (no source SSAVar), so
        # it is UNCOVERED by the carry-up -> caught by the conservative fallback
        # (sink_tainted True), sound but not byte-granular. Closing this to
        # byte-granularity (map param regs to caller args) is the v2 increment.
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\ncallsub emit\nint 1\nreturn\n"
                "emit:\nproto 1 0\nframe_dig -1\nlog\nretsub\n")
        p = SSAProgram.from_text(teal, name="t")
        lf = _Lifter(p); lf.build()
        view = byte_taint_view(lf)
        reg = _log_arg_reg(lf)
        assert reg is not None
        assert not view.is_covered(reg)         # lift-synthesized param register
        assert view.sink_tainted(reg)           # still flagged, conservatively

    def test_uncovered_operand_is_conservatively_tainted(self):
        # a lift-synthesized register (not in lifter.regs) is uncovered, and the
        # conservative sink verdict treats it as tainted -- no silent FN.
        teal = "#pragma version 8\ntxna ApplicationArgs 0\nlog\nint 1\nreturn\n"
        p = SSAProgram.from_text(teal, name="t")
        lf = _Lifter(p); lf.build()
        view = byte_taint_view(lf)
        phantom = object()                      # stands in for a synthesized reg
        assert not view.is_covered(phantom)
        assert view.sink_tainted(phantom)       # conservative: treated as tainted


class TestByteStripViz:
    def test_byte_strip_clean_prefix_tainted_tail(self):
        # [8, INF) over an open value -> 8 clean cells, then tainted, then arrow.
        assert _byte_strip(Intervals([(8, AVM_MAX_BYTES)]), None, width=16) == "········████████→"

    def test_byte_strip_bounded_length_no_arrow(self):
        assert _byte_strip(Intervals([(0, 4)]), 4) == "████"
        assert _byte_strip(Intervals.empty(), 4) == "····"

    def test_byte_strip_interior_window(self):
        # a tainted [2,6) window inside an 8-byte value
        assert _byte_strip(Intervals([(2, 6)]), 8) == "··████··"

    def test_render_anchors_to_source_and_shows_partition(self):
        teal = ("#pragma version 8\n"
                "byte 0x0011223344556677\ntxna ApplicationArgs 0\nconcat\n"
                "pop\nint 1\nreturn\n")
        p = SSAProgram.from_text(teal, name="t")
        out = byte_taint(p).render()
        assert "byte-interval taint" in out
        assert "concat" in out                 # producing op labelled
        assert "········█" in out               # the clean-prefix partition is visible


class TestProvenance:
    def test_taint_chain_source_to_value(self):
        p = SSAProgram.from_text("#pragma version 8\n" + _PREFIX + "extract 8 8\nlog\nint 1\nreturn\n", name="t")
        r = byte_taint(p)
        v = [a for a in p.assignments if a.op == "extract" and a.immediates == "8 8"][0].outputs[0]
        from tealql.tealtools.dataflow.byte_taint import taint_chain
        ops = [d.op for d in taint_chain(v, r)]
        assert ops[0] == "txna" and ops[-1] == "extract"        # source-first, ends at value

    def test_validation_chain_recorded(self):
        p = SSAProgram.from_text(_VALIDATE.format(i=3), name="t")
        r = byte_taint(p, validate=True)
        arg = [a for a in p.assignments if a.op == "txna"][0].outputs[0]
        prov = r.provenance(arg)
        assert "tainted by:" in prov and "txna" in prov
        assert "validated:" in prov and "assert" in prov       # the assert cleared [0,8)

    def test_chain_crosses_callsub(self):
        teal = ("#pragma version 8\n"
                "txna ApplicationArgs 0\ncallsub emit\nint 1\nreturn\n"
                "emit:\nproto 1 0\nframe_dig -1\nextract 4 8\nlog\nretsub\n")
        p = SSAProgram.from_text(teal, name="t")
        r = byte_taint(p)
        v = [a for a in p.assignments if a.op == "log"][0].inputs[0]
        ops = [d.op for d in __import__("tealql.tealtools.dataflow.byte_taint", fromlist=["taint_chain"]).taint_chain(v, r)]
        assert "txna" in ops and "frame_dig" in ops             # crossed the call boundary
