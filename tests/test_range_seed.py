"""Unit tests for static range *seeding* (``tealtools.passes.range_seed``).

Focused on the two enrichment sources the op-alone single-output path can't
reach on its own:

  - ``_OP_OUTPUT_SEEDS`` — the 0/1 "exists / found" flag that the
    ``*_get`` / ``*_ex`` family pushes as its top output (``outputs[0]``,
    top-first), plus ``box_len``'s length output bounded by the 32768-byte
    max box size.
  - the count-valued ``_TXN_FIELD_RANGES`` additions (reference-array
    lengths, schema entry counts, spec-capped scalars).

Built from in-memory TEAL so no DB is needed.
"""
from tealtools.ssa import SSAProgram


def _ranges_by_op(teal):
    """{op: [(immediates, [(out_index, range_or_None), …])]} after seeding."""
    prog = SSAProgram.from_text(teal, name="t")
    prog.propagate_ranges()
    out = {}
    for a in prog.assignments:
        rngs = [(i, o.range) for i, o in enumerate(a.outputs)]
        out.setdefault(a.op, []).append((a.immediates, rngs))
    return out


class TestExistsFlagSeeds:
    def test_asset_params_get_exists_flag_only(self):
        # outputs[0] = exists flag (top, the value `assert`/`bnz` reads),
        # outputs[1] = the field value (type-dependent, NOT range-seeded).
        r = _ranges_by_op(
            "#pragma version 8\nint 0\nasset_params_get AssetTotal\n"
            "assert\nreturn\n"
        )
        (_, outs), = r["asset_params_get"]
        assert outs[0][1] is not None
        assert (outs[0][1].lo, outs[0][1].hi) == (0, 1)
        assert outs[1][1] is None  # value output left unranged

    def test_get_ex_family_exists_flags(self):
        teal = (
            "#pragma version 8\n"
            "int 0\nint 0\napp_local_get_ex\nassert\npop\n"
            "int 0\nbyte 0x00\napp_global_get_ex\nassert\npop\n"
            "byte 0x00\nbox_get\nassert\npop\n"
            "return\n"
        )
        r = _ranges_by_op(teal)
        for op in ("app_local_get_ex", "app_global_get_ex", "box_get"):
            (_, outs), = r[op]
            assert (outs[0][1].lo, outs[0][1].hi) == (0, 1), op

    def test_box_len_bounds_both_outputs(self):
        # outputs[0] = exists flag [0,1]; outputs[1] = length [0, 32768].
        r = _ranges_by_op(
            "#pragma version 8\nbyte 0x00\nbox_len\nassert\nreturn\n"
        )
        (_, outs), = r["box_len"]
        assert (outs[0][1].lo, outs[0][1].hi) == (0, 1)
        assert (outs[1][1].lo, outs[1][1].hi) == (0, 32768)

    def test_vrf_verify_flag(self):
        # outputs[0] = verified flag [0,1]; outputs[1] = the 64-byte VRF
        # output (a bytes value, NOT range-seeded here).
        r = _ranges_by_op(
            "#pragma version 8\nbyte 0x00\nbyte 0x00\nbyte 0x00\n"
            "vrf_verify VrfAlgorand\nreturn\n"
        )
        (_, outs), = r["vrf_verify"]
        assert (outs[0][1].lo, outs[0][1].hi) == (0, 1)
        assert outs[1][1] is None


class TestWideAndSqrtSeeds:
    def test_addw_high_word_is_carry(self):
        # addw pushes (high, low); low on top = outputs[0] (unbounded),
        # high = outputs[1] = the 0/1 carry of a 64+64-bit add.
        r = _ranges_by_op(
            "#pragma version 8\nint 1\nint 2\naddw\nreturn\n"
        )
        (_, outs), = r["addw"]
        assert outs[0][1] is None
        assert (outs[1][1].lo, outs[1][1].hi) == (0, 1)

    def test_sqrt_bounded_by_2_pow_32(self):
        # isqrt of any uint64 is <= 2**32 - 1, regardless of input.
        r = _ranges_by_op(
            "#pragma version 8\nint 25\nsqrt\nreturn\n"
        )
        (_, outs), = r["sqrt"]
        assert (outs[0][1].lo, outs[0][1].hi) == (0, 0xFFFFFFFF)


class TestTxnCountFieldSeeds:
    def test_reference_array_and_schema_counts(self):
        cases = {
            "NumAppArgs": (0, 16),
            "NumAccounts": (0, 4),
            "NumAssets": (0, 8),
            "NumApplications": (0, 8),
            "NumLogs": (0, 32),
            "GlobalNumUint": (0, 64),
            "GlobalNumByteSlice": (0, 64),
            "LocalNumUint": (0, 16),
            "LocalNumByteSlice": (0, 16),
            "ExtraProgramPages": (0, 3),
            "ConfigAssetDecimals": (0, 19),
        }
        body = "".join(f"txn {f}\npop\n" for f in cases)
        r = _ranges_by_op("#pragma version 8\n" + body + "int 1\nreturn\n")
        seen = {imm: outs[0][1] for imm, outs in r["txn"]}
        for field, (lo, hi) in cases.items():
            assert seen[field] is not None, field
            assert (seen[field].lo, seen[field].hi) == (lo, hi), field
