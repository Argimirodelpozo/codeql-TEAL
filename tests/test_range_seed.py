"""Unit tests for static range *seeding* (``tealql.tealtools.passes.range_seed``).

Focused on the two enrichment sources the op-alone single-output path can't
reach on its own:

  - ``_OP_OUTPUT_SEEDS`` — the 0/1 "exists / found" flag that the
    ``*_get`` / ``*_ex`` family pushes as its top output (``outputs[0]``,
    top-first), plus ``box_len``'s length output bounded by the 32768-byte
    max box size.
  - the count-valued ``_TXN_FIELD_RANGES`` additions (reference-array
    lengths, schema entry counts, spec-capped scalars).

Built from in-memory TEAL so no fixture is needed.
"""
from tealql.tealtools.ssa import SSAProgram


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

    def test_group_indexed_inner_txn_form(self):
        # gitxn t F reads field F of inner txn t — field is the SECOND
        # immediate. Previously uncovered (only txn/gtxn*/gtxns/itxn were).
        r = _ranges_by_op(
            "#pragma version 8\nitxn_begin\ngitxn 0 NumAppArgs\n"
            "pop\nint 1\nreturn\n"
        )
        (_, outs), = r["gitxn"]
        assert (outs[0][1].lo, outs[0][1].hi) == (0, 16)


class TestParamsValueRangeSeeds:
    def test_params_value_output_bounded_fields(self):
        # outputs[1] (the value, not the exists flag) is bounded for some
        # *_params_get fields.
        cases = {
            "asset_params_get": [("AssetDecimals", (0, 19)),
                                 ("AssetDefaultFrozen", (0, 1))],
            "app_params_get":   [("AppExtraProgramPages", (0, 3)),
                                 ("AppGlobalNumUint", (0, 64)),
                                 ("AppLocalNumByteSlice", (0, 16))],
            "acct_params_get":  [("AcctIncentiveEligible", (0, 1))],
        }
        for op, fields in cases.items():
            for field, (lo, hi) in fields:
                teal = (f"#pragma version 8\nint 0\n{op} {field}\n"
                        f"pop\npop\nint 1\nreturn\n")
                r = _ranges_by_op(teal)
                (_, outs), = r[op]
                val = outs[1][1]
                assert val is not None, (op, field)
                assert (val.lo, val.hi) == (lo, hi), (op, field)

    def test_unbounded_params_field_value_left_alone(self):
        # AssetTotal has no static bound — value output stays unranged.
        r = _ranges_by_op(
            "#pragma version 8\nint 0\nasset_params_get AssetTotal\n"
            "pop\npop\nint 1\nreturn\n"
        )
        (_, outs), = r["asset_params_get"]
        assert outs[1][1] is None


def test_bool_typed_fields_seed_zero_one():
    """A field DECLARED `bool` ranges 0..1, on both the global and txn sides.

    Derived from the type tables rather than listed per field: the bound is what
    the type MEANS. Contrast `MinTxnFee` / `MinBalance`, which are deliberately
    unranged — those are consensus PARAMETERS, and pinning today's value would
    let a consensus upgrade silently make the analyzer prove false things.
    """
    prog = SSAProgram({"p.teal":
        "#pragma version 11\n"
        "global PayoutsEnabled\ntxn Nonparticipation\n"
        "txn ConfigAssetDefaultFrozen\n"
        "global Round\ntxn Amount\n"
        "pop\npop\npop\npop\npop\nint 1\nreturn\n"})
    prog.propagate_constants()
    prog.propagate_ranges()
    got = {}
    for a in prog.assignments:
        if a.op in ("global", "txn") and a.outputs:
            got[a.immediates.strip()] = getattr(a.outputs[0], "range", None)

    for field in ("PayoutsEnabled", "Nonparticipation", "ConfigAssetDefaultFrozen"):
        r = got[field]
        assert r is not None and (r.lo, r.hi) == (0, 1), f"{field} -> {r}"

    # Unbounded fields must stay unbounded — a range here would be unsound.
    for field in ("Round", "Amount"):
        assert got[field] is None, f"{field} -> {got[field]}"
