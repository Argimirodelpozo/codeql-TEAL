"""The three hand-spelled operand tables must agree with the AVM langspec.

"Which operand is the key / what type is position i" is written down three times,
in two different orders:

* ``type_recovery._POS_IN``            — per-position types, TOP-FIRST
* ``fund_flow._STATE_WRITE_KEY_IDX``   — which operand is the state key, TOP-FIRST
* ``box_recovery._STORAGE_OPS``        — which operand is the box name, AVM order

They agree today, and each is one hand edit from the "read the wrong operand ->
silently wrong schema / missed sink" failure their own comments warn about. Puya
ships the authoritative signature (``_puya_compat.langspec_variants``), so rather
than leave the tables trusting each other, check them against it.

Deriving the tables from the langspec outright would be the tidier end state, but
it is a behaviour-carrying refactor of type recovery, the fund-flow sink taxonomy
and box recovery at once. This gate makes the drift loud, which is the part that
was missing; the derivation can follow separately.
"""
import pytest

pytest.importorskip("puya")

from tealql.tealtools.language.avm import avm  # noqa: E402
from tealql.tealtools.lift import _puya_compat as _compat  # noqa: E402


def _langspec_arg_types(op: str):
    """``[avm-family or None]`` per argument in AVM (bottom-first) order, or
    ``None`` when puya knows no such op.

    ``None`` at a position means polymorphic / ``any`` / a union, which the tables
    are entitled to leave unconstrained (``getbit`` is deliberately so). A
    field-keyed ``DynamicVariants`` op is skipped: its signature depends on the
    immediate, which these tables do not key on."""
    from puya.ir.avm_ops import AVMOp

    enum_op = getattr(AVMOp, op, None)
    if enum_op is None:
        return None
    variants = _compat.langspec_variants(enum_op)
    sig = getattr(variants, "signature", None)
    if sig is None:                       # DynamicVariants or unknown shape
        return None
    out = []
    for a in getattr(sig, "args", []):
        name = getattr(a, "name", None) or str(a)
        f = avm(str(name).split(".")[-1])
        out.append(f if f in ("u", "b") else None)
    return out or None


def test_pos_in_matches_the_langspec():
    """``_POS_IN`` is TOP-FIRST, so position ``i`` is langspec argument
    ``len(args) - 1 - i``. A table entry that CONSTRAINS a position must match the
    langspec there; leaving a position ``None`` is always allowed (``getbit`` is
    deliberately unconstrained because it is polymorphic)."""
    from tealql.tealtools.lift.type_recovery import _POS_IN

    checked = 0
    for op, positions in _POS_IN.items():
        spec = _langspec_arg_types(op)
        if spec is None:
            continue
        for i, want in enumerate(positions):
            if want is None or i >= len(spec):
                continue
            spec_family = spec[len(spec) - 1 - i]
            if spec_family is None:
                continue
            checked += 1
            assert avm(want) == spec_family, (
                f"_POS_IN[{op!r}][{i}] says {want!r} ({avm(want)}) but the langspec "
                f"says argument {len(spec) - 1 - i} is {spec_family} — the table is "
                "TOP-FIRST, so check the order before 'fixing' the langspec read")
    assert checked > 20, f"only {checked} positions were comparable — probe broke"


def test_state_write_key_operand_is_bytes_in_the_langspec():
    """``_STATE_WRITE_KEY_IDX`` names the operand a tainted key would poison. Every
    one of those positions must be a bytes argument in the langspec: an index
    pointing at a uint64 operand means the detector is reading the wrong slot and
    the real key is unchecked."""
    from tealql.tealtools.lift.fund_flow import _STATE_WRITE_KEY_IDX

    checked = 0
    for op, idx in _STATE_WRITE_KEY_IDX.items():
        spec = _langspec_arg_types(op)
        if spec is None or idx >= len(spec):
            continue
        family = spec[len(spec) - 1 - idx]      # top-first -> langspec order
        if family is None:
            continue
        checked += 1
        assert family == "b", (
            f"_STATE_WRITE_KEY_IDX[{op!r}]={idx} points at a {family} operand; a "
            "state key is bytes, so this index is off")
    assert checked >= 4, f"only {checked} key indices were comparable"


def test_box_name_operand_is_bytes_in_the_langspec():
    """``_STORAGE_OPS`` is in AVM (bottom-first) order — the opposite of the two
    above, which is correct only because ``to_puya_ir`` reverses intrinsic args.
    The box NAME must be bytes at that index."""
    from tealql.tealtools.lift.box_recovery import _STORAGE_OPS

    checked = 0
    for op, (_kind, key_idx, val_idx, _v_is_result) in _STORAGE_OPS.items():
        spec = _langspec_arg_types(op)
        if spec is None:
            continue
        if key_idx < len(spec) and spec[key_idx] is not None:
            checked += 1
            assert spec[key_idx] == "b", (
                f"_STORAGE_OPS[{op!r}] key index {key_idx} points at a "
                f"{spec[key_idx]} operand — this table is BOTTOM-FIRST, unlike "
                "_POS_IN, so check the order before changing the index")
        # The VALUE operand, where the table names one, must not be the key's slot.
        if val_idx is not None:
            assert val_idx != key_idx, f"_STORAGE_OPS[{op!r}] key and value collide"
    assert checked >= 8, f"only {checked} storage key indices were comparable"
